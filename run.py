#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =========================================================
# SAFE SQLi AUDITOR PRO
# Single File Edition
# For Security Testing & Learning Only
# =========================================================

import os
import re
import time
import random
import threading
import urllib.parse

from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================================================
# CONFIG
# =========================================================

TIMEOUT = 15
DELAY = 0.3
MAX_THREADS = 5
MAX_COLUMNS = 15
CRAWL_DEPTH = 1

# =========================================================
# COLORS
# =========================================================

C = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "END": "\033[0m"
}

# =========================================================
# USER AGENTS
# =========================================================

USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

# =========================================================
# THREAD SAFE PRINT
# =========================================================

print_lock = threading.Lock()

def safe_print(msg):
    with print_lock:
        print(msg)

# =========================================================
# LOGGER
# =========================================================

def info(msg):
    safe_print(f"{C['CYAN']}[INFO]{C['END']} {msg}")

def success(msg):
    safe_print(f"{C['GREEN']}[FOUND]{C['END']} {msg}")

def warning(msg):
    safe_print(f"{C['YELLOW']}[WARN]{C['END']} {msg}")

def error(msg):
    safe_print(f"{C['RED']}[ERROR]{C['END']} {msg}")

# =========================================================
# BANNER
# =========================================================

def banner():

    os.system("clear")

    print(f"""{C['BOLD']}{C['BLUE']}
╔══════════════════════════════════════════════╗
║           SAFE SQLi AUDITOR PRO             ║
║         Professional Single File            ║
╚══════════════════════════════════════════════╝
{C['END']}""")

# =========================================================
# SESSION
# =========================================================

session = requests.Session()

retry = Retry(
    total=2,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504]
)

adapter = HTTPAdapter(max_retries=retry)

session.mount("http://", adapter)
session.mount("https://", adapter)

# =========================================================
# REQUEST
# =========================================================

def request(url, method="GET", params=None, data=None):

    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:

        time.sleep(DELAY)

        if method == "POST":

            r = session.post(
                url,
                data=data,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True
            )

        else:

            r = session.get(
                url,
                params=params,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True
            )

        r.encoding = "utf-8"

        return r

    except Exception as e:

        error(str(e))
        return None

# =========================================================
# PARSER
# =========================================================

class SmartParser(HTMLParser):

    def __init__(self, base_url):

        super().__init__()

        self.base_url = base_url

        self.links = []
        self.forms = []

    def handle_starttag(self, tag, attrs):

        attrs = dict(attrs)

        # LINKS
        if tag == "a":

            href = attrs.get("href")

            if href:

                full = urllib.parse.urljoin(
                    self.base_url,
                    href
                )

                self.links.append(full)

        # FORMS
        elif tag == "form":

            action = attrs.get("action", "")
            method = attrs.get("method", "get").lower()

            full_action = urllib.parse.urljoin(
                self.base_url,
                action
            )

            self.forms.append({
                "action": full_action,
                "method": method,
                "inputs": []
            })

        # INPUTS
        elif tag == "input" and self.forms:

            name = attrs.get("name")

            if name:
                self.forms[-1]["inputs"].append(name)

# =========================================================
# UTILITIES
# =========================================================

def extract_params(url):

    parsed = urllib.parse.urlparse(url)

    query = urllib.parse.parse_qs(parsed.query)

    result = {}

    for k, v in query.items():

        result[k] = v[0]

    return result

def normalize_endpoint(url):

    parsed = urllib.parse.urlparse(url)

    return parsed.path

# =========================================================
# DBMS GUESS
# =========================================================

def fingerprint_dbms(text):

    text = text.lower()

    if "mysql" in text:
        return "MySQL"

    if "mariadb" in text:
        return "MariaDB"

    if "postgresql" in text:
        return "PostgreSQL"

    if "sqlite" in text:
        return "SQLite"

    if "oracle" in text:
        return "Oracle"

    if "microsoft sql" in text or "sql server" in text:
        return "MSSQL"

    return "Unknown"

# =========================================================
# WAF DETECTION
# =========================================================

def detect_waf(headers):

    headers = str(headers).lower()

    wafs = {
        "cloudflare": "Cloudflare",
        "sucuri": "Sucuri",
        "imperva": "Imperva",
        "mod_security": "ModSecurity",
        "aws": "AWS WAF"
    }

    for key, value in wafs.items():

        if key in headers:
            return value

    return "Not Detected"

# =========================================================
# SQL ERRORS
# =========================================================

SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "quoted string",
    "unclosed quotation",
    "pdoexception",
    "warning: mysql",
    "mysqli",
    "postgresql",
    "sqlite error",
    "oracle error",
]

# =========================================================
# CHECK SQLI
# =========================================================

def is_sqli(original, modified):

    if not modified:
        return False

    text = modified.text.lower()

    for err in SQL_ERRORS:

        if err in text:
            return True

    if len(original.text) != len(modified.text):
        return True

    return False

# =========================================================
# COLUMN COUNT
# =========================================================

def count_columns(url, param, value):

    for i in range(1, MAX_COLUMNS + 1):

        payload = f"{value}' ORDER BY {i}-- -"

        r = request(
            url,
            params={param: payload}
        )

        if not r:
            continue

        text = r.text.lower()

        if "unknown column" in text or "order by" in text:

            return i - 1

    return None

# =========================================================
# BOOLEAN TEST
# =========================================================

def boolean_test(url, param, value):

    true_payload = f"{value}' AND '1'='1"
    false_payload = f"{value}' AND '1'='2"

    r1 = request(url, params={param: true_payload})
    r2 = request(url, params={param: false_payload})

    if not r1 or not r2:
        return False

    return len(r1.text) != len(r2.text)

# =========================================================
# TIME TEST
# =========================================================

def time_test(url, param, value):

    start = time.time()

    payload = f"{value}' AND SLEEP(3)-- -"

    request(url, params={param: payload})

    end = time.time()

    return (end - start) >= 3

# =========================================================
# CRAWLER
# =========================================================

def crawl(target):

    info(f"Crawling: {target}")

    r = request(target)

    if not r:
        return [], []

    parser = SmartParser(target)

    parser.feed(r.text)

    get_targets = []
    post_targets = []

    seen = set()

    # GET
    for link in parser.links:

        if "?" not in link:
            continue

        norm = normalize_endpoint(link)

        if norm in seen:
            continue

        seen.add(norm)

        params = extract_params(link)

        if params:
            get_targets.append((link, params))

    # POST
    for form in parser.forms:

        if form["method"] == "post":
            post_targets.append(form)

    info(f"GET endpoints : {len(get_targets)}")
    info(f"POST forms    : {len(post_targets)}")

    return get_targets, post_targets

# =========================================================
# RESULT DISPLAY
# =========================================================

def show_result(
    url,
    param,
    method,
    sqli_type,
    dbms,
    waf,
    cols,
    status,
    diff
):

    print(f"""
{C['GREEN']}=================================================={C['END']}

{C['BOLD']}[FOUND] Possible SQL Injection{C['END']}

URL         : {url}
Parameter   : {param}
Method      : {method}
Type        : {sqli_type}
DBMS Guess  : {dbms}
Columns     : {cols}
HTTP Code   : {status}
Difference  : {diff} bytes
WAF         : {waf}

Safe PoC:
{url}

{C['GREEN']}=================================================={C['END']}
""")

# =========================================================
# GET SCAN
# =========================================================

def scan_get(url, params):

    info(f"Scanning GET: {url}")

    original = request(url)

    if not original:
        return

    for param, value in params.items():

        payload = f"{value}'"

        modified = request(
            url,
            params={param: payload}
        )

        if not modified:
            continue

        if is_sqli(original, modified):

            dbms = fingerprint_dbms(modified.text)

            waf = detect_waf(modified.headers)

            cols = count_columns(url, param, value)

            boolean_based = boolean_test(
                url,
                param,
                value
            )

            time_based = time_test(
                url,
                param,
                value
            )

            sqli_type = "Error-Based"

            if boolean_based:
                sqli_type += " + Boolean-Based"

            if time_based:
                sqli_type += " + Time-Based"

            diff = abs(
                len(original.text) - len(modified.text)
            )

            poc = (
                f"{url.split('?')[0]}"
                f"?{param}={urllib.parse.quote(payload)}"
            )

            show_result(
                poc,
                param,
                "GET",
                sqli_type,
                dbms,
                waf,
                cols,
                modified.status_code,
                diff
            )

# =========================================================
# POST SCAN
# =========================================================

def scan_post(form):

    action = form["action"]

    inputs = form["inputs"]

    if not inputs:
        return

    info(f"Scanning POST: {action}")

    data = {}

    for inp in inputs:
        data[inp] = "test"

    original = request(
        action,
        method="POST",
        data=data
    )

    if not original:
        return

    for inp in inputs:

        payload_data = data.copy()

        payload_data[inp] = "test'"

        modified = request(
            action,
            method="POST",
            data=payload_data
        )

        if not modified:
            continue

        if is_sqli(original, modified):

            dbms = fingerprint_dbms(modified.text)

            waf = detect_waf(modified.headers)

            diff = abs(
                len(original.text) - len(modified.text)
            )

            show_result(
                action,
                inp,
                "POST",
                "Error-Based",
                dbms,
                waf,
                "-",
                modified.status_code,
                diff
            )

# =========================================================
# MAIN
# =========================================================

def main():

    banner()

    target = input(
        f"{C['BOLD']}Target URL:{C['END']} "
    ).strip()

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    get_targets, post_targets = crawl(target)

    if not get_targets and not post_targets:

        warning("No parameters/forms found")
        return

    futures = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

        # GET
        for url, params in get_targets:

            futures.append(
                executor.submit(
                    scan_get,
                    url,
                    params
                )
            )

        # POST
        for form in post_targets:

            futures.append(
                executor.submit(
                    scan_post,
                    form
                )
            )

        for future in as_completed(futures):

            try:
                future.result()

            except Exception as e:
                error(str(e))

    success("Scan Finished")

# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":

    requests.packages.urllib3.disable_warnings()

    main()
