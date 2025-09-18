# ui.py
"""
Vulnex UI helpers: banner, progress helpers, and ASCII summary.
Author: Draxel01 + ChatGPT
"""

import random
import textwrap
from colorama import init, Fore, Style

init(autoreset=True)

VERSION = "0.1.0"
AUTHOR = "Draxel01"

BANNERS = [
r"""
 __     __     _                _         
 \ \   / /__ _| | ___ _ __  ___| |__   ___ 
  \ \ / / _` | |/ _ \ '_ \/ __| '_ \ / _ \
   \ V / (_| | |  __/ | | \__ \ | | |  __/
    \_/ \__,_|_|\___|_| |_|___/_| |_|\___|
""",
r"""
 __      __      _                      _     
 \ \    / /__ __| |__ _ _ _  __ _ ___  | |__  
  \ \/\/ / -_) _` / _` | ' \/ _` / -_) | '_ \ 
   \_/\_/\___\__,_\__,_|_||_\__, \___| |_.__/
                            |___/             
"""
]

def show_banner():
    banner = random.choice(BANNERS)
    print(Fore.CYAN + banner + Style.RESET_ALL)
    tagline = f" Vulnex {VERSION} — By {AUTHOR} "
    print(Fore.MAGENTA + ("=" * len(tagline)))
    print(Fore.MAGENTA + tagline)
    print(Fore.MAGENTA + ("=" * len(tagline)) + "\n" + Style.RESET_ALL)

def progress(msg: str):
    """Simple progress line for main script to call."""
    print(Fore.YELLOW + "[*] " + msg + Style.RESET_ALL)

def show_summary(report: dict):
    """
    Draw a compact ASCII summary/diagram from the report dict produced by vulnex.py
    (expects keys: network, http, bruteforce, param_reflections, target).
    """
    target = report.get('target', 'N/A')
    open_ports = len(report.get('network', []))
    http = report.get('http') or {}
    http_status = http.get('status', 'N/A')
    http_hits = len(http.get('sig_hits', [])) if http else 0
    paths_found = len(report.get('bruteforce', []))
    reflections = len(report.get('param_reflections', []))
    total_issues = http_hits + paths_found + reflections

    # simple "risk" buckets (heuristic for display only)
    high = http_hits
    medium = reflections
    low = paths_found

    box = f"""
┌─────────────────────────────────────────────────────────────┐
│                         Vulnex Summary                      │
├─────────────────────────────────────────────────────────────┤
│ Target         : {target:40} │
│ Open ports     : {open_ports:<3}                                     │
│ HTTP Status    : {http_status:<3}                                   │
│ HTTP Hits      : {http_hits:<3}   (signature hints)                │
│ Paths found    : {paths_found:<3}   (dir bruteforce)               │
│ Reflections    : {reflections:<3}   (param reflection checks)      │
├─────────────────────────────────────────────────────────────┤
│ High (http sigs): {high:<3}    Medium (reflections): {medium:<3}   Low (paths): {low:<3} │
├─────────────────────────────────────────────────────────────┤
│ TOTAL heuristic issues: {total_issues:<3}                                         │
└─────────────────────────────────────────────────────────────┘
"""
    print(Fore.GREEN + textwrap.dedent(box) + Style.RESET_ALL)

def show_network_map(report: dict):
    """
    Minimal ASCII network map: target -> open ports list
    """
    target = report.get('target', 'N/A')
    ports = [str(x['port']) for x in report.get('network', [])]
    ports_line = ", ".join(ports) if ports else "none"
    map_box = f"""
    [ INTERNET ] ---> [ {target} ]
                     | open ports: {ports_line}
    """
    print(Fore.BLUE + map_box + Style.RESET_ALL)
