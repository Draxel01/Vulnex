#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo "[*] Running Vulnex demo against example.com"
python vulnex.py --target https://example.com
