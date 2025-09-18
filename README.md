# Vulnex — Hybrid Vulnerability Scanner (MVP)

Vulnex is a compact hybrid vulnerability scanner (network + web) intended as a learning/demo project.

**UI extras**: startup ASCII banner and a neat ASCII summary/diagram at the end (By Draxel01).

## Quickstart
```bash
git clone https://github.com/Draxel01/vulnex.git
cd vulnex
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run:
python vulnex.py --target https://example.com
