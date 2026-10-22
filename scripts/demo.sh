#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1. Scanning a clean fixture environment ==="
python3 scan.py --path fixtures/clean_site_packages
clean_status=$?
echo "exit code: $clean_status"
echo

echo "=== 2. Scanning a fixture with the documented IOCs planted ==="
set +e
python3 scan.py --path fixtures/compromised_site_packages
compromised_status=$?
set -e
echo "exit code: $compromised_status"
echo

echo "=== 3. Scanning this machine's real site-packages (informational) ==="
python3 scan.py || true
