#!/usr/bin/env bash
# Run the full netrecon test suite (stdlib only, no pytest required).
#   1) unit/integration tests  (python -m unittest)
#   2) CLI-level E2E scan+report against the loopback mock network
set -uo pipefail
cd "$(dirname "$0")/.."

echo "==> unittest suite"
python3 -m unittest discover -s tests -p 'test_*.py' -v
rc1=$?

echo
echo "==> CLI-level E2E (real netrecon subprocess)"
python3 tests/run_e2e.py
rc2=$?

echo
if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ]; then
    echo "ALL TESTS PASS"
    exit 0
else
    echo "TESTS FAILED (unittest=$rc1 e2e=$rc2)"
    exit 1
fi
