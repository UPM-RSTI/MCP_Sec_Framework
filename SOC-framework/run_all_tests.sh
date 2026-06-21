#!/bin/bash
# run_all_tests.sh — Runs the full T00-T05 evaluation suite with a
# wazuh-mcp container restart between each test.
#
# Why: the wazuh-mcp server (Rust) accumulates open connections across
# rapid reconnects and becomes unstable after ~17-20 connections within a
# short window, causing RemoteDisconnected errors on later tests even
# after a sleep. A restart resets its internal connection state cleanly,
# which a sleep alone does not.
#
# Usage:
#   ./run_all_tests.sh            # N=20, all tests
#   ./run_all_tests.sh 10         # N=10, all tests
#   ./run_all_tests.sh 20 T02     # N=20, only T02 (still restarts first)

set -e

N="${1:-20}"
ONLY="${2:-}"

TESTS=(T00 T01 T02 T03 T04 T05)
if [ -n "$ONLY" ]; then
    TESTS=("$ONLY")
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for t in "${TESTS[@]}"; do
    echo ""
    echo "############################################################"
    echo "# Restarting wazuh-mcp before $t"
    echo "############################################################"
    docker restart wazuh-mcp
    sleep 10

    echo ">>> Lanzando $t (N=$N)"
    python run_tests.py --test "$t" --n "$N" || echo "  !! $t FAILED, continuing with next test"

    sleep 5
done

echo ""
echo "############################################################"
echo "# All tests finished. Results in test_results.jsonl"
echo "############################################################"
