#!/bin/bash
# Run the GnuGk test harness (needs root for the network namespaces).
#
#   test/run.sh                      all tests
#   test/run.sh -k "h46018 and md5"  a subset, any pytest options work
#
# Results (traces, pcap, CDRs, endpoint JSON) end up in test/results/<test name>/
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v pytest > /dev/null; then
	echo "pytest is missing (pip install pytest)" >&2
	exit 2
fi
exec pytest "$@"
