#!/bin/bash
# Reproduction script for CVE-2024-2004 / HackerOne report #2384833
#
# Summary:
#   curl's --proto flag with "-all" (disabling all protocols) incorrectly
#   enables ALL protocols instead of blocking them when only removals are used.
#   This allows data to be sent over an unencrypted channel even when the caller
#   expects curl to refuse the request.
#
# Affected versions: curl 7.85.0 – 8.6.0
# Fixed in:         curl 8.7.1 (released 2024-03-27)
# CVE:              CVE-2024-2004
# Severity:         Low (CVSS 3.1: 3.7)
#
# References:
#   https://curl.se/docs/CVE-2024-2004.html
#   https://hackerone.com/reports/2384833

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

VULNERABLE_VERSION=0
BYPASSED=0

echo "========================================================"
echo "  CVE-2024-2004 – curl --proto disabled-protocol bypass"
echo "  HackerOne report #2384833"
echo "========================================================"
echo ""

# ── 1. Check curl availability ─────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    echo -e "${RED}[!] curl is not installed. Please install curl to run this test.${NC}"
    exit 1
fi

CURL_VERSION=$(curl --version 2>&1 | head -1 | awk '{print $2}')
echo -e "${YELLOW}[*] Detected curl version: ${CURL_VERSION}${NC}"

# ── 2. Version range check ─────────────────────────────────────────────────
# Vulnerable: 7.85.0 <= version < 8.7.1
check_vulnerable_version() {
    python3 - "$1" <<'PYEOF'
import sys
from packaging.version import Version

v = Version(sys.argv[1])
if Version("7.85.0") <= v < Version("8.7.1"):
    print("VULNERABLE")
else:
    print("PATCHED")
PYEOF
}

if command -v python3 &>/dev/null && python3 -c "import packaging" &>/dev/null 2>&1; then
    VERSION_STATUS=$(check_vulnerable_version "$CURL_VERSION")
    if [ "$VERSION_STATUS" = "VULNERABLE" ]; then
        echo -e "${RED}[!] Version ${CURL_VERSION} is in the vulnerable range (7.85.0 – 8.6.0).${NC}"
        VULNERABLE_VERSION=1
    else
        echo -e "${GREEN}[+] Version ${CURL_VERSION} is outside the known vulnerable range.${NC}"
    fi
else
    echo -e "${YELLOW}[*] python3/packaging unavailable – skipping version range check.${NC}"
fi

echo ""
echo "--------------------------------------------------------"
echo " Reproduction steps (CVE-2024-2004)"
echo "--------------------------------------------------------"
echo ""
echo " The documented behaviour of '--proto -all' is to forbid EVERY"
echo " protocol so that no transfer is possible. On vulnerable curl"
echo " versions, a proto string that:"
echo "   1. starts with '-all', AND"
echo "   2. only removes protocols (never adds one)"
echo " silently disables the restriction, allowing all protocols."
echo ""
echo " Vulnerable command examples:"
echo "   curl --proto -all                    http://example.com"
echo "   curl --proto -all,-http              http://example.com"
echo "   curl --proto -all,-ftp,-smtp,-pop3   http://example.com"
echo ""
echo " Expected result on any version:"
echo "   curl: (1) Protocol \"http\" not supported or disabled in libcurl"
echo ""
echo " Actual result on VULNERABLE versions (7.85.0 – 8.6.0):"
echo "   The request SUCCEEDS – data is sent over unencrypted HTTP."
echo ""
echo "--------------------------------------------------------"
echo " Live test (requires network access to example.com)"
echo "--------------------------------------------------------"
echo ""

run_test() {
    local description="$1"
    local proto_arg="$2"
    local url="$3"

    echo -n "  Testing: curl --proto ${proto_arg} ${url}  ->  "
    OUTPUT=$(curl -s -o /dev/null -w "%{http_code}" --proto "$proto_arg" "$url" 2>&1 || true)
    EXIT_CODE=$?

    # If curl exited with exit code 1 (CURLE_UNSUPPORTED_PROTOCOL) it blocked correctly.
    if echo "$OUTPUT" | grep -qi "disabled\|not supported\|protocol" 2>/dev/null || [ "$EXIT_CODE" -eq 1 ]; then
        echo -e "${GREEN}BLOCKED (correct)${NC}"
        return 0
    fi

    # Fallback: check exit code (curl exits 1 when protocol is blocked)
    RESULT=$(curl -v --proto "$proto_arg" "$url" 2>&1 | head -5 || true)
    if echo "$RESULT" | grep -qi "disabled\|not supported\|Protocol"; then
        echo -e "${GREEN}BLOCKED (correct)${NC}"
    else
        echo -e "${RED}BYPASSED – VULNERABLE! Data sent despite protocol restriction.${NC}"
        BYPASSED=1
    fi
}

# Test the failure scenarios listed in the report
run_test "proto=-all"                 "-all"                "http://example.com" || true
run_test "proto=-all,-http"           "-all,-http"          "http://example.com" || true
run_test "proto=-all,-ftp,-smtp,-pop3" "-all,-ftp,-smtp,-pop3" "http://example.com" || true

echo ""
echo "--------------------------------------------------------"
echo " Control test: '--proto -http' should ALSO block HTTP"
echo "--------------------------------------------------------"
echo ""
run_test "proto=-http (control)" "-http" "http://example.com" || true

echo ""
echo "========================================================"
if [ "$BYPASSED" -eq 1 ]; then
    echo -e "${RED}[!] RESULT: This system appears VULNERABLE to CVE-2024-2004.${NC}"
    echo ""
    echo "    Remediation: Upgrade curl to version 8.7.1 or later."
    echo "    https://curl.se/download.html"
elif [ "$VULNERABLE_VERSION" -eq 1 ]; then
    echo -e "${YELLOW}[~] RESULT: curl ${CURL_VERSION} is in the affected version range, but all${NC}"
    echo -e "${YELLOW}    live behavioural tests passed (the patch may have been backported).${NC}"
    echo ""
    echo "    Confirm by upgrading to curl 8.7.1 or later if possible."
else
    echo -e "${GREEN}[+] RESULT: This system does not appear vulnerable to CVE-2024-2004.${NC}"
    echo ""
    echo "    The installed curl correctly blocks protocols when '--proto -all'"
    echo "    (or similar) is specified."
fi
echo "========================================================"
