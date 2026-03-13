#!/usr/bin/env python3
"""
CVE-2024-2004 / HackerOne report #2384833
------------------------------------------
curl --proto disabled-protocol bypass

This script demonstrates and checks for CVE-2024-2004:
  When curl's --proto flag is given a list that starts with '-all' and
  only ever removes protocols (never adds any), the restriction is
  silently dropped, allowing ALL protocols instead of blocking them.

Affected versions: curl 7.85.0 – 8.6.0
Fixed in:         curl 8.7.1 (2024-03-27)

Usage:
    python3 check_curl_cve_2024_2004.py
"""

import subprocess
import sys
import re

# ANSI colours
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RESET  = "\033[0m"


def get_curl_version() -> str:
    """Return the version string of the installed curl, or '' on failure."""
    try:
        out = subprocess.check_output(["curl", "--version"], stderr=subprocess.DEVNULL, text=True)
        match = re.search(r"curl ([\d.]+)", out)
        return match.group(1) if match else ""
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def parse_version(version_str: str) -> tuple:
    """Convert a dotted version string to a comparable tuple of ints."""
    try:
        return tuple(int(x) for x in version_str.split("."))
    except ValueError:
        return (0,)


def is_vulnerable_version(version_str: str) -> bool:
    """Return True if the version is in the CVE-2024-2004 affected range."""
    v = parse_version(version_str)
    return parse_version("7.85.0") <= v < parse_version("8.7.1")


def test_proto_restriction(proto: str, url: str) -> bool:
    """
    Run curl with the given --proto value against url.
    Return True if the protocol was correctly BLOCKED, False if it BYPASSED.
    """
    result = subprocess.run(
        ["curl", "-s", "--max-time", "5", "--proto", proto, url],
        capture_output=True,
        text=True,
    )
    # curl exit code 1 = CURLE_UNSUPPORTED_PROTOCOL → correctly blocked
    if result.returncode == 1:
        return True
    # Also scan stderr for the "disabled in libcurl" message
    combined = (result.stdout + result.stderr).lower()
    if "disabled" in combined or "not supported" in combined:
        return True
    return False


def main() -> int:
    print("=" * 60)
    print("  CVE-2024-2004 – curl --proto bypass checker")
    print("  HackerOne report #2384833")
    print("=" * 60)
    print()

    version = get_curl_version()
    if not version:
        print(f"{RED}[!] curl not found. Please install curl to run this check.{RESET}")
        return 2

    print(f"{YELLOW}[*] Detected curl version: {version}{RESET}")

    if is_vulnerable_version(version):
        print(f"{RED}[!] Version {version} is in the vulnerable range "
              f"(7.85.0 \u2013 8.6.0).{RESET}")
    else:
        print(f"{GREEN}[+] Version {version} is outside the known vulnerable range.{RESET}")

    print()
    print("-" * 60)
    print(" Vulnerability description")
    print("-" * 60)
    print("""
 When curl is invoked with a --proto string that:
   1. Starts with '-all'  (disables every protocol), AND
   2. Only removes further protocols (never adds one back)

 …the protocol restriction is silently ignored on affected versions
 (7.85.0 – 8.6.0), and ALL protocols are allowed.  This can result
 in sensitive data being sent over an unencrypted channel.

 Vulnerable command examples:
   curl --proto -all                     http://example.com
   curl --proto -all,-http               http://example.com
   curl --proto -all,-ftp,-smtp,-pop3    http://example.com

 Expected: curl exits with code 1 and prints
   "Protocol \\"http\\" not supported or disabled in libcurl"

 Actual (vulnerable): the request SUCCEEDS.
""")

    print("-" * 60)
    print(" Live behavioural tests")
    print("-" * 60)
    print()

    test_url = "http://example.com"

    # (proto_value, expected_to_be_blocked, label)
    test_cases = [
        ("-all",                  True,  "--proto -all"),
        ("-all,-http",            True,  "--proto -all,-http"),
        ("-all,-ftp,-smtp,-pop3", True,  "--proto -all,-ftp,-smtp,-pop3"),
        ("-http",                 True,  "--proto -http  (control)"),
        ("-all,https",            True,  "--proto -all,https  (control, should block http)"),
    ]

    any_bypassed = False
    for proto, should_block, label in test_cases:
        blocked = test_proto_restriction(proto, test_url)
        if blocked:
            status = f"{GREEN}BLOCKED (correct){RESET}"
        else:
            status = f"{RED}BYPASSED – VULNERABLE{RESET}"
            any_bypassed = True
        print(f"  {label:<40}  {status}")

    print()
    print("=" * 60)
    if any_bypassed:
        print(f"{RED}[!] RESULT: VULNERABLE – one or more --proto restrictions "
              f"were bypassed.{RESET}")
        print()
        print("    Remediation: upgrade curl to 8.7.1 or later.")
        print("    https://curl.se/download.html")
        return 1
    else:
        print(f"{GREEN}[+] RESULT: NOT VULNERABLE – all --proto restrictions "
              f"were correctly enforced.{RESET}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
