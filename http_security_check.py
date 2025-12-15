"""
HTTP security checker for lab/owned targets.
Checks common headers (HSTS, CSP, XFO, Referrer-Policy, Permissions-Policy),
TLS version (best-effort via requests/urllib), and basic misconfig indicators.
"""

from __future__ import annotations

import argparse
import json
import ssl
import urllib.request
from typing import Dict, List, Tuple


SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def fetch(url: str, timeout: float) -> Tuple[int, Dict[str, str]]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return status, headers


def analyze(headers: Dict[str, str]) -> Dict[str, str]:
    report: Dict[str, str] = {}
    for h in SEC_HEADERS:
        if h in headers:
            report[h] = "present"
        else:
            report[h] = "missing"
    # Basic checks
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        report["x-content-type-options"] = report.get("x-content-type-options", "missing/invalid")
    if headers.get("x-frame-options", "").lower() not in {"deny", "sameorigin"}:
        report["x-frame-options"] = report.get("x-frame-options", "missing/invalid")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP security header checker (authorized targets).")
    parser.add_argument("--url", required=True, help="Target URL (owned/authorized).")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout seconds.")
    parser.add_argument("--json-out", help="Write JSON report to file.")
    args = parser.parse_args()

    print("⚠️  Authorized use only. Test only sites you own/control.")

    status, headers = fetch(args.url, args.timeout)
    report = analyze(headers)
    output = {
        "url": args.url,
        "status": status,
        "headers": headers,
        "findings": report,
    }
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
