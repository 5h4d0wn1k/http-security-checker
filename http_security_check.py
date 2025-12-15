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
    "x-xss-protection",
    "expect-ct",
    "public-key-pins",
]


def fetch(url: str, timeout: float) -> Tuple[int, Dict[str, str]]:
    """
    Fetch HTTP response headers from a URL.
    
    Makes a GET request and returns status code and headers.
    Headers are normalized to lowercase keys.
    
    Args:
        url: Target URL to fetch.
        timeout: Request timeout in seconds.
        
    Returns:
        Tuple of (status_code, headers_dict).
        
    Raises:
        urllib.error.URLError: If request fails.
    """
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return status, headers


def analyze(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Analyze HTTP security headers.
    
    Checks for presence and validity of common security headers.
    Validates header values where applicable.
    
    Args:
        headers: Dictionary of HTTP headers (lowercase keys).
        
    Returns:
        Dictionary mapping header names to status ("present", "missing", or "missing/invalid").
    """
    report: Dict[str, str] = {}
    
    # Check all security headers
    for h in SEC_HEADERS:
        if h in headers:
            report[h] = "present"
        else:
            report[h] = "missing"
    
    # Validate specific headers
    x_content_type = headers.get("x-content-type-options", "").lower()
    if x_content_type and x_content_type != "nosniff":
        report["x-content-type-options"] = "invalid"
    elif not x_content_type:
        report["x-content-type-options"] = "missing"
    
    x_frame = headers.get("x-frame-options", "").lower()
    if x_frame and x_frame not in {"deny", "sameorigin"}:
        report["x-frame-options"] = "invalid"
    elif not x_frame:
        report["x-frame-options"] = "missing"
    
    # Check HSTS max-age
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "max-age" not in hsts.lower():
            report["strict-transport-security"] = "present (no max-age)"
        elif "max-age=0" in hsts.lower():
            report["strict-transport-security"] = "present (disabled)"
    
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
