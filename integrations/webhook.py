#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Forward asnmap JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument("--header", action="append", default=[], help="Extra header as 'Key: Value'")
    args = ap.parse_args()

    # Validate URL scheme before reading stdin.
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print(
            f"webhook: URL must use http or https scheme, got {parsed.scheme!r}",
            file=sys.stderr,
        )
        return 1
    if not parsed.netloc:
        print("webhook: URL is missing a host", file=sys.stderr)
        return 1

    try:
        payload = sys.stdin.buffer.read()
    except Exception as exc:
        print(f"webhook: failed to read stdin: {exc}", file=sys.stderr)
        return 1

    if not payload:
        print("webhook: stdin was empty — nothing to send", file=sys.stderr)
        return 1

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            print(f"webhook: skipping malformed header {h!r}", file=sys.stderr)
            continue
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook: connection failed: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"webhook: unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
