#!/usr/bin/env python3
"""Dependency-free entity extraction from already-fetched text.

This intentionally reports contact indicators only; installing spaCy is not
required for the static reconx distribution.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
PHONE_RE = re.compile(r"(?x)\b(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)?\d{3,4}[ .-]\d{3,4}\b")
HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan)\b")


def main() -> int:
    parser = argparse.ArgumentParser(description="reconx passive entity extractor")
    parser.parse_args()
    text = sys.stdin.read(2_000_000)
    print(json.dumps({
        "emails": sorted(set(EMAIL_RE.findall(text)))[:1000],
        "phones": sorted(set(PHONE_RE.findall(text)))[:1000],
        "internal_hosts": sorted(set(HOST_RE.findall(text)))[:1000],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
