#!/usr/bin/env python3
"""Dependency-free entity extraction from already-fetched text.

The extractor deliberately avoids heavyweight NLP dependencies: it combines
bounded regular expressions with simple validation so a static distribution can
still surface useful OSINT leads. Values are indicators, not verified facts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
PHONE_RE = re.compile(r"(?x)\b(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)?\d{3,4}[ .-]\d{3,4}\b")
HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan)\b")
ORG_RE = re.compile(r"\b([A-Z][\w&.-]*(?:\s+[A-Z][\w&.-]*){0,3}\s+(?:Inc|LLC|Ltd|Corp|GmbH|Technologies|Labs|Systems|Industries))\b")
PERSON_RE = re.compile(r"\b(?:Mr|Mrs|Ms|Dr)\.?\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,2})\b")
PERSON_PAIR_RE = re.compile(r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,2})\b")
NON_PERSON_WORDS = {"contact", "headquarters", "project", "initiative", "program", "codename"}
ADDRESS_RE = re.compile(r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Parkway|Pkwy|Court|Ct|Way)(?:,\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)?\b")
PROJECT_RE = re.compile(r'\b(?:Project| Initiative| Program)\s+["“]?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})["”]?')
CODENAME_RE = re.compile(r'(?i)\b(?:codenamed|codename|operation)\s+["“]?([A-Z][A-Za-z0-9_-]{2,24})["”]?')


def bounded(values: list[str], maximum: int = 1000) -> list[str]:
    return sorted(set(value.strip() for value in values if value and value.strip()))[:maximum]


def people(text: str) -> list[str]:
    candidates = list(PERSON_RE.findall(text))
    for candidate in PERSON_PAIR_RE.findall(text):
        words = candidate.lower().split()
        if any(word in NON_PERSON_WORDS for word in words):
            continue
        if any(word in {"inc", "llc", "ltd", "corp", "gmbh", "technologies", "labs", "systems", "industries"} for word in words):
            continue
        candidates.append(candidate)
    return bounded(candidates)


def extract(text: str) -> dict[str, list[str]]:
    return {
        "emails": bounded(EMAIL_RE.findall(text)),
        "phones": bounded(PHONE_RE.findall(text)),
        "internal_hosts": bounded(HOST_RE.findall(text)),
        "organizations": bounded(ORG_RE.findall(text)),
        "people": people(text),
        "physical_addresses": bounded(ADDRESS_RE.findall(text)),
        "project_names": bounded(PROJECT_RE.findall(text)),
        "codenames": bounded(CODENAME_RE.findall(text)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="reconx passive entity extractor")
    parser.parse_args()
    text = sys.stdin.read(2_000_000)
    print(json.dumps(extract(text), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
