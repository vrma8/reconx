#!/usr/bin/env python3
"""Capture one full-page screenshot using an installed Playwright runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="reconx screenshot helper")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit("Playwright is not installed; install the optional playwright dependency and browser runtime") from exc
    output = Path(arguments.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1080})
        page.goto(arguments.url, wait_until="networkidle", timeout=30_000)
        page.screenshot(path=str(output), full_page=True)
        browser.close()
    print(json.dumps({"url": arguments.url, "path": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
