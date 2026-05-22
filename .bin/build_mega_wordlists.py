#!/usr/bin/env python3
"""
Build mega-fuzz wordlists by downloading, merging, and deduplicating
all sources defined in wordlist-sources.json.

Usage:
  python3 .bin/build_mega_wordlists.py [--targets t1,t2] [--dry-run]

  --targets   Comma-separated list of output targets to build (default: all)
  --dry-run   Print stats without writing output files
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = REPO_ROOT / "wordlist-sources.json"

OUTPUT_MAP = {
    "mega-fuzz-directories": REPO_ROOT / "Discovery/Web-Content/mega-fuzz-directories.txt",
    "mega-fuzz-files":       REPO_ROOT / "Discovery/Web-Content/mega-fuzz-files.txt",
    "mega-fuzz-api":         REPO_ROOT / "Discovery/Web-Content/api/mega-fuzz-api.txt",
    "mega-fuzz-parameters":  REPO_ROOT / "Discovery/Web-Content/mega-fuzz-parameters.txt",
    "mega-fuzz-extensions":  REPO_ROOT / "Discovery/Web-Content/mega-fuzz-extensions.txt",
    "mega-fuzz-payloads":    REPO_ROOT / "Discovery/Web-Content/mega-fuzz-payloads.txt",
    "mega-fuzz-subdomains":  REPO_ROOT / "Discovery/DNS/mega-fuzz-subdomains.txt",
}

SKIP_SUBCATEGORIES = {"kiterunner-binary"}
MAX_LINE_LEN = 1024
RETRIES = 3


def fetch_text(url: str) -> str | None:
    """Download URL and return text content, with retries."""
    headers = {"User-Agent": "SecLists-Aggregator/1.0"}
    for attempt in range(1, RETRIES + 1):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=120) as r:
                return r.read().decode("utf-8", errors="ignore")
        except URLError as e:
            print(f"    [!] Attempt {attempt}/{RETRIES} failed for {url}: {e}")
    return None


def read_local(url: str) -> list[str]:
    """Read lines from a file:// URL."""
    path = Path(url.replace("file://", ""))
    if not path.exists():
        print(f"    [!] Local file not found: {path}")
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()


def extract_nuclei_paths(content: str) -> list[str]:
    """Extract path strings from a nuclei template YAML."""
    try:
        import yaml
        data = yaml.safe_load(content)
        paths = []
        for section in ("requests", "http"):
            for req in data.get(section, []):
                for p in req.get("path", []):
                    p = re.sub(r"\{\{[^}]+\}\}", "", p).strip("/")
                    if p:
                        paths.append(p)
        return paths
    except Exception as e:
        print(f"    [!] YAML parse error: {e}")
        return []


def extract_json_paths(content: str) -> list[str]:
    """Extract file paths from snallygaster-style fingerprint JSON."""
    try:
        data = json.loads(content)
        paths = []
        items = data if isinstance(data, list) else data.get("fingerprints", [])
        for item in items:
            if isinstance(item, dict):
                for key in ("path", "uri", "url", "file", "filename"):
                    if key in item:
                        paths.append(str(item[key]).lstrip("/"))
                        break
        return paths
    except Exception as e:
        print(f"    [!] JSON parse error: {e}")
        return []


def get_lines(entry: dict) -> list[str]:
    """Fetch and return lines for a catalogue entry, handling all special cases."""
    subcategory = entry.get("subcategory", "")

    if subcategory in SKIP_SUBCATEGORIES:
        print(f"    [~] Skipping binary format ({entry['filename']})")
        return []

    source = entry["source"]
    url = entry["source_url"]

    if source == "SecLists/local":
        return read_local(url)

    print(f"    [↓] {entry['filename']}  (~{entry.get('approx_size_mb', '?')} MB, ~{entry.get('approx_lines', '?'):,} lines)")
    content = fetch_text(url)
    if content is None:
        return []

    if subcategory == "nuclei-template":
        return extract_nuclei_paths(content)

    if entry["filename"].endswith(".json"):
        return extract_json_paths(content)

    return content.splitlines()


def clean(lines: list[str]) -> list[str]:
    """Strip comments, blanks, and oversized lines."""
    return [
        l for l in lines
        if l and not l.startswith("#") and len(l) <= MAX_LINE_LEN
    ]


def build(targets: set[str], dry_run: bool) -> None:
    with open(SOURCES_FILE) as f:
        catalogue = json.load(f)

    entries = catalogue["entries"]
    buckets: dict[str, set[str]] = {t: set() for t in targets}

    for entry in entries:
        entry_targets = [t for t in entry.get("output_target", []) if t in targets]
        if not entry_targets or entry["category"] == "blacklist":
            continue

        print(f"\n[{entry['id']}] {entry['source']} / {entry['filename']}")
        lines = clean(get_lines(entry))
        print(f"    -> {len(lines):,} usable lines")

        for t in entry_targets:
            buckets[t].update(lines)

    print("\n" + "=" * 60)
    print("Results:")
    for target in sorted(targets):
        unique = buckets[target]
        path = OUTPUT_MAP[target]
        print(f"  {target}: {len(unique):,} unique lines -> {path.relative_to(REPO_ROOT)}")

        if dry_run or not unique:
            continue

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(unique)) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", help="Comma-separated targets to build (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="Print stats, do not write files")
    args = parser.parse_args()

    if args.targets:
        targets = set(args.targets.split(","))
        unknown = targets - OUTPUT_MAP.keys()
        if unknown:
            print(f"[!] Unknown targets: {unknown}")
            print(f"    Valid: {sorted(OUTPUT_MAP.keys())}")
            sys.exit(1)
    else:
        targets = set(OUTPUT_MAP.keys())

    print(f"[*] Building {len(targets)} target(s): {sorted(targets)}")
    print(f"[*] Catalogue: {SOURCES_FILE}")
    if args.dry_run:
        print("[*] DRY RUN — no files will be written\n")

    build(targets, args.dry_run)


if __name__ == "__main__":
    main()
