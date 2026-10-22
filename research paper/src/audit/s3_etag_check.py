"""Verify the original CSE-CIC-IDS-2018 CSVs against the official AWS Open Data objects.

The official files live in the public bucket ``cse-cic-ids2018`` (registry.opendata.aws/cse-cic-ids2018,
paper reference [8]). Their S3 ETags are multipart ETags ("<md5-of-part-md5s>-<n_parts>"), so a
plain MD5 cannot be compared. This script sends a HEAD request per file (no download), reads the
ETag and Content-Length, recomputes the multipart ETag locally for 8/16/32/64 MiB part sizes, and
records whether any part size reproduces the official ETag.

Usage (from the project root; network access required for the HEAD requests)
-----------------------------------------------------------------------------
    python -I src/audit/s3_etag_check.py [--overwrite]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"
PART_SIZES_MIB = (8, 16, 32, 64)
FIELDS = ["relpath", "s3_url", "http_status", "s3_content_length", "local_size", "size_match", "s3_etag",
          "s3_last_modified", "local_multipart_etag", "part_size_mib", "etag_match"]


def multipart_etag(path: Path, part_size: int) -> str:
    digests = []
    with path.open("rb") as fh:
        while chunk := fh.read(part_size):
            digests.append(hashlib.md5(chunk).digest())
    if len(digests) == 1:
        return digests[0].hex()
    return hashlib.md5(b"".join(digests)).hexdigest() + f"-{len(digests)}"


def head(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", default="data/raw_original/CSE-CIC-IDS-2018")
    p.add_argument("--out", default="data/manifests/original_2018_s3_etag_check.csv")
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    out = ROOT / args.out
    if out.exists() and not args.overwrite:
        print(f"refusing to overwrite {out} (pass --overwrite)", file=sys.stderr)
        return 2
    rows, failures = [], 0
    for f in sorted((ROOT / args.dir).glob("*.csv")):
        url = BASE + urllib.parse.quote(f.name)
        status, h = head(url)
        etag = h.get("etag", "").strip('"')
        n_parts = int(etag.split("-")[1]) if "-" in etag else 1
        local, used = "", ""
        for mib in PART_SIZES_MIB:
            size = mib * 1024 * 1024
            if -(-f.stat().st_size // size) != n_parts:  # part count must agree before hashing
                continue
            local = multipart_etag(f, size)
            if local == etag:
                used = mib
                break
        ok = local == etag
        failures += not ok
        rows.append({"relpath": f.relative_to(ROOT).as_posix(), "s3_url": url, "http_status": status,
                     "s3_content_length": h.get("content-length"), "local_size": f.stat().st_size,
                     "size_match": str(f.stat().st_size) == h.get("content-length"), "s3_etag": etag,
                     "s3_last_modified": h.get("last-modified"), "local_multipart_etag": local,
                     "part_size_mib": used, "etag_match": ok})
        print(f"{f.name}: {'MATCH' if ok else 'MISMATCH'} ({etag})", flush=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
