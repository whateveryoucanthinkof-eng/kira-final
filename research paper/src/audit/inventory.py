"""Phase 1 dataset inventory and checksum tooling (strictly read-only).

Subcommands
-----------
scan
    Inventory raw files (project-root files plus ``data/raw_*`` if present) and
    every archive member, using only the ZIP central directory. Also captures the
    first line (header) of each CSV member by decompressing at most
    ``HEADER_READ_LIMIT`` bytes. Cheap; no full-file reads.
hash
    Streaming SHA-256 of a registered file and, with ``--members``, of every
    archive member. Members are decompressed in memory-bounded chunks and never
    written to disk; ``zipfile`` verifies each member's CRC-32 when it is read to
    the end, so this doubles as an archive integrity test. Results are merged into
    a checksum cache keyed by (path, member, size, mtime) so large inputs are not
    re-hashed unless they change (or ``--force`` is given).

Raw inputs are only ever opened in binary read mode. Nothing is extracted.

Usage (from the project root)
-----------------------------
    python -I src/audit/inventory.py scan
    python -I src/audit/inventory.py hash --target CICIDS2017_improved.zip --members
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import logging
import os
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Callable, Iterator

import yaml

TOOL = "src/audit/inventory.py"
CHUNK = 8 * 1024 * 1024
HEADER_READ_LIMIT = 1024 * 1024
PROGRESS_EVERY = 1024**3  # log progress every 1 GiB

DATA_EXT = {".csv", ".tsv", ".parquet", ".pcap", ".pcapng", ".arff", ".feather"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
DOC_EXT = {".pdf", ".md", ".txt", ".html", ".htm", ".docx", ".rst", ".bib"}
SCRIPT_EXT = {".py", ".sh", ".java", ".ipynb", ".r", ".ps1", ".bat", ".jar"}

# Files this project generates at the root; they are scaffolding, not inputs.
SCAFFOLD_FILES = {"README.md", ".gitignore", "pytest.ini"}
RAW_SUBDIRS = ("data/raw_original", "data/raw_improved")

ZIP_METHODS = {0: "stored", 8: "deflated", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd"}
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
WEEKDAY_RE = re.compile(r"([A-Za-z]+day)", re.IGNORECASE)
DATE_RE = re.compile(r"(\d{2})-(\d{2})-(\d{4})")

INVENTORY_FIELDS = [
    "record_type", "dataset_family", "variant", "role", "release", "release_status",
    "relpath", "archive_relpath", "member_name", "filename", "extension", "file_category",
    "size_bytes", "compressed_bytes", "fs_mtime_utc", "archive_member_datetime_naive",
    "filename_weekday_token", "filename_date_iso", "weekday_matches_date",
    "suspicious_flags", "notes",
]
ARCHIVE_FIELDS = [
    "archive_relpath", "member_index", "member_name", "is_dir", "extension", "file_category",
    "uncompressed_bytes", "compressed_bytes", "compression_ratio", "compression_method",
    "crc32_hex", "archive_member_datetime_naive", "encrypted", "nested_archive",
    "unsafe_path", "suspicious_flags",
]
CHECKSUM_FIELDS = [
    "object_type", "relpath", "member_name", "size_bytes", "container_size_bytes",
    "container_mtime_ns", "sha256", "crc32_expected", "crc32_verified", "bytes_read",
    "seconds", "mib_per_s", "computed_at_utc", "tool", "error",
]

log = logging.getLogger("inventory")


# --------------------------------------------------------------------------- helpers
def classify_file(name: str) -> str:
    """Classify a path by extension into data/archive/documentation/script/other."""
    ext = Path(name).suffix.lower()
    if ext in DATA_EXT:
        return "data"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in DOC_EXT:
        return "documentation"
    if ext in SCRIPT_EXT:
        return "script"
    return "other"


def filename_day_tokens(name: str) -> dict[str, str]:
    """Extract weekday/date tokens from a file name.

    These are labels taken from the *name only*; they say nothing about the
    timestamps inside the file. ``weekday_matches_date`` is "True"/"False" when
    both tokens exist, "token_not_weekday" when the weekday-like token is not a
    real weekday (e.g. a typo), and "" otherwise.
    """
    stem = Path(name).name
    wd = WEEKDAY_RE.search(stem)
    dm = DATE_RE.search(stem)
    weekday = wd.group(1).lower() if wd else ""
    date_iso, matches = "", ""
    if dm:
        day, month, year = (int(g) for g in dm.groups())
        try:
            date = dt.date(year, month, day)
            date_iso = date.isoformat()
        except ValueError:
            date = None
        if weekday and date is not None:
            matches = (
                str(WEEKDAYS[date.weekday()] == weekday)
                if weekday in WEEKDAYS
                else "token_not_weekday"
            )
    return {"filename_weekday_token": weekday, "filename_date_iso": date_iso,
            "weekday_matches_date": matches}


def utc_iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat(timespec="seconds")


def now_utc() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="seconds")


def rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_unsafe_member_path(name: str) -> bool:
    """True if extracting this member could escape the target directory."""
    p = name.replace("\\", "/")
    return p.startswith("/") or bool(re.match(r"^[A-Za-z]:", p)) or ".." in p.split("/")


def load_registry(config: Path) -> dict[str, dict]:
    """Registry keyed by relative path. Keys ending in "/" describe whole directories."""
    with config.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    return {s["path"] if s["path"].endswith("/") else Path(s["path"]).as_posix(): s
            for s in cfg.get("sources", [])}


def registry_lookup(registry: dict[str, dict], relpath: str) -> tuple[str, dict]:
    """Exact match first, else the longest directory entry containing ``relpath``."""
    if relpath in registry:
        return relpath, registry[relpath]
    dirs = [k for k in registry if k.endswith("/") and relpath.startswith(k)]
    if dirs:
        key = max(dirs, key=len)
        return key, registry[key]
    return "", {}


def discover_raw_files(root: Path) -> list[Path]:
    """Root-level files (minus scaffolding) plus anything under data/raw_*.

    ``*.partial`` files (in-progress acquisitions) are skipped.
    """
    files = [p for p in sorted(root.iterdir()) if p.is_file() and p.name not in SCAFFOLD_FILES]
    for sub in RAW_SUBDIRS:
        d = root / sub
        if d.is_dir():
            files.extend(sorted(p for p in d.rglob("*") if p.is_file()))
    return [p for p in files if not p.name.endswith(".partial")]


def refuse_overwrite(paths: list[Path], overwrite: bool) -> None:
    existing = [str(p) for p in paths if p.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Refusing to overwrite existing outputs (pass --overwrite to replace): "
            + ", ".join(existing)
        )


# --------------------------------------------------------------------------- zip reading
def list_zip_members(path: Path) -> list[dict]:
    """Read member metadata from the ZIP central directory (no decompression)."""
    rows = []
    with zipfile.ZipFile(path) as zf:
        for idx, info in enumerate(zf.infolist()):
            ext = Path(info.filename).suffix.lower()
            flags = []
            if not info.is_dir() and info.file_size == 0:
                flags.append("empty_member")
            elif classify_file(info.filename) == "data" and info.file_size < 1024:
                flags.append("tiny_data_member")
            encrypted = bool(info.flag_bits & 0x1)
            nested = ext in ARCHIVE_EXT
            unsafe = is_unsafe_member_path(info.filename)
            if encrypted:
                flags.append("encrypted")
            if nested:
                flags.append("nested_archive")
            if unsafe:
                flags.append("unsafe_path")
            rows.append({
                "member_index": idx,
                "member_name": info.filename,
                "is_dir": info.is_dir(),
                "extension": ext,
                "file_category": "directory" if info.is_dir() else classify_file(info.filename),
                "uncompressed_bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "compression_ratio": round(info.file_size / info.compress_size, 4)
                if info.compress_size else "",
                "compression_method": ZIP_METHODS.get(info.compress_type, str(info.compress_type)),
                "crc32_hex": f"{info.CRC:08x}",
                "archive_member_datetime_naive": dt.datetime(*info.date_time).isoformat(),
                "encrypted": encrypted,
                "nested_archive": nested,
                "unsafe_path": unsafe,
                "suspicious_flags": ";".join(flags),
            })
    return rows


def read_member_header(zf: zipfile.ZipFile, name: str, limit: int = HEADER_READ_LIMIT) -> dict:
    """Decompress only until the first newline (or ``limit`` bytes) of a member.

    Returns the raw header line and a naive split; quoting is reported, not parsed.
    """
    buf = b""
    with zf.open(name) as fh:
        while b"\n" not in buf and len(buf) < limit:
            chunk = fh.read(65536)
            if not chunk:
                break
            buf += chunk
    first, sep, _ = buf.partition(b"\n")
    has_bom = first.startswith(b"\xef\xbb\xbf")
    line_ending = ("CRLF" if first.endswith(b"\r") else "LF") if sep else "no_newline_within_limit"
    text = first.rstrip(b"\r").decode("utf-8-sig", errors="replace")
    counts = {d: text.count(d) for d in [",", ";", "\t", "|"]}
    delim = max(counts, key=counts.get) if any(counts.values()) else ""
    cols = text.split(delim) if delim else [text]
    seen, dups = set(), []
    for c in cols:
        if c in seen and c not in dups:
            dups.append(c)
        seen.add(c)
    return {
        "header_line": text,
        "delimiter_guess": delim,
        "n_columns_naive_split": len(cols),
        "columns_naive_split": cols,
        "duplicate_column_names": dups,
        "columns_with_outer_whitespace": [c for c in cols if c != c.strip()],
        "contains_quote_char": '"' in text,
        "utf8_bom": has_bom,
        "line_ending": line_ending,
        "bytes_decompressed_for_header": len(buf),
        "method": f"first line only; decompressed <= {limit} bytes; naive split on delimiter",
    }


# --------------------------------------------------------------------------- hashing
def _progress_logger(label: str, total: int | None) -> Callable[[int], None]:
    state = {"next": PROGRESS_EVERY, "t0": time.perf_counter()}

    def report(done: int) -> None:
        if done >= state["next"]:
            el = time.perf_counter() - state["t0"]
            pct = f"{100 * done / total:5.1f}%" if total else "?"
            log.info("  %s: %s (%.2f GiB) at %.0f MiB/s", label, pct, done / 1024**3,
                     done / 1024**2 / el if el else 0)
            state["next"] += PROGRESS_EVERY
    return report


def sha256_stream(fh, progress: Callable[[int], None] | None = None) -> tuple[str, int]:
    """SHA-256 of a binary stream read in ``CHUNK`` pieces. Returns (hexdigest, bytes)."""
    h = hashlib.sha256()
    n = 0
    while chunk := fh.read(CHUNK):
        h.update(chunk)
        n += len(chunk)
        if progress:
            progress(n)
    return h.hexdigest(), n


def hash_file(path: Path) -> dict:
    st = path.stat()
    t0 = time.perf_counter()
    with path.open("rb") as fh:
        digest, n = sha256_stream(fh, _progress_logger(path.name, st.st_size))
    secs = time.perf_counter() - t0
    return {"sha256": digest, "bytes_read": n, "seconds": round(secs, 2),
            "mib_per_s": round(n / 1024**2 / secs, 1) if secs else ""}


def hash_zip_members(path: Path, skip: Callable[[zipfile.ZipInfo], bool] = lambda i: False
                     ) -> Iterator[dict]:
    """Stream-decompress each member, hashing it; CRC-32 is checked by zipfile at EOF."""
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or skip(info):
                continue
            t0 = time.perf_counter()
            digest, n, ok, err = "", 0, False, ""
            try:
                with zf.open(info) as fh:
                    digest, n = sha256_stream(fh, _progress_logger(info.filename, info.file_size))
                ok = n == info.file_size
                if not ok:
                    err = f"size mismatch: read {n}, central directory says {info.file_size}"
            except (zipfile.BadZipFile, OSError, EOFError) as exc:  # CRC failure lands here
                err = f"{type(exc).__name__}: {exc}"
                digest = ""
            secs = time.perf_counter() - t0
            yield {"member_name": info.filename, "size_bytes": info.file_size,
                   "sha256": digest, "crc32_expected": f"{info.CRC:08x}",
                   "crc32_verified": ok and not err, "bytes_read": n,
                   "seconds": round(secs, 2),
                   "mib_per_s": round(n / 1024**2 / secs, 1) if secs else "", "error": err}


def load_checksums(path: Path) -> dict[tuple[str, str, str], dict]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as fh:
        return {(r["object_type"], r["relpath"], r["member_name"]): r for r in csv.DictReader(fh)}


def save_checksums(path: Path, rows: dict[tuple[str, str, str], dict]) -> None:
    """Write the merged cache atomically (temp file + replace). Existing rows are kept."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CHECKSUM_FIELDS)
        w.writeheader()
        for key in sorted(rows):
            w.writerow({k: rows[key].get(k, "") for k in CHECKSUM_FIELDS})
    os.replace(tmp, path)


def _cache_valid(row: dict | None, size: int, container_size: int, mtime_ns: int) -> bool:
    return bool(row) and row.get("sha256", "") != "" and \
        str(row.get("size_bytes")) == str(size) and \
        str(row.get("container_size_bytes")) == str(container_size) and \
        str(row.get("container_mtime_ns")) == str(mtime_ns)


# --------------------------------------------------------------------------- commands
def cmd_scan(root: Path, registry: dict[str, dict], out_dir: Path, overwrite: bool) -> int:
    inv_path = out_dir / "dataset_inventory.csv"
    arc_path = out_dir / "archive_contents.csv"
    hdr_path = out_dir / "archive_member_headers.json"
    refuse_overwrite([inv_path, arc_path, hdr_path], overwrite)

    inventory, archive_rows, headers = [], [], {}
    files = discover_raw_files(root)
    registered = set(registry)
    log.info("scan: %d raw/root files discovered under %s", len(files), root.name)

    for path in files:
        rp = rel(path, root)
        key, meta = registry_lookup(registry, rp)
        registered.discard(key)
        st = path.stat()
        flags = ["empty_file"] if st.st_size == 0 else []
        if not meta:
            flags.append("unregistered")
        base = {
            "dataset_family": meta.get("dataset_family", ""),
            "variant": meta.get("variant", ""),
            "role": meta.get("role", "unregistered"),
            "release": meta.get("release", ""),
            "release_status": meta.get("release_status", ""),
        }
        inventory.append({
            **base, "record_type": "file", "relpath": rp, "archive_relpath": "",
            "member_name": "", "filename": path.name, "extension": path.suffix.lower(),
            "file_category": classify_file(path.name), "size_bytes": st.st_size,
            "compressed_bytes": "", "fs_mtime_utc": utc_iso(st.st_mtime),
            "archive_member_datetime_naive": "", **filename_day_tokens(path.name),
            "suspicious_flags": ";".join(flags), "notes": "fs mtime is filesystem metadata only",
        })
        if path.suffix.lower() != ".zip":
            continue
        try:
            members = list_zip_members(path)
        except (zipfile.BadZipFile, OSError) as exc:
            log.error("cannot read central directory of %s: %s: %s", rp, type(exc).__name__, exc)
            inventory[-1]["suspicious_flags"] += ";central_directory_unreadable"
            continue
        log.info("scan: %s -> %d members", rp, len(members))
        with zipfile.ZipFile(path) as zf:
            for m in members:
                archive_rows.append({"archive_relpath": rp, **m})
                inventory.append({
                    **base, "record_type": "archive_member", "relpath": "",
                    "archive_relpath": rp, "member_name": m["member_name"],
                    "filename": Path(m["member_name"]).name, "extension": m["extension"],
                    "file_category": m["file_category"], "size_bytes": m["uncompressed_bytes"],
                    "compressed_bytes": m["compressed_bytes"], "fs_mtime_utc": "",
                    "archive_member_datetime_naive": m["archive_member_datetime_naive"],
                    **filename_day_tokens(m["member_name"]),
                    "suspicious_flags": m["suspicious_flags"],
                    "notes": "size_bytes = uncompressed size from central directory; "
                             "zip datetime has no timezone",
                })
                if m["extension"] in {".csv", ".tsv"} and not m["is_dir"]:
                    try:
                        headers[f"{rp}::{m['member_name']}"] = read_member_header(zf, m["member_name"])
                    except (zipfile.BadZipFile, OSError, EOFError) as exc:
                        log.error("header read failed for %s::%s: %s", rp, m["member_name"], exc)
                        headers[f"{rp}::{m['member_name']}"] = {"error": f"{type(exc).__name__}: {exc}"}

    for missing in sorted(registered):
        log.warning("registered source not found on disk: %s", missing)

    out_dir.mkdir(parents=True, exist_ok=True)
    with inv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=INVENTORY_FIELDS)
        w.writeheader()
        w.writerows(inventory)
    with arc_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ARCHIVE_FIELDS)
        w.writeheader()
        w.writerows(archive_rows)
    with hdr_path.open("w", encoding="utf-8") as fh:
        json.dump({"generated_at_utc": now_utc(), "tool": TOOL, "members": headers}, fh, indent=2)
    log.info("scan: wrote %s (%d rows), %s (%d rows), %s (%d headers)", rel(inv_path, root),
             len(inventory), rel(arc_path, root), len(archive_rows), rel(hdr_path, root), len(headers))
    return 0


def cmd_hash(root: Path, targets: list[str], members: bool, checksums: Path, force: bool) -> int:
    cache = load_checksums(checksums)
    failures = 0
    for target in targets:
        path = (root / target)
        rp = rel(path, root)
        st_before = path.stat()
        size, mtime_ns = st_before.st_size, st_before.st_mtime_ns

        key = ("file", rp, "")
        if not force and _cache_valid(cache.get(key), size, size, mtime_ns):
            log.info("hash: %s cached (sha256 %s...), skipping", rp, cache[key]["sha256"][:16])
        else:
            log.info("hash: SHA-256 of %s (%.2f GiB)", rp, size / 1024**3)
            res = hash_file(path)
            cache[key] = {"object_type": "file", "relpath": rp, "member_name": "",
                          "size_bytes": size, "container_size_bytes": size,
                          "container_mtime_ns": mtime_ns, "crc32_expected": "",
                          "crc32_verified": "", "computed_at_utc": now_utc(), "tool": TOOL,
                          "error": "", **res}
            log.info("hash: %s sha256=%s (%.1f s, %s MiB/s)", rp, res["sha256"],
                     res["seconds"], res["mib_per_s"])
            save_checksums(checksums, cache)

        if members and path.suffix.lower() == ".zip":
            def skip(info: zipfile.ZipInfo) -> bool:
                ok = not force and _cache_valid(cache.get(("archive_member", rp, info.filename)),
                                                info.file_size, size, mtime_ns)
                if ok:
                    log.info("hash: %s::%s cached, skipping", rp, info.filename)
                return ok

            for res in hash_zip_members(path, skip):
                cache[("archive_member", rp, res["member_name"])] = {
                    "object_type": "archive_member", "relpath": rp,
                    "container_size_bytes": size, "container_mtime_ns": mtime_ns,
                    "computed_at_utc": now_utc(), "tool": TOOL, **res}
                status = "CRC OK" if res["crc32_verified"] else f"FAILED ({res['error']})"
                log.info("hash: %s::%s %s sha256=%s (%.1f s, %s MiB/s)", rp, res["member_name"],
                         status, res["sha256"], res["seconds"], res["mib_per_s"])
                failures += 0 if res["crc32_verified"] else 1
                save_checksums(checksums, cache)

        st_after = path.stat()
        if (st_after.st_size, st_after.st_mtime_ns) != (size, mtime_ns):
            log.error("raw file changed during hashing (size/mtime differ): %s", rp)
            failures += 1
        else:
            log.info("hash: %s unchanged after read (size and mtime_ns identical)", rp)
    return 1 if failures else 0


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=Path("."), help="project root (default: cwd)")
    p.add_argument("--config", type=Path, default=Path("configs/datasets.yaml"))
    p.add_argument("--log", type=Path, default=Path("logs/phase1_inventory.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="inventory files and archive members (central directory only)")
    s.add_argument("--out-dir", type=Path, default=Path("data/manifests"))
    s.add_argument("--overwrite", action="store_true", help="replace existing scan outputs")
    h = sub.add_parser("hash", help="streaming SHA-256 (+ member CRC verification)")
    h.add_argument("--target", action="append", required=True, help="file relative to root; repeatable")
    h.add_argument("--members", action="store_true", help="also hash/verify archive members")
    h.add_argument("--checksums", type=Path, default=Path("data/manifests/checksums_sha256.csv"))
    h.add_argument("--force", action="store_true", help="ignore the checksum cache")
    return p


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    for old in log.handlers:
        old.close()
    log.handlers[:] = [fh, sh]
    log.setLevel(logging.INFO)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    resolve = lambda p: p if p.is_absolute() else root / p  # noqa: E731
    setup_logging(resolve(args.log))
    log.info("=== %s %s | python %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv),
             sys.version.split()[0])
    t0 = time.perf_counter()
    try:
        if args.cmd == "scan":
            rc = cmd_scan(root, load_registry(resolve(args.config)), resolve(args.out_dir),
                          args.overwrite)
        else:
            rc = cmd_hash(root, args.target, args.members, resolve(args.checksums), args.force)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
