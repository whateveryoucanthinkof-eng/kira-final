"""Acquire raw inputs into the project layout without touching the sources.

Subcommands
-----------
extract
    Stream every member of a ZIP into a directory, hashing while writing. Each member
    must reproduce the SHA-256 recorded for it in ``data/manifests/checksums_sha256.csv``
    (run ``inventory.py hash --members`` first).
copy
    Copy files from an external directory into a project directory, hashing while
    copying. The source's size and mtime are checked before and after; its mtime is
    preserved on the copy.
verify
    Re-read every acquired file from disk, recompute SHA-256, and compare with the
    acquisition manifest. Also counts newline bytes (an independent row-count check
    for CSVs) and records the results in the checksum cache.

Safety
------
- Sources are opened read-only. Existing destination files are never overwritten
  (they are reported as ``skipped_exists``).
- Data is written to ``<name>.partial`` and renamed only after its hash matches.
- Finished files are marked read-only.
- Every action, including exclusions and failures, is appended to
  ``data/manifests/acquisition_manifest.csv``.

Usage (from the project root)
-----------------------------
    python -I src/audit/acquire.py extract --archive CICIDS2017_improved.zip --dest data/raw_improved/CIC-IDS-2017
    python -I src/audit/acquire.py copy --src ../gnn/cic2017csv --dest data/raw_original/CIC-IDS-2017 --pattern "*.csv"
    python -I src/audit/acquire.py verify
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import logging
import os
import shutil
import stat
import sys
import time
import zipfile
from pathlib import Path

# Project root on sys.path so the sibling module resolves under `python -I`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.inventory import (  # noqa: E402
    CHUNK, is_unsafe_member_path, load_checksums, now_utc, save_checksums, setup_logging, utc_iso,
)

TOOL = "src/audit/acquire.py"
MANIFEST_FIELDS = [
    "action", "source", "source_member", "dest_relpath", "size_bytes", "sha256",
    "expected_sha256", "source_mtime_utc", "source_unchanged", "status", "seconds",
    "finished_at_utc", "tool", "note",
]
VERIFY_FIELDS = [
    "dest_relpath", "size_bytes", "expected_sha256", "sha256", "verified", "n_newline_bytes",
    "ends_with_newline", "seconds", "verified_at_utc", "error",
]

log = logging.getLogger("inventory")  # share handlers configured by setup_logging


def _relpath(path: Path, root: Path) -> str:
    return Path(os.path.relpath(path.resolve(), root.resolve())).as_posix()


def append_manifest(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in MANIFEST_FIELDS})


def ensure_space(dest: Path, needed: int, margin: float = 1.05) -> None:
    probe = dest
    while not probe.exists():
        probe = probe.parent
    free = shutil.disk_usage(probe).free
    if free < needed * margin:
        raise OSError(f"insufficient disk space: need {needed * margin:,.0f} B, free {free:,} B")
    log.info("disk check: need %.2f GiB, free %.2f GiB", needed / 1024**3, free / 1024**3)


def write_verified(src_stream, target: Path, expected: str | None, expected_size: int | None
                   ) -> tuple[str, int, bool, str]:
    """Copy a stream to ``target`` via ``target.partial`` while hashing.

    The final name appears only if the digest (and size, when given) match ``expected``;
    ``expected=None`` means "accept whatever was read" (used for copies, where the
    digest of the bytes read *is* the reference). Returns (digest, bytes, ok, note).
    """
    partial = target.with_name(target.name + ".partial")
    if partial.exists():
        log.warning("removing stale partial file from an earlier interrupted run: %s", partial)
        partial.unlink()
    h = hashlib.sha256()
    n = 0
    with partial.open("xb") as out:
        while chunk := src_stream.read(CHUNK):
            h.update(chunk)
            out.write(chunk)
            n += len(chunk)
        out.flush()
        os.fsync(out.fileno())
    digest = h.hexdigest()
    problems = []
    if expected is not None and digest != expected:
        problems.append(f"sha256 mismatch (expected {expected}, got {digest})")
    if expected_size is not None and n != expected_size:
        problems.append(f"size mismatch (expected {expected_size}, got {n})")
    if problems:
        partial.unlink()
        return digest, n, False, "; ".join(problems) + "; partial file deleted"
    os.rename(partial, target)  # fails rather than overwrites if target appeared meanwhile
    return digest, n, True, ""


def mark_read_only(path: Path) -> None:
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def cmd_extract(root: Path, archive_rel: str, dest_rel: str, checksums: Path, manifest: Path) -> int:
    archive, dest = root / archive_rel, root / dest_rel
    cache = load_checksums(checksums)
    failures = 0
    st_before = archive.stat()
    with zipfile.ZipFile(archive) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        ensure_space(dest, sum(i.file_size for i in infos))
        dest.mkdir(parents=True, exist_ok=True)
        for info in infos:
            row = {"action": "extract", "source": archive_rel, "source_member": info.filename,
                   "size_bytes": info.file_size, "tool": TOOL}
            expected = cache.get(("archive_member", archive_rel, info.filename), {}).get("sha256")
            target = dest / info.filename
            row["dest_relpath"] = _relpath(target, root)
            row["expected_sha256"] = expected or ""
            if is_unsafe_member_path(info.filename):
                row.update(status="failed", note="unsafe member path; refused")
            elif not expected:
                row.update(status="failed", note="no recorded member SHA-256; run inventory.py hash --members first")
            elif target.exists():
                row.update(status="skipped_exists", note="destination exists; not overwritten")
            else:
                t0 = time.perf_counter()
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src:
                    digest, n, ok, note = write_verified(src, target, expected, info.file_size)
                row.update(sha256=digest, seconds=round(time.perf_counter() - t0, 2), note=note,
                           status="ok" if ok else "failed")
                if ok:
                    mark_read_only(target)
            row["finished_at_utc"] = now_utc()
            failures += row["status"] == "failed"
            log.info("extract: %s::%s -> %s [%s] %s", archive_rel, info.filename,
                     row["dest_relpath"], row["status"], row.get("note", ""))
            append_manifest(manifest, row)
    st_after = archive.stat()
    if (st_before.st_size, st_before.st_mtime_ns) != (st_after.st_size, st_after.st_mtime_ns):
        log.error("archive changed during extraction: %s", archive_rel)
        failures += 1
    return 1 if failures else 0


def cmd_copy(root: Path, src_dir: Path, dest_rel: str, pattern: str, manifest: Path) -> int:
    src_dir = (src_dir if src_dir.is_absolute() else root / src_dir).resolve()
    dest = root / dest_rel
    files = sorted(p for p in src_dir.iterdir() if p.is_file())
    wanted = [p for p in files if fnmatch.fnmatch(p.name, pattern)]
    ensure_space(dest, sum(p.stat().st_size for p in wanted))
    dest.mkdir(parents=True, exist_ok=True)
    failures = 0
    for p in files:
        st0 = p.stat()
        target = dest / p.name
        row = {"action": "copy", "source": _relpath(p, root), "dest_relpath": _relpath(target, root),
               "size_bytes": st0.st_size, "source_mtime_utc": utc_iso(st0.st_mtime), "tool": TOOL}
        if p not in wanted:
            row.update(status="excluded", note=f"name does not match pattern {pattern!r}")
        elif target.exists():
            row.update(status="skipped_exists", note="destination exists; not overwritten")
        else:
            t0 = time.perf_counter()
            with p.open("rb") as src:
                digest, n, ok, note = write_verified(src, target, None, st0.st_size)
            st1 = p.stat()
            unchanged = (st0.st_size, st0.st_mtime_ns) == (st1.st_size, st1.st_mtime_ns)
            if ok:
                os.utime(target, ns=(st0.st_atime_ns, st0.st_mtime_ns))
                mark_read_only(target)
            row.update(sha256=digest, expected_sha256=digest, source_unchanged=unchanged,
                       seconds=round(time.perf_counter() - t0, 2),
                       status="ok" if ok and unchanged else "failed",
                       note=note if ok else note or "copy failed")
            if not unchanged:
                row["note"] = (row["note"] + "; " if row["note"] else "") + "SOURCE CHANGED DURING COPY"
        row["finished_at_utc"] = now_utc()
        failures += row["status"] == "failed"
        log.info("copy: %s -> %s [%s] %s", row["source"], row["dest_relpath"], row["status"],
                 row.get("note", ""))
        append_manifest(manifest, row)
    return 1 if failures else 0


def cmd_verify(root: Path, manifest: Path, out: Path, checksums: Path, overwrite: bool) -> int:
    if out.exists() and not overwrite:
        log.error("refusing to overwrite %s (pass --overwrite)", out)
        return 2
    with manifest.open(newline="", encoding="utf-8") as fh:
        latest = {r["dest_relpath"]: r for r in csv.DictReader(fh) if r["status"] == "ok"}
    cache = load_checksums(checksums)
    results, failures = [], 0
    for dest_rel, r in sorted(latest.items()):
        path = root / dest_rel
        t0 = time.perf_counter()
        res = {"dest_relpath": dest_rel, "expected_sha256": r["sha256"], "verified_at_utc": now_utc()}
        try:
            h, n, nl, last = hashlib.sha256(), 0, 0, b""
            with path.open("rb") as fh:
                while chunk := fh.read(CHUNK):
                    h.update(chunk)
                    n += len(chunk)
                    nl += chunk.count(b"\n")
                    last = chunk[-1:]
            res.update(size_bytes=n, sha256=h.hexdigest(), n_newline_bytes=nl,
                       ends_with_newline=last == b"\n", error="")
            res["verified"] = res["sha256"] == r["sha256"] and str(n) == r["size_bytes"]
            st = path.stat()
            cache[("file", dest_rel, "")] = {
                "object_type": "file", "relpath": dest_rel, "member_name": "", "size_bytes": n,
                "container_size_bytes": n, "container_mtime_ns": st.st_mtime_ns,
                "sha256": res["sha256"], "crc32_expected": "", "crc32_verified": "",
                "bytes_read": n, "seconds": round(time.perf_counter() - t0, 2), "mib_per_s": "",
                "computed_at_utc": res["verified_at_utc"], "tool": TOOL, "error": ""}
        except OSError as exc:
            res.update(verified=False, error=f"{type(exc).__name__}: {exc}")
        res["seconds"] = round(time.perf_counter() - t0, 2)
        failures += not res["verified"]
        log.info("verify: %s %s (%.1f s)", dest_rel, "OK" if res["verified"] else "FAILED", res["seconds"])
        results.append(res)
    save_checksums(checksums, cache)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=VERIFY_FIELDS)
        w.writeheader()
        w.writerows(results)
    log.info("verify: %d/%d files verified", len(results) - failures, len(results))
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--log", type=Path, default=Path("logs/acquisition.log"))
    p.add_argument("--manifest", type=Path, default=Path("data/manifests/acquisition_manifest.csv"))
    p.add_argument("--checksums", type=Path, default=Path("data/manifests/checksums_sha256.csv"))
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--archive", required=True)
    e.add_argument("--dest", required=True)
    c = sub.add_parser("copy")
    c.add_argument("--src", type=Path, required=True)
    c.add_argument("--dest", required=True)
    c.add_argument("--pattern", default="*")
    v = sub.add_parser("verify")
    v.add_argument("--out", type=Path, default=Path("data/manifests/acquisition_verification.csv"))
    v.add_argument("--overwrite", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    resolve = lambda p: p if p.is_absolute() else root / p  # noqa: E731
    setup_logging(resolve(args.log))
    log.info("=== %s %s | python %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv),
             sys.version.split()[0])
    t0 = time.perf_counter()
    try:
        if args.cmd == "extract":
            rc = cmd_extract(root, args.archive, args.dest, resolve(args.checksums), resolve(args.manifest))
        elif args.cmd == "copy":
            rc = cmd_copy(root, args.src, args.dest, args.pattern, resolve(args.manifest))
        else:
            rc = cmd_verify(root, resolve(args.manifest), resolve(args.out), resolve(args.checksums),
                            args.overwrite)
    except OSError as exc:
        log.error("%s: %s", type(exc).__name__, exc)
        rc = 1
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
