"""Tests for src/audit/acquire.py. Uses only tiny synthetic files in tmp_path."""
from __future__ import annotations

import csv
import hashlib
import os
import stat
import zipfile
from pathlib import Path

from src.audit import acquire, inventory

A = b"id,Label\n1,BENIGN\n2,DoS\n"
B = b"id,Label\n3,BENIGN\n"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def project_with_zip(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    with zipfile.ZipFile(root / "d.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.csv", A)
        zf.writestr("b.csv", B)
    assert inventory.main(["--root", str(root), "hash", "--target", "d.zip", "--members"]) == 0
    return root


def manifest_rows(root: Path) -> list[dict]:
    with (root / "data/manifests/acquisition_manifest.csv").open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def make_writable(p: Path) -> None:
    os.chmod(p, stat.S_IWRITE | stat.S_IREAD)


def test_extract_verifies_and_never_overwrites(tmp_path):
    root = project_with_zip(tmp_path)
    argv = ["--root", str(root), "extract", "--archive", "d.zip", "--dest", "data/raw/x"]
    assert acquire.main(argv) == 0
    out = root / "data/raw/x"
    assert (out / "a.csv").read_bytes() == A and (out / "b.csv").read_bytes() == B
    assert not os.access(out / "a.csv", os.W_OK)  # marked read-only
    assert not list(out.glob("*.partial"))
    assert acquire.main(argv) == 0  # second run: skipped, not overwritten
    statuses = [r["status"] for r in manifest_rows(root)]
    assert statuses == ["ok", "ok", "skipped_exists", "skipped_exists"]
    for p in out.iterdir():
        make_writable(p)


def test_extract_rejects_hash_mismatch(tmp_path):
    root = project_with_zip(tmp_path)
    ck = root / "data/manifests/checksums_sha256.csv"
    cache = inventory.load_checksums(ck)
    cache[("archive_member", "d.zip", "a.csv")]["sha256"] = "0" * 64
    inventory.save_checksums(ck, cache)
    rc = acquire.main(["--root", str(root), "extract", "--archive", "d.zip", "--dest", "out"])
    assert rc == 1
    assert not (root / "out/a.csv").exists() and not (root / "out/a.csv.partial").exists()
    assert (root / "out/b.csv").read_bytes() == B
    make_writable(root / "out/b.csv")


def test_copy_excludes_and_preserves_mtime(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    src = tmp_path / "external"
    src.mkdir()
    (src / "a.csv").write_bytes(A)
    (src / ".gitkeep").write_bytes(b"")
    os.utime(src / "a.csv", (1_500_000_000, 1_500_000_000))
    rc = acquire.main(["--root", str(root), "copy", "--src", str(src), "--dest", "data/orig",
                       "--pattern", "*.csv"])
    assert rc == 0
    rows = {Path(r["source"]).name: r for r in manifest_rows(root)}
    assert rows[".gitkeep"]["status"] == "excluded"
    assert rows["a.csv"]["status"] == "ok" and rows["a.csv"]["sha256"] == sha(A)
    assert rows["a.csv"]["source_unchanged"] == "True"
    copied = root / "data/orig/a.csv"
    assert copied.read_bytes() == A and int(copied.stat().st_mtime) == 1_500_000_000
    assert (src / "a.csv").read_bytes() == A  # source untouched
    make_writable(copied)


def test_verify_detects_tampering_and_counts_newlines(tmp_path):
    root = project_with_zip(tmp_path)
    assert acquire.main(["--root", str(root), "extract", "--archive", "d.zip", "--dest", "x"]) == 0
    assert acquire.main(["--root", str(root), "verify"]) == 0
    with (root / "data/manifests/acquisition_verification.csv").open(encoding="utf-8") as fh:
        res = {r["dest_relpath"]: r for r in csv.DictReader(fh)}
    assert res["x/a.csv"]["verified"] == "True" and res["x/a.csv"]["n_newline_bytes"] == "3"
    assert inventory.load_checksums(root / "data/manifests/checksums_sha256.csv")[
        ("file", "x/a.csv", "")]["sha256"] == sha(A)
    assert acquire.main(["--root", str(root), "verify"]) == 2  # refuses overwrite
    target = root / "x/a.csv"
    make_writable(target)
    target.write_bytes(A.replace(b"DoS", b"XoS"))
    assert acquire.main(["--root", str(root), "verify", "--overwrite"]) == 1
    for p in (root / "x").iterdir():
        make_writable(p)
