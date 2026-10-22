"""Tests for src/audit/inventory.py. Uses only tiny synthetic files in tmp_path."""
from __future__ import annotations

import csv
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from src.audit import inventory as inv

CSV_BYTES = b"Flow ID,Timestamp,Label\r\nx,2017-07-03 11:00:00.000001,BENIGN\r\n"
DOC_BYTES = b"readme\n"


def make_zip(path: Path, method: int = zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(path, "w", compression=method) as zf:
        zf.writestr("monday.csv", CSV_BYTES)
        zf.writestr("docs/README.txt", DOC_BYTES)
        zf.writestr("inner.zip", b"PK\x05\x06" + b"\x00" * 18)  # empty nested zip


def make_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    make_zip(root / "data_improved.zip")
    (root / "paper.pdf").write_bytes(b"%PDF-1.4\n")
    (root / "configs").mkdir()
    (root / "configs" / "datasets.yaml").write_text(
        "sources:\n"
        "  - path: data_improved.zip\n"
        "    dataset_family: CIC-IDS-2017\n"
        "    variant: improved\n"
        "    role: raw_improved\n"
        "    release: test\n"
        "    release_status: VERIFIED\n",
        encoding="utf-8",
    )
    return root


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.mark.parametrize("name,expected", [
    ("a.csv", "data"), ("A.PARQUET", "data"), ("x.zip", "archive"), ("p.pdf", "documentation"),
    ("s.py", "script"), ("weird.bin", "other"),
])
def test_classify_file(name, expected):
    assert inv.classify_file(name) == expected


def test_filename_day_tokens():
    t = inv.filename_day_tokens("Wednesday-14-02-2018.csv")
    assert t == {"filename_weekday_token": "wednesday", "filename_date_iso": "2018-02-14",
                 "weekday_matches_date": "True"}
    assert inv.filename_day_tokens("Friday-14-02-2018.csv")["weekday_matches_date"] == "False"
    typo = inv.filename_day_tokens("Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv")
    assert typo["weekday_matches_date"] == "token_not_weekday"
    assert inv.filename_day_tokens("monday.csv") == {
        "filename_weekday_token": "monday", "filename_date_iso": "", "weekday_matches_date": ""}


def test_unsafe_member_path():
    assert inv.is_unsafe_member_path("../evil.csv")
    assert inv.is_unsafe_member_path("/abs.csv")
    assert inv.is_unsafe_member_path("C:/x.csv")
    assert not inv.is_unsafe_member_path("dir/ok.csv")


def test_list_zip_members_and_header(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z)
    rows = {r["member_name"]: r for r in inv.list_zip_members(z)}
    assert rows["monday.csv"]["uncompressed_bytes"] == len(CSV_BYTES)
    assert rows["monday.csv"]["file_category"] == "data"
    assert rows["docs/README.txt"]["file_category"] == "documentation"
    assert rows["inner.zip"]["nested_archive"] is True
    assert "nested_archive" in rows["inner.zip"]["suspicious_flags"]
    with zipfile.ZipFile(z) as zf:
        h = inv.read_member_header(zf, "monday.csv")
    assert h["columns_naive_split"] == ["Flow ID", "Timestamp", "Label"]
    assert h["line_ending"] == "CRLF" and h["delimiter_guess"] == ","
    assert h["duplicate_column_names"] == []


def test_hash_members_match_and_crc(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z)
    res = {r["member_name"]: r for r in inv.hash_zip_members(z)}
    assert res["monday.csv"]["sha256"] == sha(CSV_BYTES)
    assert res["docs/README.txt"]["sha256"] == sha(DOC_BYTES)
    assert all(r["crc32_verified"] for r in res.values())


def test_crc_corruption_is_detected(tmp_path):
    z = tmp_path / "stored.zip"
    make_zip(z, method=zipfile.ZIP_STORED)
    raw = bytearray(z.read_bytes())
    pos = raw.find(b"BENIGN")
    raw[pos] ^= 0xFF  # flip one byte of stored member data
    z.write_bytes(bytes(raw))
    res = {r["member_name"]: r for r in inv.hash_zip_members(z)}
    assert res["monday.csv"]["crc32_verified"] is False
    assert "CRC" in res["monday.csv"]["error"]
    assert res["docs/README.txt"]["crc32_verified"] is True


def test_scan_outputs_and_refuses_overwrite(tmp_path):
    root = make_project(tmp_path)
    raw_before = sha((root / "data_improved.zip").read_bytes())
    argv = ["--root", str(root), "scan"]
    assert inv.main(argv) == 0
    with (root / "data/manifests/dataset_inventory.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    members = [r for r in rows if r["record_type"] == "archive_member"]
    assert len(members) == 3 and all(r["dataset_family"] == "CIC-IDS-2017" for r in members)
    pdf = next(r for r in rows if r["filename"] == "paper.pdf")
    assert "unregistered" in pdf["suspicious_flags"]
    hdr = json.loads((root / "data/manifests/archive_member_headers.json").read_text("utf-8"))
    assert "data_improved.zip::monday.csv" in hdr["members"]
    # second run must refuse rather than silently overwrite
    assert inv.main(argv) == 2
    assert inv.main(argv + ["--overwrite"]) == 0
    assert sha((root / "data_improved.zip").read_bytes()) == raw_before


def test_hash_cache_skips_rehash(tmp_path):
    root = make_project(tmp_path)
    argv = ["--root", str(root), "hash", "--target", "data_improved.zip", "--members"]
    assert inv.main(argv) == 0
    path = root / "data/manifests/checksums_sha256.csv"
    first = inv.load_checksums(path)
    assert first[("file", "data_improved.zip", "")]["sha256"] == sha(
        (root / "data_improved.zip").read_bytes())
    assert first[("archive_member", "data_improved.zip", "monday.csv")]["sha256"] == sha(CSV_BYTES)
    assert inv.main(argv) == 0
    second = inv.load_checksums(path)
    assert {k: v["sha256"] for k, v in first.items()} == {k: v["sha256"] for k, v in second.items()}
    log_text = (root / "logs/phase1_inventory.log").read_text(encoding="utf-8")
    second_run = log_text.rsplit("=== src/audit/inventory.py", 1)[1]
    assert "data_improved.zip cached" in second_run
    assert "data_improved.zip::monday.csv cached, skipping" in second_run
    assert "SHA-256 of" not in second_run
