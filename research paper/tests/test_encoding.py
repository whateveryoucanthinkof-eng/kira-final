"""Tests for src/audit/encoding.py (synthetic files only)."""
from __future__ import annotations

import csv

from src.audit import encoding, inventory
from src.audit.common import DataFile


def write_check(root, rows):
    p = root / "data/manifests/encoding_check.csv"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=encoding.CHECK_FIELDS)
        w.writeheader()
        w.writerows(rows)


def test_check_counts_line_endings_across_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(encoding, "CHUNK", 4)  # force CRLF pairs to straddle chunks
    p = tmp_path / "m.csv"
    p.write_bytes(b"a,b\r\n1,2\r\n3,4\n5,6\n")
    r = encoding.check_file(p)
    assert (r["n_crlf"], r["n_bare_lf"], r["n_lone_cr"]) == (2, 2, 0)
    assert r["line_ending"] == "mixed" and r["first_bare_lf_offset"] == 13  # "3,4\n" -> LF at byte 13
    q = tmp_path / "c.csv"
    q.write_bytes(b"x\r\ny\r\n")
    assert encoding.check_file(q)["line_ending"] == "CRLF"


def test_check_detects_cp1252(tmp_path):
    p = tmp_path / "w.csv"
    p.write_bytes(b"Label\nWeb Attack \x96 XSS\n")
    r = encoding.check_file(p)
    assert r["utf8_valid"] is False and r["chosen_encoding"] == "cp1252" and r["n_non_ascii_bytes"] == 1


def test_readable_path_normalises_mixed_eol_and_transcodes(tmp_path, monkeypatch):
    monkeypatch.setattr(encoding, "cache_dir", lambda: tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    monkeypatch.setattr(encoding, "CHUNK", 5)
    raw = b"a,Label\r\n1,Web Attack \x96 XSS\r\n2,Benign\n3,Benign\n"
    src = tmp_path / "data/raw/m.csv"
    src.parent.mkdir(parents=True)
    src.write_bytes(raw)
    chk = encoding.check_file(src)
    write_check(tmp_path, [{"relpath": "data/raw/m.csv", **chk, "checked_at_utc": "x"}])
    df = DataFile("TEST", "original", "data/raw/m.csv", src)
    path, enc = encoding.readable_path(df, tmp_path)
    assert enc == "cp1252" and path != src
    assert path.read_bytes() == "a,Label\n1,Web Attack – XSS\n2,Benign\n3,Benign\n".encode("utf-8")
    assert src.read_bytes() == raw  # raw file untouched
    with (tmp_path / "data/manifests/encoding_transcode_manifest.csv").open(encoding="utf-8") as fh:
        row = next(csv.DictReader(fh))
    assert "CRLF -> LF (2 terminators)" in row["transform"] and "cp1252 -> utf-8" in row["transform"]
    # second call reuses the verified cache file
    assert encoding.readable_path(df, tmp_path) == (path, "cp1252")


def test_readable_path_in_place_for_clean_utf8(tmp_path):
    src = tmp_path / "data/raw/u.csv"
    src.parent.mkdir(parents=True)
    src.write_bytes(b"a\n1\n")
    write_check(tmp_path, [{"relpath": "data/raw/u.csv", **encoding.check_file(src), "checked_at_utc": "x"}])
    assert encoding.readable_path(DataFile("T", "improved", "data/raw/u.csv", src), tmp_path) == (src, "utf-8")
