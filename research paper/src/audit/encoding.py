"""Encoding check and lossless transcoding for DuckDB (read-only w.r.t. raw data).

DuckDB 1.5.6 cannot read the cp1252 byte 0x96 found in original CIC-IDS-2017 labels
("Web Attack \\x96 Brute Force"): utf-8 mode raises an INTERNAL error that invalidates the
connection, and latin-1 mode rejects the file. Files that are not valid UTF-8 are therefore
decoded as cp1252 (errors='strict', so an undefined byte stops the run instead of being
replaced) and written as UTF-8 to a cache directory under the OS temp dir (outside the
project and OneDrive). Raw files are never changed; every transcoded file is recorded with
both SHA-256 digests in ``data/manifests/encoding_transcode_manifest.csv``.

The cp1252 assumption is DOCUMENTED by the authors' own 2017 labelling code, which reads the
CSVs with ``pd.read_csv(path, encoding='cp1252')``.

Usage (from the project root)
-----------------------------
    python -I src/audit/encoding.py check      # writes data/manifests/encoding_check.csv
"""
from __future__ import annotations

import argparse
import codecs
import csv
import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import PROJECT_ROOT, DataFile, discover_data_files, load_config, portable_temp_path  # noqa: E402
from src.audit.inventory import CHUNK, now_utc  # noqa: E402

CHECK_FIELDS = ["relpath", "size_bytes", "n_non_ascii_bytes", "utf8_valid", "first_invalid_utf8_offset",
                "chosen_encoding", "n_crlf", "n_bare_lf", "n_lone_cr", "line_ending", "first_bare_lf_offset",
                "checked_at_utc"]
TRANSCODE_FIELDS = ["relpath", "source_sha256", "source_encoding", "transform", "cache_path", "cache_sha256",
                    "source_bytes", "cache_bytes", "created_at_utc"]


def cache_dir() -> Path:
    d = Path(tempfile.gettempdir()) / "nids_audit_cache" / "utf8"
    d.mkdir(parents=True, exist_ok=True)
    return d


def check_file(path: Path) -> dict:
    """Count non-ASCII bytes, test UTF-8 validity, and count line-ending types."""
    dec = codecs.getincrementaldecoder("utf-8")()
    n_high, offset, first_bad, valid = 0, 0, "", True
    n_lf = n_crlf = n_cr = 0
    first_bare_lf = ""
    prev_last = b""
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            if not chunk.isascii():
                n_high += sum(1 for b in chunk if b >= 0x80)
                if valid:
                    try:
                        dec.decode(chunk)
                    except UnicodeDecodeError as exc:
                        valid, first_bad = False, offset + exc.start
            elif valid:
                dec.decode(chunk)
            boundary = 1 if prev_last == b"\r" and chunk[:1] == b"\n" else 0
            crlf_here = chunk.count(b"\r\n") + boundary
            lf_here = chunk.count(b"\n")
            n_lf += lf_here
            n_crlf += crlf_here
            n_cr += chunk.count(b"\r")
            if first_bare_lf == "" and lf_here > crlf_here:
                i = 0
                while (j := chunk.find(b"\n", i)) >= 0:
                    before = chunk[j - 1:j] if j > 0 else prev_last
                    if before != b"\r":
                        first_bare_lf = offset + j
                        break
                    i = j + 1
            prev_last = chunk[-1:]
            offset += len(chunk)
    if valid:
        try:
            dec.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            valid, first_bad = False, offset + exc.start
    bare_lf, lone_cr = n_lf - n_crlf, n_cr - n_crlf
    ending = ("CRLF" if n_crlf and not bare_lf else "LF" if bare_lf and not n_crlf else
              "mixed" if n_crlf and bare_lf else "none")
    return {"size_bytes": offset, "n_non_ascii_bytes": n_high, "utf8_valid": valid,
            "first_invalid_utf8_offset": first_bad, "chosen_encoding": "utf-8" if valid else "cp1252",
            "n_crlf": n_crlf, "n_bare_lf": bare_lf, "n_lone_cr": lone_cr, "line_ending": ending,
            "first_bare_lf_offset": first_bare_lf if ending == "mixed" else ""}


def newline_option(df: DataFile, root: Path = PROJECT_ROOT) -> str:
    """DuckDB ``new_line`` option for a file, from the recorded line-ending check.

    Mixed files are read with LF as terminator; CRLF lines then keep a literal trailing CR
    in their last field, which the audit reports instead of silently normalising.
    """
    chk = load_check(root)[df.relpath]
    return "new_line='\\r\\n'" if chk["line_ending"] == "CRLF" else "new_line='\\n'"  # mixed -> normalised cache


def load_check(root: Path = PROJECT_ROOT) -> dict[str, dict]:
    p = root / "data/manifests/encoding_check.csv"
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as fh:
        return {r["relpath"]: r for r in csv.DictReader(fh)}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def readable_path(df: DataFile, root: Path = PROJECT_ROOT) -> tuple[Path, str]:
    """Path DuckDB should read, and the source encoding it represents.

    UTF-8 files with a single line-ending style are read in place. Others get a cache copy:
    cp1252 is transcoded to UTF-8, and in files with MIXED line endings every CRLF terminator
    is normalised to LF (DuckDB 1.5.6 silently dropped the CRLF section of such a file; see
    reports/schema_and_labels.md). Field contents are unchanged. A cache file is reused only if
    its SHA-256 matches the manifest.
    """
    chk = load_check(root).get(df.relpath)
    if chk is None:
        raise RuntimeError(f"no encoding check for {df.relpath}; run encoding.py check first")
    normalise_eol = chk["line_ending"] == "mixed"
    if chk["chosen_encoding"] == "utf-8" and not normalise_eol:
        return df.path, "utf-8"
    src_enc = chk["chosen_encoding"]
    manifest = root / "data/manifests/encoding_transcode_manifest.csv"
    rows = {}
    if manifest.exists():
        with manifest.open(encoding="utf-8") as fh:
            rows = {r["relpath"]: r for r in csv.DictReader(fh)}
    target = cache_dir() / (df.dataset_family + "__" + df.variant + "__" + df.path.name)
    known = rows.get(df.relpath)
    if known and target.exists() and _sha256(target) == known["cache_sha256"]:
        return target, src_enc
    src_sha, out_sha = hashlib.sha256(), hashlib.sha256()
    dec = codecs.getincrementaldecoder(src_enc)(errors="strict")
    tmp = target.with_suffix(".partial")
    n_in = n_out = n_eol = 0
    carry = b""
    with df.path.open("rb") as src, tmp.open("wb") as out:
        while chunk := src.read(CHUNK):
            src_sha.update(chunk)
            n_in += len(chunk)
            if normalise_eol:
                chunk = carry + chunk
                carry = b""
                if chunk.endswith(b"\r"):  # CR may pair with an LF in the next chunk
                    chunk, carry = chunk[:-1], b"\r"
                n_eol += chunk.count(b"\r\n")
                chunk = chunk.replace(b"\r\n", b"\n")
            data = dec.decode(chunk).encode("utf-8")
            out_sha.update(data)
            out.write(data)
            n_out += len(data)
        tail = dec.decode(carry, final=True).encode("utf-8")
        out.write(tail)
        out_sha.update(tail)
        n_out += len(tail)
    tmp.replace(target)
    transform = "; ".join(x for x in [f"{src_enc} -> utf-8" if src_enc != "utf-8" else "",
                                      f"CRLF -> LF ({n_eol} terminators)" if normalise_eol else ""] if x)
    rows[df.relpath] = {"relpath": df.relpath, "source_sha256": src_sha.hexdigest(), "source_encoding": src_enc,
                        "transform": transform, "cache_path": portable_temp_path(target), "cache_sha256": out_sha.hexdigest(),
                        "source_bytes": n_in, "cache_bytes": n_out, "created_at_utc": now_utc()}
    with manifest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=TRANSCODE_FIELDS)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in TRANSCODE_FIELDS} for r in (rows[k] for k in sorted(rows)))
    return target, src_enc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("cmd", choices=["check"])
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    out = PROJECT_ROOT / "data/manifests/encoding_check.csv"
    if out.exists() and not args.overwrite:
        print(f"refusing to overwrite {out} (pass --overwrite)", file=sys.stderr)
        return 2
    rows = []
    for df in discover_data_files(load_config()):
        r = {"relpath": df.relpath, **check_file(df.path), "checked_at_utc": now_utc()}
        print(f"{df.relpath}: non-ascii={r['n_non_ascii_bytes']} utf8_valid={r['utf8_valid']} -> "
              f"{r['chosen_encoding']} | endings={r['line_ending']} crlf={r['n_crlf']} lf={r['n_bare_lf']} "
              f"cr={r['n_lone_cr']}", flush=True)
        rows.append(r)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CHECK_FIELDS)
        w.writeheader()
        w.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
