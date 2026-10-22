"""Shared helpers for the audit phases: config, file discovery, DuckDB, headers, column roles.

Everything here is read-only with respect to raw data.
"""
from __future__ import annotations

import csv
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG = PROJECT_ROOT / "configs/data_audit.yaml"


def load_config(path: Path = CONFIG) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@dataclass(frozen=True)
class DataFile:
    dataset_family: str
    variant: str
    relpath: str
    path: Path

    @property
    def key(self) -> str:
        return f"{self.dataset_family}|{self.variant}|{Path(self.relpath).name}"


def discover_data_files(cfg: dict, root: Path = PROJECT_ROOT) -> list[DataFile]:
    """All CSVs under the configured data dirs, in deterministic (sorted) order."""
    files = []
    for d in cfg["data_dirs"]:
        base = root / d["path"]
        for p in sorted(base.glob("*.csv")):
            files.append(DataFile(d["dataset_family"], d["variant"],
                                  p.relative_to(root).as_posix(), p))
    return files


def norm_name(name: str) -> str:
    """Lowercase alphanumerics only: ' Flow ID' -> 'flowid'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


# Abbreviation/synonym tokens used to match original column names to improved ones
# (e.g. 'Tot Fwd Pkts' ~ 'Total Fwd Packet', 'Init_Win_bytes_forward' ~ 'FWD Init Win Bytes').
TOKEN_MAP = {
    "tot": ["total"], "totlen": ["total", "length"], "len": ["length"], "pkt": ["packet"],
    "pkts": ["packet"], "packets": ["packet"], "byts": ["bytes"], "cnt": ["count"],
    "backward": ["bwd"], "forward": ["fwd"], "source": ["src"], "destination": ["dst"],
    "average": ["avg"], "seg": ["segment"], "blk": ["bulk"], "b": ["bulk"], "var": ["variance"],
    "of": [],
}
MANUAL_OVERRIDES = {  # original token-key -> (improved token-key, basis)
    ("count", "cwe", "flag"): (("count", "cwr", "flag"),
                               "HYPOTHESIS: 'CWE' is a header typo for the CWR TCP flag in original releases"),
}


def token_key(name: str) -> tuple[str, ...]:
    toks = []
    for t in re.split(r"[^A-Za-z0-9]+", name.strip().lower()):
        if t:
            toks.extend(TOKEN_MAP.get(t, [t]))
    return tuple(sorted(toks))


def canonical_names(names: list[str], improved_names: list[str]) -> list[str]:
    """Map a file's column names onto the improved-release names where a match is defensible.

    Same rules as the Phase 2 schema diff: exact/whitespace/case match, then token-normalised
    match, then the documented manual override; otherwise the stripped original name.
    A repeated name keeps a ``__dupN`` suffix so it never collides with the first one.
    """
    by_strip = {n.strip(): n for n in improved_names}
    by_lower = {n.strip().lower(): n for n in improved_names}
    by_key: dict[tuple, list[str]] = {}
    for n in improved_names:
        by_key.setdefault(token_key(n), []).append(n)
    out, seen = [], {}
    for n in names:
        s = n.strip()
        if s in seen:
            seen[s] += 1
            out.append(f"{s}__dup{seen[s]}")
            continue
        seen[s] = 0
        tk = token_key(n)
        if s in by_strip:
            out.append(by_strip[s])
        elif s.lower() in by_lower:
            out.append(by_lower[s.lower()])
        elif len(by_key.get(tk, [])) == 1:
            out.append(by_key[tk][0])
        elif tk in MANUAL_OVERRIDES and len(by_key.get(MANUAL_OVERRIDES[tk][0], [])) == 1:
            out.append(by_key[MANUAL_OVERRIDES[tk][0]][0])
        else:
            out.append(s)
    return out


def column_role(name: str, cfg: dict) -> str:
    n = norm_name(name)
    for role, names in cfg["column_roles"].items():
        if n in names:
            return role
    return "feature"


def qident(name: str) -> str:
    """Quote a SQL identifier for DuckDB."""
    return '"' + name.replace('"', '""') + '"'


def sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def read_header(path: Path, limit: int = 1 << 20) -> dict:
    """Exact header names from the first line. UTF-8 is tried first, then cp1252/latin-1."""
    with path.open("rb") as fh:
        raw = fh.read(limit).split(b"\n", 1)[0].rstrip(b"\r")
    try:
        text, enc = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("latin-1"), "latin-1"
    names = next(csv.reader([text]))
    return {"names": names, "header_encoding": enc, "has_bom": raw.startswith(b"\xef\xbb\xbf")}


def portable_temp_path(p: Path) -> str:
    """Path under the OS temp dir written as '%TEMP%/...', so manifests carry no user-specific paths."""
    try:
        return "%TEMP%/" + Path(p).resolve().relative_to(Path(tempfile.gettempdir()).resolve()).as_posix()
    except ValueError:
        return Path(p).as_posix()


def duckdb_connect(cfg: dict):
    import duckdb

    d = cfg["duckdb"]
    tmp = Path(tempfile.gettempdir()) / d["temp_subdir"]
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"SET threads={int(d['threads'])}")
    con.execute(f"SET memory_limit={sql_str(d['memory_limit'])}")
    con.execute(f"SET temp_directory={sql_str(tmp.as_posix())}")
    con.execute("SET preserve_insertion_order=false")
    return con


def csv_source(path: Path, encoding: str, rejects: str | None = None, extra: str = "") -> str:
    """read_csv() expression that reads every column as VARCHAR (no type guessing)."""
    opts = [f"{sql_str(path.as_posix())}", "header=true", "all_varchar=true", "delim=','",
            "quote='\"'", "escape='\"'", f"encoding={sql_str(encoding)}", "auto_detect=false"]
    if rejects:
        opts += ["store_rejects=true", f"rejects_table={sql_str(rejects + '_errors')}",
                 f"rejects_scan={sql_str(rejects + '_scans')}"]
    if extra:
        opts.append(extra)
    return "read_csv(" + ", ".join(opts) + ")"


def columns_option(names: list[str]) -> tuple[str, list[str]]:
    """``columns={...}`` option giving every header column VARCHAR under its exact name.

    Passing names explicitly stops DuckDB from renaming or trimming them. A repeated name
    gets a ``__dupN`` suffix; the returned list says which name each position was given.
    """
    seen: dict[str, int] = {}
    out = []
    for n in names:
        k = n
        if k in seen:
            seen[k] += 1
            k = f"{n}__dup{seen[n]}"
        else:
            seen[k] = 0
        out.append(k)
    body = ", ".join(f"{sql_str(k)}: 'VARCHAR'" for k in out)
    return "columns={" + body + "}", out
