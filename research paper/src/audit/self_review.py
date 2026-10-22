"""Self-review: independent re-computation of headline audit numbers.

Everything here is computed with pyarrow + pandas + numpy straight from the raw CSVs (or, for the
reference values, read from the saved audit outputs). It shares NO SQL, NO DuckDB reader and NO
cache with the audit pipeline, so agreement is evidence that the pipeline's numbers are not an
artefact of one reader or one query.

Checks (results/audit/self_review_checks.csv; one row per check)
  R01  2017 improved row counts per file                 vs schema_by_file.json
  R02  2017 improved feature-identical copies            vs duplicates_by_file.csv
  R03  2017 improved rows in label-conflict groups + minimum unavoidable error
                                                         vs duplicates_by_file.csv / label_conflict_composition.csv
  R04  improved int16 header-length negatives and range  vs findings.csv (EXPORT_OVERFLOW)
  R05  share of flows lasting > 2 s per file (min-max)   vs temporal_feasibility.json
  R06  attack / Attempted flows outside documented windows (must be 0) and their total
                                                         vs label_window_consistency.csv
  R07  2018 improved row counts per file                 vs schema_by_file.json
  R08  stray flows dated before 23 Feb in Friday-23-02-2018 (expected 2,609)
  R09  next-window target per improved file: windows, positives, persistent (h=1)
                                                         vs temporal_feasibility.json, plus 2018 totals
                                                         recomputed WITHOUT the stray rows
  R10  original releases: every parsed hour in 1..12 (12-hour clock) and total rows

Usage (from the project root; reads ~45 GB once, streaming)
    python -I src/audit/self_review.py [--overwrite] [--only R01 R02 ...]
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pcsv

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/audit/self_review_checks.csv"
R = ROOT / "results/audit"
IMP = {"CIC-IDS-2017": ROOT / "data/raw_improved/CIC-IDS-2017",
       "CSE-CIC-IDS-2018": ROOT / "data/raw_improved/CSE-CIC-IDS-2018"}
ORIG = {"CIC-IDS-2017": ROOT / "data/raw_original/CIC-IDS-2017",
        "CSE-CIC-IDS-2018": ROOT / "data/raw_original/CSE-CIC-IDS-2018"}
WINDOW_US = 2_000_000
STRAY = ("Friday-23-02-2018.csv", pd.Timestamp("2018-02-23 00:00:00"))
BLOCK = 1 << 26  # 64 MiB CSV blocks


def results() -> list[dict]:
    return []


def ref_json(name: str) -> dict:
    return json.loads((R / name).read_text(encoding="utf-8"))


def ref_csv(name: str) -> pd.DataFrame:
    return pd.read_csv(R / name, keep_default_na=False)


def add(rows, cid, claim, source, expected, recomputed, method, t0, match=None):
    m = (str(expected) == str(recomputed)) if match is None else match
    rows.append({"check_id": cid, "claim": claim, "claim_source": source, "expected": expected,
                 "recomputed": recomputed, "match": bool(m), "method": method,
                 "seconds": round(time.perf_counter() - t0, 1)})
    print(f"{cid} {'OK  ' if m else 'DIFF'} {claim}: expected {expected} | recomputed {recomputed}", flush=True)


# ------------------------------------------------------------------------------------------ helpers
def is_attack(label: pd.Series) -> np.ndarray:
    l = label.astype(str)
    return (~l.str.strip().str.upper().eq("BENIGN") & ~l.str.endswith(" - Attempted")).to_numpy()


def next_window(ts_us: np.ndarray, attack: np.ndarray) -> dict:
    """2 s bins aligned to the Unix epoch, full grid from first to last bin; empty bins are benign."""
    b = np.floor_divide(ts_us, WINDOW_US)
    lo, hi = int(b.min()), int(b.max())
    a = np.zeros(hi - lo + 1, dtype=bool)
    a[np.unique(b[attack]) - lo] = True
    now, fut = a[:-1], a[1:]
    return {"windows": int(fut.size), "positive": int(fut.sum()), "persistent": int((fut & now).sum())}


def window_check(df: pd.DataFrame, rules: pd.DataFrame) -> tuple[int, int]:
    """(# non-benign flows, # outside every same-file/label/category documented window); bounds inclusive at us."""
    nb = df[~df["Label"].astype(str).str.strip().str.upper().eq("BENIGN")]
    outside = 0
    for (lab, cat), g in nb.groupby(["Label", "Attempted Category"], sort=False):
        rr = rules[(rules.label == lab) & (rules.attempted_category.astype(str) == str(cat))]
        t = g["ts_us"].to_numpy()
        inside = np.zeros(t.size, dtype=bool)
        for s, e in zip(rr.start_ns.to_numpy() // 1000, (rr.end_ns.to_numpy() + 999) // 1000):
            inside |= (t >= s) & (t <= e)
        outside += int((~inside).sum())
    return len(nb), outside


def read_improved(path: Path, columns: list[str] | None) -> pd.DataFrame:
    conv = pcsv.ConvertOptions(include_columns=columns, column_types={"Timestamp": pa.timestamp("us"),
                                                                      "Label": pa.string(),
                                                                      "Attempted Category": pa.string()})
    t = pcsv.read_csv(path, read_options=pcsv.ReadOptions(block_size=BLOCK), convert_options=conv)
    df = t.to_pandas()
    df["ts_us"] = t.column("Timestamp").cast(pa.int64()).to_numpy()
    return df


# ------------------------------------------------------------------------------------------ 2017 improved
def check_2017(rows: list[dict]) -> None:
    t0 = time.perf_counter()
    schema = {s["relpath"]: s for s in ref_json("schema_by_file.json")["files"]}
    dup = ref_csv("duplicates_by_file.csv")
    d = dup[(dup.scope == "dataset") & (dup.variant == "improved") & (dup.dataset_family == "CIC-IDS-2017")].iloc[0]
    feat = d.feature_key.split(": ", 1)[1].split("; ")
    rules = ref_csv("attack_windows_documented.csv")
    tf = ref_json("temporal_feasibility.json")["per_file"]
    hashes, labels, counts, long_share, nw_diff, n_nb, n_out = [], [], {}, {}, [], 0, 0
    neg = {"Fwd Header Length": 0, "Bwd Header Length": 0}
    rng = [0, 0]
    for p in sorted(IMP["CIC-IDS-2017"].glob("*.csv")):
        df = read_improved(p, None)
        rel = p.relative_to(ROOT).as_posix()
        counts[p.name] = (schema[rel]["n_rows"], len(df))
        x = df[feat].apply(pd.to_numeric, errors="coerce").astype("float64")
        hashes.append(pd.util.hash_pandas_object(x, index=False).to_numpy())
        labels.append(df["Label"].astype(str).to_numpy())
        for c in neg:
            v = pd.to_numeric(df[c], errors="coerce")
            neg[c] += int((v < 0).sum())
            rng = [min(rng[0], v.min()), max(rng[1], v.max())]
        long_share[p.name] = (pd.to_numeric(df["Flow Duration"]) > WINDOW_US).mean()
        a, o = window_check(df, rules[rules.file == p.name])
        n_nb, n_out = n_nb + a, n_out + o
        nw = next_window(df["ts_us"].to_numpy(), is_attack(df["Label"]))
        ref = tf[rel]["next_window_target_excl_attempted"]["1"]
        nw_diff.append((p.name, nw, {"windows": ref["n_windows_with_target"], "positive": ref["n_positive_target"],
                                     "persistent": ref["n_persistent (attack now and at t+h)"]}))
        del df, x
    add(rows, "R01", "2017 improved rows per file", "schema_by_file.json",
        {k: v[0] for k, v in counts.items()}, {k: v[1] for k, v in counts.items()}, "pyarrow full read", t0)
    h = np.concatenate(hashes)
    lab = np.concatenate(labels)
    add(rows, "R02", "2017 improved feature-identical copies (83 feature columns, by value)", "duplicates_by_file.csv",
        int(d.n_feature_duplicate_rows), int(h.size - np.unique(h).size), "pandas hash_pandas_object on float64", t0)
    g = pd.DataFrame({"h": h, "lab": lab})
    per = g.groupby(["h", "lab"]).size().rename("n").reset_index()
    nlab = per.groupby("h")["lab"].transform("size")
    conf = per[nlab > 1]
    tot = conf.groupby("h")["n"].agg(["sum", "max"])
    comp = ref_csv("label_conflict_composition.csv")
    comp17 = comp[comp.dataset_family == "CIC-IDS-2017"]
    add(rows, "R03", "2017 improved rows in label-conflict groups / minimum unavoidable error",
        "duplicates_by_file.csv; label_conflict_composition.csv",
        f"{int(d.n_rows_in_label_conflict_groups)} / {int(comp17.n_min_error_rows.sum())}",
        f"{int(tot['sum'].sum())} / {int((tot['sum'] - tot['max']).sum())}", "pandas groupby on row hashes", t0)
    add(rows, "R04a", "2017 improved negative Fwd/Bwd Header Length; all values within int16",
        "findings.csv EXPORT_OVERFLOW-001/002", "309 / 472; True",
        f"{neg['Fwd Header Length']} / {neg['Bwd Header Length']}; {bool(rng[0] >= -32768 and rng[1] <= 32767)}",
        "pandas", t0)
    ls = sorted(long_share.values())
    add(rows, "R05a", "2017 improved share of flows lasting > 2 s (min-max over files)",
        "reports/temporal_feasibility.md §3", "23.9%-30.7%", f"{ls[0]:.1%}-{ls[-1]:.1%}", "pandas", t0)
    add(rows, "R06a", "2017 improved non-benign flows / outside documented windows", "label_window_consistency.csv",
        f"{lwc_total('CIC-IDS-2017')} / 0", f"{n_nb} / {n_out}", "numpy interval test against attack_windows_documented.csv", t0)
    add(rows, "R09a", "2017 improved next-window h=1 per file (windows, positives, persistent)",
        "temporal_feasibility.json", "all 5 files equal", "all 5 files equal" if all(a == b for _, a, b in nw_diff)
        else "; ".join(f"{n}: {a} vs {b}" for n, a, b in nw_diff if a != b), "numpy epoch-aligned 2 s grid", t0)


def lwc_total(ds: str) -> int:
    lw = ref_csv("label_window_consistency.csv")
    col = next(c for c in lw.columns if c.startswith("n_") and ("flows" in c or "rows" in c))
    return int(pd.to_numeric(lw[lw.dataset_family == ds][col]).sum())


# ------------------------------------------------------------------------------------------ 2018 improved
def check_2018(rows: list[dict]) -> None:
    t0 = time.perf_counter()
    schema = {s["relpath"]: s for s in ref_json("schema_by_file.json")["files"]}
    rules = ref_csv("attack_windows_documented.csv")
    tf = ref_json("temporal_feasibility.json")["per_file"]
    cols = ["Timestamp", "Label", "Attempted Category", "Flow Duration", "Fwd Header Length", "Bwd Header Length"]
    counts, long_share, neg, rng, n_nb, n_out, stray = {}, {}, [0, 0], [0, 0], 0, 0, None
    nw_tot = {"windows": 0, "positive": 0, "persistent": 0}
    nw_tot_excl = {"windows": 0, "positive": 0, "persistent": 0}
    nw_equal = []
    for p in sorted(IMP["CSE-CIC-IDS-2018"].glob("*.csv")):
        df = read_improved(p, cols)
        rel = p.relative_to(ROOT).as_posix()
        counts[p.name] = (schema[rel]["n_rows"], len(df))
        for i, c in enumerate(("Fwd Header Length", "Bwd Header Length")):
            v = df[c].to_numpy()
            neg[i] += int((v < 0).sum())
            rng = [min(rng[0], v.min()), max(rng[1], v.max())]
        long_share[p.name] = float((df["Flow Duration"].to_numpy() > WINDOW_US).mean())
        a, o = window_check(df, rules[rules.file == p.name])
        n_nb, n_out = n_nb + a, n_out + o
        att = is_attack(df["Label"])
        ts = df["ts_us"].to_numpy()
        nw = next_window(ts, att)
        ref = tf[rel]["next_window_target_excl_attempted"]["1"]
        nw_equal.append(nw == {"windows": ref["n_windows_with_target"], "positive": ref["n_positive_target"],
                               "persistent": ref["n_persistent (attack now and at t+h)"]})
        for k in nw_tot:
            nw_tot[k] += nw[k]
        keep = np.ones(ts.size, dtype=bool)
        if p.name == STRAY[0]:
            cut = int(STRAY[1].value // 1000)
            stray = int((ts < cut).sum())
            keep = ts >= cut
        nwx = next_window(ts[keep], att[keep])
        for k in nw_tot_excl:
            nw_tot_excl[k] += nwx[k]
        del df
    add(rows, "R07", "2018 improved rows per file", "schema_by_file.json",
        {k: v[0] for k, v in counts.items()}, {k: v[1] for k, v in counts.items()}, "pyarrow streaming read", t0)
    add(rows, "R04b", "2018 improved negative Fwd/Bwd Header Length; all values within int16",
        "findings.csv EXPORT_OVERFLOW-003/004", "10039 / 17509; True",
        f"{neg[0]} / {neg[1]}; {bool(rng[0] >= -32768 and rng[1] <= 32767)}", "numpy", t0)
    ls = sorted(long_share.values())
    add(rows, "R05b", "2018 improved share of flows lasting > 2 s (min-max over files)",
        "reports/temporal_feasibility.md §3", "22.3%-38.1%", f"{ls[0]:.1%}-{ls[-1]:.1%}", "numpy", t0)
    add(rows, "R06b", "2018 improved non-benign flows / outside documented windows", "label_window_consistency.csv",
        f"{lwc_total('CSE-CIC-IDS-2018')} / 0", f"{n_nb} / {n_out}", "numpy interval test", t0)
    add(rows, "R08", "Friday-23-02-2018 improved: flows dated before 23 Feb", "findings.csv TIMESTAMP-003",
        2609, stray, "pyarrow timestamp parse", t0)
    add(rows, "R09b", "2018 improved next-window h=1 per file equals the pipeline", "temporal_feasibility.json",
        "all 10 files equal", f"{sum(nw_equal)} of 10 files equal", "numpy epoch-aligned 2 s grid", t0,
        match=all(nw_equal))
    add(rows, "R09c", "2018 improved next-window h=1 totals (windows, positives, positive rate) INCLUDING stray rows",
        "reports/temporal_feasibility.md §5", "300254, 22183, 7.39%",
        f"{nw_tot['windows']}, {nw_tot['positive']}, {nw_tot['positive'] / nw_tot['windows']:.2%}", "numpy", t0)
    add(rows, "R09d", "2018 improved next-window h=1 totals EXCLUDING the 2,609 stray rows (corrected figure)",
        "new (self-review)", "not previously reported",
        f"{nw_tot_excl['windows']}, {nw_tot_excl['positive']}, {nw_tot_excl['positive'] / nw_tot_excl['windows']:.2%}; "
        f"persistence share {nw_tot_excl['persistent'] / nw_tot_excl['positive']:.1%}", "numpy", t0, match=True)


# ------------------------------------------------------------------------------------------ originals
def check_originals(rows: list[dict]) -> None:
    t0 = time.perf_counter()
    rx = re.compile(r" (\d{1,2}):\d{2}")
    for ds, d in ORIG.items():
        hours, n_rows, bad_files = set(), 0, []
        for p in sorted(d.glob("*.csv")):
            with p.open("rb") as fh:
                header = fh.readline().decode("cp1252").rstrip("\r\n").split(",")
            names = [f"c{i}" for i in range(len(header))]
            ti = next(i for i, h in enumerate(header) if h.strip() == "Timestamp")
            enc = "cp1252" if "WebAttacks" in p.name else "utf8"
            reader = pcsv.open_csv(p, read_options=pcsv.ReadOptions(column_names=names, skip_rows=1, block_size=BLOCK,
                                                                     encoding=enc),
                                   convert_options=pcsv.ConvertOptions(include_columns=[names[ti]],
                                                                       column_types={names[ti]: pa.string()}),
                                   parse_options=pcsv.ParseOptions(newlines_in_values=False))
            fh_hours = set()
            for batch in reader:
                col = batch.column(0)
                n_rows += batch.num_rows
                m = pc.extract_regex(col, r" (?P<h>\d{1,2}):\d{2}")
                hs = pc.struct_field(m, "h").drop_null()
                fh_hours |= {int(x) for x in pc.unique(hs).to_pylist()}
            hours |= fh_hours
            if not fh_hours <= set(range(1, 13)):
                bad_files.append(p.name)
        add(rows, f"R10{'a' if ds == 'CIC-IDS-2017' else 'b'}",
            f"{ds} original: rows read; every parsed hour in 1..12 (12-hour clock, no AM/PM)",
            "schema_by_file.json; reports/dataset_audit_report.md §2",
            f"{3119345 if ds == 'CIC-IDS-2017' else 16233002}; True",
            f"{n_rows}; {not bad_files} (hours seen: {sorted(hours)})",
            "pyarrow streaming read, regex hour extraction", t0,
            match=(n_rows == (3119345 if ds == "CIC-IDS-2017" else 16233002)) and not bad_files)
        t0 = time.perf_counter()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--only", nargs="+", choices=["2017", "2018", "originals"])
    a = ap.parse_args(argv)
    if OUT.exists() and not a.overwrite:
        print(f"refusing to overwrite {OUT} (pass --overwrite)")
        return 2
    rows: list[dict] = []
    steps = {"2017": check_2017, "2018": check_2018, "originals": check_originals}
    for name, fn in steps.items():
        if not a.only or name in a.only:
            fn(rows)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in r.items()})
    n_bad = sum(not r["match"] for r in rows)
    print(f"{len(rows)} checks, {n_bad} differences -> {OUT.relative_to(ROOT).as_posix()}")
    return 1 if n_bad else 0


if __name__ == "__main__":
    sys.exit(main())
