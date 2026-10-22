"""Phase 4: original-versus-improved comparison (read-only).

Subcommands (run from the project root, after Phases 2-3)
---------------------------------------------------------
families  Label-family counts, original vs improved, per dataset (configs/label_family_map.yaml).
features  Dataset-scope feature distributions, original vs improved (from numeric_feature_summary.csv).
matching  Row-matching FEASIBILITY: can an original flow be matched to exactly one improved flow by
          (src ip, src port, dst ip, dst port, protocol, start time at the original's resolution)?
          The original timestamps carry no timezone, so whole-hour offsets are searched on a
          deterministic sample; the 12-hour clock without AM/PM of the originals (both datasets,
          detected from the parsed hour histogram) is handled by comparing hour modulo 12, so an
          offset is identified only modulo 12 h plus the date. A label transition matrix is written ONLY for day pairs with
          unique-match coverage >= MIN_UNIQUE_COVERAGE and ambiguity <= MAX_AMBIGUOUS.
summary   original_vs_improved_summary.csv from all Phase 2-4 outputs.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import PROJECT_ROOT, DataFile, discover_data_files, duckdb_connect, load_config, sql_str  # noqa: E402
from src.audit.integrity import guard, timeline_path, write_csv  # noqa: E402
from src.audit.inventory import setup_logging  # noqa: E402

TOOL = "src/audit/compare.py"
OUT = Path("results/audit")
MIN_UNIQUE_COVERAGE = 0.90
MAX_AMBIGUOUS = 0.02
SAMPLE_MOD = 20          # offset search uses rows with hash(rn) % 20 = 0 (~5%)
OFFSETS_H = range(-12, 13)
log = logging.getLogger("inventory")

# original file -> improved file (same capture day)
DAY_PAIRS_2017 = {
    "Monday-WorkingHours.pcap_ISCX.csv": "monday.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "tuesday.csv",
    "Wednesday-workingHours.pcap_ISCX.csv": "wednesday.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "thursday.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "thursday.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "friday.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "friday.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "friday.csv",
}


def label_map(root: Path) -> dict:
    return yaml.safe_load((root / "configs/label_family_map.yaml").read_text(encoding="utf-8"))


def family_of(lmap: dict, ds: str, label: str) -> tuple[str, bool]:
    attempted = label.endswith(" - Attempted")
    base = label[: -len(" - Attempted")] if attempted else label
    e = lmap.get(ds, {}).get(base)
    return (e["family"] if e else f"UNMAPPED:{base}"), attempted


def cmd_families(root: Path, overwrite: bool) -> int:
    out = root / OUT / "label_family_comparison.csv"
    guard([out], overwrite)
    lmap = label_map(root)
    with (root / OUT / "label_distribution_by_dataset.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    agg = defaultdict(lambda: defaultdict(int))
    totals = {}
    for r in rows:
        fam, att = family_of(lmap, r["dataset_family"], r["label"])
        key = (r["dataset_family"], fam)
        col = r["variant"] + ("_attempted" if att else "")
        agg[key][col] += int(r["count"])
        totals[(r["dataset_family"], r["variant"])] = int(r["rows_in_dataset"])
    outrows = []
    for (ds, fam), c in sorted(agg.items()):
        o, i, ia = c.get("original", 0), c.get("improved", 0), c.get("improved_attempted", 0)
        outrows.append({"dataset_family": ds, "family": fam, "original_count": o,
                        "original_share": round(o / totals[(ds, "original")], 8),
                        "improved_count_not_attempted": i, "improved_count_attempted": ia,
                        "improved_share_not_attempted": round(i / totals[(ds, "improved")], 8),
                        "improved_total_vs_original_ratio": round((i + ia) / o, 4) if o else "",
                        "improved_not_attempted_vs_original_ratio": round(i / o, 4) if o else "",
                        "comparison_level": "label-family counts (not row correspondence)"})
    write_csv(out, outrows)
    log.info("families: %d rows", len(outrows))
    return 0


STATS = ["n_numeric", "n_pos_inf", "n_neg_inf", "n_nan", "n_negative", "n_zero", "min", "q01", "q25", "q50",
         "q75", "q99", "max", "mean", "std"]


def cmd_features(root: Path, overwrite: bool) -> int:
    out = root / OUT / "feature_distribution_comparison.csv"
    guard([out], overwrite)
    with (root / OUT / "numeric_feature_summary.csv").open(encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["scope"] == "dataset"]
    by = {(r["dataset_family"], r["variant"], r["column"]): r for r in rows}
    outrows = []
    for (ds, var, col), r in sorted(by.items()):
        if var != "improved":
            continue
        o = by.get((ds, "original", col))

        def f(x):
            try:
                return float(x)
            except (TypeError, ValueError):
                return None

        row = {"dataset_family": ds, "column": col, "in_original": o is not None}
        for s in STATS:
            row[f"improved_{s}"] = r.get(s, "")
            row[f"original_{s}"] = o.get(s, "") if o else ""
        if o:
            ni, no = f(r["n_rows"]), f(o["n_rows"])
            for s in ("q50", "q99", "mean"):
                a, b = f(r[s]), f(o[s])
                row[f"rel_change_{s}"] = round((a - b) / abs(b), 6) if a is not None and b not in (None, 0.0) else ""
            row["improved_share_zero"] = round(f(r["n_zero"]) / ni, 6) if ni else ""
            row["original_share_zero"] = round(f(o["n_zero"]) / no, 6) if no else ""
            row["improved_nonfinite"] = int(f(r["n_pos_inf"]) + f(r["n_neg_inf"]) + f(r["n_nan"]))
            row["original_nonfinite"] = int(f(o["n_pos_inf"]) + f(o["n_neg_inf"]) + f(o["n_nan"]))
        row["caveat"] = "dataset-level marginals; differences mix feature fixes, flow-termination changes and label/class composition"
        outrows.append(row)
    write_csv(out, outrows)
    log.info("features: %d rows", len(outrows))
    return 0


def resolution_of(fmts: str) -> str:
    return "second" if "%S" in fmts else "minute"


def cmd_matching(root: Path, cfg: dict, overwrite: bool) -> int:
    out_f, out_t = root / OUT / "row_matching_feasibility.csv", root / OUT / "label_transition_matrix.csv"
    guard([out_f, out_t], overwrite)
    files = discover_data_files(cfg, root)
    by_name = {(f.dataset_family, f.variant, Path(f.relpath).name): f for f in files}
    with (root / "data/manifests/timeline_cache_manifest.csv").open(encoding="utf-8") as fh:
        fmts = {r["relpath"]: r["timestamp_formats"] for r in csv.DictReader(fh)}
    with (root / OUT / "timestamp_quality.csv").open(encoding="utf-8") as fh:
        clock12 = {r["file"]: all(1 <= int(h) <= 12 for h in json.loads(r["hour_histogram_as_parsed"]))
                   for r in csv.DictReader(fh) if r["variant"] == "original"}
    pairs =[("CIC-IDS-2017", o, i) for o, i in DAY_PAIRS_2017.items()]
    pairs += [("CSE-CIC-IDS-2018", f.path.name, f.path.name.split("_")[0].replace("Thuesday", "Tuesday") + ".csv")
              for f in files if f.dataset_family == "CSE-CIC-IDS-2018" and f.variant == "original"]
    con = duckdb_connect(cfg)
    feas, trans = [], []
    for ds, oname, iname in pairs:
        fo, fi = by_name[(ds, "original", oname)], by_name[(ds, "improved", iname)]
        t0 = time.perf_counter()
        so, si = (f"read_parquet({sql_str(timeline_path(x).as_posix())})" for x in (fo, fi))
        has_tuple = con.execute(f"SELECT count(src_ip) > 0 FROM {so}").fetchone()[0]
        res = resolution_of(fmts[fo.relpath])
        # 12-hour clock without AM/PM, decided from the data: every parsed hour lies in 1..12 (no 0, no
        # 13-23). True for all 2017 and all 2018 originals (timestamp_quality.csv hour histograms).
        twelve = clock12[fo.relpath]
        trunc = "minute" if res == "minute" else "second"

        def tkey(expr: str) -> str:
            t = f"date_trunc('{trunc}', {expr})"
            if twelve:  # 12-hour clock without AM/PM in the original: compare day, hour mod 12, minute[, second]
                sec = f" || ':' || second({t})::VARCHAR" if trunc == "second" else ""
                return (f"(strftime({t}, '%Y-%m-%d') || ' ' || (hour({t}) % 12)::VARCHAR || ':' || "
                        f"minute({t})::VARCHAR{sec})")
            return f"strftime({t}, '%Y-%m-%d %H:%M:%S')"

        cols = "src_ip, src_port, dst_ip, dst_port, protocol" if has_tuple else "dst_port, protocol"
        base = {"dataset_family": ds, "original_file": oname, "improved_file": iname,
                "key": f"({cols}, start time at {trunc} resolution{'; hour mod 12' if twelve else ''})",
                "original_has_5tuple": has_tuple}
        # 1) offset search on a deterministic sample of labelled original rows
        best = (None, -1.0)
        scan = []
        for h in OFFSETS_H:
            q = con.execute(
                f"WITH o AS (SELECT {cols}, {tkey('ts')} k FROM {so} WHERE ts IS NOT NULL AND label IS NOT NULL "
                f"AND hash(rn) % {SAMPLE_MOD} = 0), i AS (SELECT DISTINCT {cols}, {tkey(f'ts + to_hours({h})')} k "
                f"FROM {si} WHERE ts IS NOT NULL) SELECT count(*), count_if(EXISTS (SELECT 1 FROM i WHERE "
                + " AND ".join(f"i.{c} IS NOT DISTINCT FROM o.{c}" for c in cols.split(", ")) +
                " AND i.k = o.k)) FROM o").fetchone()
            rate = q[1] / q[0] if q[0] else 0.0
            scan.append((h, round(rate, 4)))
            if rate > best[1]:
                best = (h, rate)
        h = best[0]
        # 2) evaluation at the best offset: all rows when the 5-tuple exists; otherwise the sample only
        #    (a (dst port, protocol, time) key matches very many flows, and the pair cannot be defensible)
        scope_filter = "" if has_tuple else f" AND hash(rn) % {SAMPLE_MOD} = 0"
        base["evaluation_scope"] = "all labelled original rows" if has_tuple else f"sample hash(rn) % {SAMPLE_MOD} = 0"
        q = con.execute(
            f"WITH o AS (SELECT rn, label, {cols}, {tkey('ts')} k FROM {so} WHERE ts IS NOT NULL AND label IS NOT NULL{scope_filter}), "
            f"i AS (SELECT label ilabel, {cols}, {tkey(f'ts + to_hours({h})')} k FROM {si} WHERE ts IS NOT NULL), "
            f"m AS (SELECT o.rn, o.label, count(i.k) n_cand, min(i.ilabel) il_min, max(i.ilabel) il_max FROM o LEFT JOIN i ON "
            + " AND ".join(f"i.{c} IS NOT DISTINCT FROM o.{c}" for c in cols.split(", ")) +
            " AND i.k = o.k GROUP BY o.rn, o.label) "
            "SELECT count(*), count_if(n_cand = 1), count_if(n_cand > 1), count_if(n_cand = 0), "
            "count_if(n_cand > 1 AND il_min <> il_max) FROM m").fetchone()
        n, uniq, amb, none, amb_conflict = q
        cov, ambr = (uniq / n if n else 0), (amb / n if n else 0)
        defensible = has_tuple and cov >= MIN_UNIQUE_COVERAGE and ambr <= MAX_AMBIGUOUS
        feas.append({**base, "best_offset_hours_added_to_improved_utc": h,
                     "sample_match_rate_at_best": round(best[1], 4), "offset_scan": json.dumps(scan),
                     "n_original_rows": n, "n_unique_match": uniq, "n_ambiguous_match": amb,
                     "n_ambiguous_with_conflicting_improved_labels": amb_conflict, "n_unmatched": none,
                     "unique_coverage": round(cov, 4), "ambiguous_share": round(ambr, 4),
                     "defensible_for_row_level": defensible,
                     "criteria": f"5-tuple present, unique>={MIN_UNIQUE_COVERAGE}, ambiguous<={MAX_AMBIGUOUS}"})
        if defensible:
            for ol, il, c in con.execute(
                    f"WITH o AS (SELECT rn, label, {cols}, {tkey('ts')} k FROM {so} WHERE ts IS NOT NULL AND label IS NOT NULL), "
                    f"i AS (SELECT label ilabel, {cols}, {tkey(f'ts + to_hours({h})')} k FROM {si} WHERE ts IS NOT NULL), "
                    f"m AS (SELECT o.rn, o.label, count(i.k) n_cand, min(i.ilabel) il FROM o LEFT JOIN i ON "
                    + " AND ".join(f"i.{c} IS NOT DISTINCT FROM o.{c}" for c in cols.split(", ")) +
                    " AND i.k = o.k GROUP BY o.rn, o.label) "
                    "SELECT label, il, count(*) FROM m WHERE n_cand = 1 GROUP BY 1, 2 ORDER BY 1, 3 DESC").fetchall():
                trans.append({"dataset_family": ds, "original_file": oname, "improved_file": iname,
                              "original_label": ol, "improved_label": il, "n_uniquely_matched_flows": c,
                              "scope": f"unique matches only ({round(cov * 100, 2)}% of original rows)"})
        log.info("matching: %s -> %s offset=%s unique=%.3f amb=%.3f (%.1f s)", oname, iname, h, cov, ambr,
                 time.perf_counter() - t0)
    con.close()
    write_csv(out_f, feas)
    write_csv(out_t, trans, ["dataset_family", "original_file", "improved_file", "original_label", "improved_label",
                             "n_uniquely_matched_flows", "scope"])
    return 0


def cmd_summary(root: Path, overwrite: bool) -> int:
    """One row per (dataset, metric): original value, improved value, and the evidence file."""
    out = root / OUT / "original_vs_improved_summary.csv"
    guard([out], overwrite)
    o = root / OUT
    schemas = json.loads((o / "schema_by_file.json").read_text(encoding="utf-8"))["files"]
    rd = lambda n: list(csv.DictReader((o / n).open(encoding="utf-8")))  # noqa: E731
    labels, summ, dups, tsq, match = (rd("label_distribution_by_dataset.csv"), rd("numeric_feature_summary.csv"),
                                      rd("duplicates_by_file.csv"), rd("timestamp_quality.csv"),
                                      rd("row_matching_feasibility.csv"))
    rows = []

    def add(ds, metric, orig, imp, evidence, note=""):
        rows.append({"dataset_family": ds, "metric": metric, "original": orig, "improved": imp,
                     "evidence": evidence, "note": note})

    for ds in ("CIC-IDS-2017", "CSE-CIC-IDS-2018"):
        sc = {v: [s for s in schemas if s["dataset_family"] == ds and s["variant"] == v] for v in ("original", "improved")}
        add(ds, "files", len(sc["original"]), len(sc["improved"]), "schema_by_file.json")
        add(ds, "rows (all)", sum(s["n_rows"] for s in sc["original"]), sum(s["n_rows"] for s in sc["improved"]),
            "schema_by_file.json")
        lab = {v: [r for r in labels if r["dataset_family"] == ds and r["variant"] == v] for v in ("original", "improved")}
        art = {"", "Label"}
        nflow = {v: sum(int(r["count"]) for r in lab[v] if r["label"] not in art) for v in lab}
        add(ds, "flows (excluding empty / header rows)", nflow["original"], nflow["improved"], "label_distribution_by_dataset.csv")
        ben = {v: sum(int(r["count"]) for r in lab[v] if r["label"].upper() == "BENIGN") for v in lab}
        att = {v: sum(int(r["count"]) for r in lab[v] if r["label"].endswith(" - Attempted")) for v in lab}
        add(ds, "benign share of flows", round(ben["original"] / nflow["original"], 6),
            round(ben["improved"] / nflow["improved"], 6), "label_distribution_by_dataset.csv")
        add(ds, "'Attempted' flows", att["original"], att["improved"], "label_distribution_by_dataset.csv",
            "class introduced by CNS2022")
        add(ds, "distinct (label, category) pairs", len(lab["original"]), len(lab["improved"]), "label_distribution_by_dataset.csv")
        add(ds, "columns", "; ".join(sorted({str(s["n_columns"]) for s in sc["original"]})),
            "; ".join(sorted({str(s["n_columns"]) for s in sc["improved"]})), "schema_by_file.json")
        tsf = {v: sorted({max(s["timestamp_format_coverage"], key=s["timestamp_format_coverage"].get)
                          for s in sc[v] if s["timestamp_format_coverage"]}) for v in sc}
        add(ds, "timestamp format(s)", " | ".join(tsf["original"]), " | ".join(tsf["improved"]), "schema_by_file.json",
            "original: local time, no timezone; improved: UTC (DOCUMENTED)")
        for v_name, key in (("non-finite rate values (Flow Bytes/s)", "Flow Bytes/s"),):
            vals = {v: next((r for r in summ if r["scope"] == "dataset" and r["dataset_family"] == ds
                             and r["variant"] == v and r["column"] == key), None) for v in ("original", "improved")}
            add(ds, v_name, *(int(float(x["n_pos_inf"]) + float(x["n_neg_inf"]) + float(x["n_nan"])) if x else "" for x in
                              (vals["original"], vals["improved"])), "numeric_feature_summary.csv")
        neg = {v: sum(int(float(r["n_negative"])) for r in summ if r["scope"] == "dataset" and r["dataset_family"] == ds
                      and r["variant"] == v and r["semantics"] == "nonnegative") for v in ("original", "improved")}
        add(ds, "negative values in non-negative columns (cells)", neg["original"], neg["improved"],
            "numeric_feature_summary.csv", "improved negatives are int16 header-length overflow (see findings EXPORT_OVERFLOW)")
        const = {v: [r["column"] for r in summ if r["scope"] == "dataset" and r["dataset_family"] == ds
                     and r["variant"] == v and r["is_constant"] == "True"] for v in ("original", "improved")}
        add(ds, "constant columns", "; ".join(const["original"]) or "none", "; ".join(const["improved"]) or "none",
            "numeric_feature_summary.csv")
        d = {v: next((r for r in dups if r["scope"] == "dataset" and r["dataset_family"] == ds and r["variant"] == v), None)
             for v in ("original", "improved")}
        for k, label in (("n_data_rows", "data rows (excl. empty and embedded header rows)"),
                         ("n_exact_duplicate_rows_excl_empty", "exact duplicate rows (data rows; copies beyond the first)"),
                         ("n_feature_duplicate_rows", "feature-identical rows (data rows; copies beyond the first)"),
                         ("n_rows_in_label_conflict_groups", "rows in label-conflict groups"),
                         ("n_rows_in_binary_conflict_groups", "rows in benign/non-benign conflict groups")):
            add(ds, label, d["original"][k] if d["original"] else "", d["improved"][k] if d["improved"] else "",
                "duplicates_by_file.csv")
        share = {v: round(int(d[v]["n_feature_duplicate_rows"]) / int(d[v]["n_data_rows"]), 6) if d[v] else ""
                 for v in ("original", "improved")}
        add(ds, "feature-identical share of data rows", share["original"], share["improved"], "duplicates_by_file.csv")
        sub = {v: [t for t in tsq if t["dataset_family"] == ds and t["variant"] == v] for v in ("original", "improved")}
        add(ds, "timestamp min .. max (as parsed)", f"{min(t['min_ts'] for t in sub['original'])} .. {max(t['max_ts'] for t in sub['original'])}",
            f"{min(t['min_ts'] for t in sub['improved'])} .. {max(t['max_ts'] for t in sub['improved'])}", "timestamp_quality.csv",
            "original clock is local, 12-hour without AM/PM (both datasets); 2018 original also has a few 1970 epoch-like values; not directly comparable")
        m = [r for r in match if r["dataset_family"] == ds]
        add(ds, "row-level match: day pairs defensible", "", f"{sum(r['defensible_for_row_level'] == 'True' for r in m)}/{len(m)}",
            "row_matching_feasibility.csv", f"criteria: unique >= {MIN_UNIQUE_COVERAGE}, ambiguous <= {MAX_AMBIGUOUS}")
        offs = sorted({r["best_offset_hours_added_to_improved_utc"] for r in m if r["original_has_5tuple"] == "True"})
        add(ds, "timezone offset of original clock (5-tuple days)", ", ".join(offs), "UTC (DOCUMENTED)", "row_matching_feasibility.csv")
    write_csv(out, rows, ["dataset_family", "metric", "original", "improved", "evidence", "note"])
    log.info("summary: %d rows", len(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/phase4_compare.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("families", "features", "matching", "summary"):
        s = sub.add_parser(name)
        s.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    t0 = time.perf_counter()
    try:
        if args.cmd == "families":
            rc = cmd_families(root, args.overwrite)
        elif args.cmd == "features":
            rc = cmd_features(root, args.overwrite)
        elif args.cmd == "summary":
            rc = cmd_summary(root, args.overwrite)
        else:
            rc = cmd_matching(root, load_config(), args.overwrite)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
