"""Compile audit findings from Phase 2-6 outputs (read-only; nothing is repaired or dropped).

Subcommands (run from the project root)
---------------------------------------
identical    Exact check of column pairs whose dataset-scope summary statistics are identical
             (candidates from numeric_feature_summary.csv): rows where the two differ.
phase3       missingness_by_file.csv, findings.csv (integrity), integrity_summary.json
phase6       leakage_findings.csv

Every finding row carries: scope, detection rule + threshold, count, denominator, severity with
rationale, evidence file, proposed action, action type, and evidence status.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import (  # noqa: E402
    PROJECT_ROOT, column_role, discover_data_files, duckdb_connect, load_config, qident,
)
from src.audit.integrity import FileView, group_by_variant, guard, improved_names, write_csv  # noqa: E402
from src.audit.inventory import now_utc, setup_logging  # noqa: E402

TOOL = "src/audit/report.py"
OUT = Path("results/audit")
log = logging.getLogger("inventory")
FINDING_FIELDS = ["finding_id", "category", "dataset_family", "variant", "scope", "column", "rule", "count",
                  "denominator", "rate", "severity", "rationale", "evidence", "proposed_action", "action_type",
                  "evidence_status"]


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def num(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


class Findings:
    def __init__(self):
        self.rows: list[dict] = []
        self.n = defaultdict(int)

    def add(self, category: str, **kw):
        self.n[category] += 1
        cnt, den = kw.get("count"), kw.get("denominator")
        rate = round(num(cnt) / num(den), 8) if den not in (None, "", 0, "0") and num(den) else ""
        self.rows.append({"finding_id": f"{category}-{self.n[category]:03d}", "category": category, "rate": rate,
                          "evidence_status": kw.pop("evidence_status", "VERIFIED"), **kw})


# --------------------------------------------------------------------------- identical columns
def cmd_identical(root: Path, cfg: dict, overwrite: bool) -> int:
    out = root / OUT / "identical_columns.csv"
    guard([out], overwrite)
    summ = [r for r in read_csv(root / OUT / "numeric_feature_summary.csv") if r["scope"] == "dataset"]
    keys = ["n_numeric", "n_zero", "n_negative", "min", "max", "mean", "std", "q01", "q25", "q50", "q75", "q99"]
    files = discover_data_files(cfg, root)
    imp = improved_names(files)
    rows = []
    for (fam, var), group in group_by_variant(files).items():
        sig = defaultdict(list)
        for r in summ:
            if r["dataset_family"] == fam and r["variant"] == var and num(r["n_numeric"]) > 0:
                sig[tuple(r[k] for k in keys)].append(r["column"])
        cands = [(a, b) for cols in sig.values() if len(cols) > 1 for i, a in enumerate(cols) for b in cols[i + 1:]]
        if not cands:
            continue
        views = [FileView(f, imp, cfg) for f in group]
        parts = []
        need = sorted({c for p in cands for c in p})
        for v in views:
            sel = [f"TRY_CAST({v.col(c)} AS DOUBLE) AS {qident(c)}" for c in need if v.col(c)]
            parts.append(f"SELECT {', '.join(sel)} FROM {v.src}")
        union = " UNION ALL BY NAME ".join(f"({p})" for p in parts)
        aggs = [f"count_if({qident(a)} IS DISTINCT FROM {qident(b)}) AS d_{i}" for i, (a, b) in enumerate(cands)]
        con = duckdb_connect(cfg)
        res = con.execute(f"SELECT count(*), {', '.join(aggs)} FROM ({union})").fetchone()
        con.close()
        for i, (a, b) in enumerate(cands):
            rows.append({"dataset_family": fam, "variant": var, "column_a": a, "column_b": b, "n_rows": res[0],
                         "n_rows_differing": res[i + 1], "identical": res[i + 1] == 0,
                         "method": "candidate from identical summary statistics, verified row by row (full scan)"})
        log.info("identical: %s/%s %d candidate pairs", fam, var, len(cands))
    write_csv(out, rows, ["dataset_family", "variant", "column_a", "column_b", "n_rows", "n_rows_differing",
                          "identical", "method"])
    return 0


# --------------------------------------------------------------------------- phase 3 findings
def cmd_phase3(root: Path, cfg: dict, overwrite: bool) -> int:
    o = root / OUT
    targets = [o / "missingness_by_file.csv", o / "findings.csv", o / "integrity_summary.json"]
    guard(targets, overwrite)
    schemas = json.loads((o / "schema_by_file.json").read_text(encoding="utf-8"))["files"]
    prof = read_csv(o / "column_profile_by_file.csv")
    summ = read_csv(o / "numeric_feature_summary.csv")
    rules = read_csv(o / "plausibility_by_file.csv")
    dups = read_csv(o / "duplicates_by_file.csv")
    tsq = read_csv(o / "timestamp_quality.csv")
    lw = read_csv(o / "label_window_consistency.csv")
    labels = read_csv(o / "label_distribution_by_dataset.csv")
    enc = read_csv(root / "data/manifests/encoding_check.csv")
    ident = read_csv(o / "identical_columns.csv") if (o / "identical_columns.csv").exists() else []
    lvr = read_csv(o / "label_vs_labelling_rules.csv")
    # embedded header rows per file (Label == 'Label'): explains timestamp parse failures in 2018 originals
    hdr_rows = {r["file"]: int(r["count"]) for r in read_csv(o / "label_distribution_by_file.csv")
                if r["label"] == "Label"}

    # missingness_by_file.csv
    miss = []
    for p in prof:
        nn = int(p["n_rows"])
        miss.append({"dataset_family": p["dataset_family"], "variant": p["variant"], "file": p["file"],
                     "column": p["name_exact"], "role": p["role"], "inferred_type": p["inferred_type"],
                     "n_rows": nn, "n_null_or_empty": p["n_null_or_empty"],
                     "share_null_or_empty": round(int(p["n_null_or_empty"]) / nn, 8) if nn else "",
                     "n_blank_whitespace": p["n_blank_whitespace"], "n_untrimmed": p["n_untrimmed"],
                     "n_special_tokens_inf_nan": p["n_special_tokens"],
                     "n_nonnumeric_text": p["n_nonnumeric_text"] if p["inferred_type"] in ("integer", "float") else ""})
    write_csv(o / "missingness_by_file.csv", miss)

    F = Findings()
    # --- encoding / format ------------------------------------------------------------------
    for e in enc:
        fam_var = next(((s["dataset_family"], s["variant"]) for s in schemas if s["relpath"] == e["relpath"]), ("", ""))
        if e["utf8_valid"] != "True":
            F.add("FORMAT", dataset_family=fam_var[0], variant=fam_var[1], scope=e["relpath"], column="Label",
                  rule="file is not valid UTF-8 (incremental decoder)", count=e["n_non_ascii_bytes"],
                  denominator=e["size_bytes"], severity="low",
                  rationale="0x96 (cp1252 en dash) in web-attack labels; naive UTF-8 readers fail or substitute characters",
                  evidence="data/manifests/encoding_check.csv", proposed_action="read as cp1252 (as the authors' code does); keep original bytes in label_bytes_hex",
                  action_type="automatic (read-time only)")
        if e["line_ending"] == "mixed":
            F.add("FORMAT", dataset_family=fam_var[0], variant=fam_var[1], scope=e["relpath"], column="",
                  rule="mixed CRLF and LF line terminators", count=e["n_crlf"],
                  denominator=int(e["n_crlf"]) + int(e["n_bare_lf"]), severity="high",
                  rationale="DuckDB 1.5.6 silently dropped the CRLF section (all 576,191 DDoS-LOIC-HTTP rows) when one terminator was forced; caught by the newline cross-check",
                  evidence="data/manifests/encoding_check.csv; data/manifests/encoding_transcode_manifest.csv",
                  proposed_action="normalise CRLF->LF in a read cache; always cross-check row counts against newline counts",
                  action_type="automatic (read-time only)")
    # --- row-count structure -------------------------------------------------------------------
    for s in schemas:
        if s["variant"] == "original" and s["dataset_family"] == "CSE-CIC-IDS-2018" and s["n_rows"] == 1048575:
            F.add("COMPLETENESS", dataset_family=s["dataset_family"], variant=s["variant"], scope=s["relpath"],
                  column="", rule="data rows == 1,048,575 (Excel row limit 2^20 minus header)", count=s["n_rows"],
                  denominator="", severity="high",
                  rationale="row count equals the Excel sheet limit exactly; file content matches the official S3 object, so the cap is in the published release. The CNS2022 paper reports the published 2018 CSVs are ~25% of the full flow set. Days are truncated, so the originals cannot support whole-day temporal analysis",
                  evidence="results/audit/schema_by_file.json; data/manifests/original_2018_s3_etag_check.csv",
                  proposed_action="do not use original 2018 files for temporal modelling; use them only for distribution-level comparison",
                  action_type="requires review", evidence_status="VERIFIED (count, S3 identity); DOCUMENTED (25% subset)")
    for lab in labels:
        if lab["label"] == "" and int(lab["count"]) > 0:
            F.add("MISSING", dataset_family=lab["dataset_family"], variant=lab["variant"], scope="dataset",
                  column="all", rule="rows where every field is empty", count=lab["count"],
                  denominator=lab["rows_in_dataset"], severity="high",
                  rationale="contiguous block at the end of the original Thursday-Morning-WebAttacks file (lines 170,368-458,969); not traffic; inflates NaN counts and duplicate counts if read naively",
                  evidence="results/audit/label_distribution_by_dataset.csv; independent grep count = 288,602",
                  proposed_action="exclude with logged count in any future preprocessing of the original release",
                  action_type="requires review")
        if lab["label"] == "Label":
            F.add("FORMAT", dataset_family=lab["dataset_family"], variant=lab["variant"], scope="dataset",
                  column="all", rule="data row equal to the header (Label == 'Label')", count=lab["count"],
                  denominator=lab["rows_in_dataset"], severity="medium",
                  rationale="repeated header lines inside data files; numeric parsing fails on these rows",
                  evidence="results/audit/label_distribution_by_dataset.csv", proposed_action="exclude with logged count in preprocessing of the original release",
                  action_type="requires review")
    # --- missing / non-finite / negative -------------------------------------------------------
    for r in summ:
        if r["scope"] != "dataset":
            continue
        nonfin = int(num(r["n_pos_inf"]) + num(r["n_neg_inf"]) + num(r["n_nan"]))
        if nonfin:
            F.add("NONFINITE", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column=r["column"], rule="value parses to +inf, -inf or NaN", count=nonfin, denominator=r["n_rows"],
                  severity="medium", rationale="rate features divide by zero duration; models and scalers break on non-finite values",
                  evidence="results/audit/numeric_feature_summary.csv",
                  proposed_action="train-fitted rule (e.g., cap or indicator) decided in Phase 8 preprocessing; never silently drop",
                  action_type="requires review")
        overflow = r["variant"] == "improved" and r["column"].endswith("Header Length")  # reported as EXPORT_OVERFLOW
        if r["semantics"] == "nonnegative" and num(r["n_negative"]) > 0 and not overflow:
            F.add("INVALID_VALUE", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column=r["column"], rule="negative value in a column that cannot be negative (configs/data_audit.yaml semantics)",
                  count=r["n_negative"], denominator=r["n_numeric"], severity="high",
                  rationale="counts, lengths, durations, IATs and rates are non-negative by definition; negatives indicate extractor errors or clock issues",
                  evidence="results/audit/numeric_feature_summary.csv", proposed_action="flag; investigate per file; handle in preprocessing with a logged rule",
                  action_type="requires review")
        if r["semantics"] == "sentinel_minus_one" and num(r["n_minus_one"]) > 0:
            F.add("SENTINEL", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column=r["column"], rule="value == -1 (documented 'not observed' sentinel)", count=r["n_minus_one"],
                  denominator=r["n_numeric"], severity="low",
                  rationale="-1 is an encoding, not a magnitude; treating it as numeric distorts scaling",
                  evidence="results/audit/numeric_feature_summary.csv", proposed_action="encode as missing-indicator in preprocessing",
                  action_type="deferred")
        if r["is_constant"] == "True":
            F.add("CONSTANT", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column=r["column"], rule="min == max over all finite values (full scan)", count=r["n_numeric"],
                  denominator=r["n_rows"], severity="low", rationale="carries no information in this release",
                  evidence="results/audit/numeric_feature_summary.csv", proposed_action="exclude from model inputs (train-split check)",
                  action_type="deferred")
    # --- export-type overflow: the authors' labelling code casts these columns with astype('int16') -------
    int16_cols = ["Fwd Header Length", "Bwd Header Length", "ICMP Code", "ICMP Type"]  # DOCUMENTED (notebooks)
    ds_rows = {(r["dataset_family"], r["variant"], r["column"]): r for r in summ if r["scope"] == "dataset"}
    for (fam, var, col), r in ds_rows.items():
        if var != "improved" or col not in int16_cols:
            continue
        lo, hi = num(r["min"]), num(r["max"])
        orig = ds_rows.get((fam, "original", col))
        if lo >= -32768 and hi <= 32767 and num(r["n_negative"]) > 0 and col.endswith("Header Length"):
            F.add("EXPORT_OVERFLOW", dataset_family=fam, variant=var, scope="dataset", column=col,
                  rule="values confined to the int16 range [-32768, 32767] with negatives present, while the original release exceeds it"
                       + (f" (original max {orig['max']})" if orig else ""),
                  count=r["n_negative"], denominator=r["n_numeric"], severity="high",
                  rationale="the authors' labelling notebooks cast this column with astype('int16') before export (DOCUMENTED); "
                            "header lengths > 32,767 bytes wrapped around. Negatives are a LOWER BOUND: larger overflows wrap to "
                            "plausible positive values and cannot be detected",
                  evidence="results/audit/numeric_feature_summary.csv; references/CNS2022_Code/Labelling/*fixed*.ipynb (int16_columns)",
                  proposed_action="exclude Fwd/Bwd Header Length from model inputs, or recompute from PCAP; report to dataset authors",
                  action_type="requires review", evidence_status="VERIFIED (range); DOCUMENTED (cast)")
    for col in ("FWD Init Win Bytes", "Bwd Init Win Bytes"):
        for fam in ("CIC-IDS-2017", "CSE-CIC-IDS-2018"):
            orow, irow = ds_rows.get((fam, "original", col)), ds_rows.get((fam, "improved", col))
            if orow and irow and num(orow["n_minus_one"]) > 0 and num(irow["n_minus_one"]) == 0:
                F.add("SEMANTICS_CHANGE", dataset_family=fam, variant="improved", scope="dataset", column=col,
                      rule="'-1' (not observed) present in original, absent in improved; share of 0 rises",
                      count=irow["n_zero"], denominator=irow["n_numeric"], severity="medium",
                      rationale=f"original has {orow['n_minus_one']} rows = -1 and {orow['n_zero']} zeros; improved has no -1 and "
                                f"{irow['n_zero']} zeros. HYPOTHESIS: the fork encodes 'not observed' as 0 (UNRESOLVED until the fork source is checked)",
                      evidence="results/audit/numeric_feature_summary.csv",
                      proposed_action="do not compare raw values across releases; treat 0 as a possible sentinel",
                      action_type="requires review", evidence_status="VERIFIED (counts); HYPOTHESIS (cause)")

    rule_cfg = {x["id"]: x for x in cfg["plausibility_rules"]}  # current severity/rationale from config
    for r in rules:
        if r["scope"] == "dataset" and r["status"] == "evaluated" and int(num(r["n_violations"])) > 0:
            rc = rule_cfg.get(r["rule_id"], {})
            F.add("PLAUSIBILITY", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column="", rule=f"{r['rule_id']}: {rc.get('expr', '')} (configs/data_audit.yaml)",
                  count=r["n_violations"], denominator=r["n_evaluable"],
                  severity=rc.get("severity", r["severity"]), rationale=rc.get("rationale", r["note"]),
                  evidence="results/audit/plausibility_by_file.csv", proposed_action="investigate per file before any modelling use",
                  action_type="requires review")
    constant = {(r["dataset_family"], r["variant"], r["column"]) for r in summ
                if r["scope"] == "dataset" and r["is_constant"] == "True"}
    for r in ident:
        both_constant = {(r["dataset_family"], r["variant"], r["column_a"]),
                         (r["dataset_family"], r["variant"], r["column_b"])} <= constant
        if r["identical"] == "True" and not both_constant:  # constant pairs are already CONSTANT findings
            F.add("DUPLICATE_COLUMN", dataset_family=r["dataset_family"], variant=r["variant"], scope="dataset",
                  column=f"{r['column_a']} == {r['column_b']}", rule="row-by-row identical (full scan)", count=r["n_rows"],
                  denominator=r["n_rows"], severity="low", rationale="redundant feature; inflates apparent dimensionality",
                  evidence="results/audit/identical_columns.csv", proposed_action="keep one of each pair in model inputs",
                  action_type="deferred")
    # --- duplicates -----------------------------------------------------------------------------
    for d in dups:
        if d["scope"] != "dataset":
            continue
        F.add("DUPLICATES", dataset_family=d["dataset_family"], variant=d["variant"], scope="dataset", column="",
              rule="exact duplicate rows (all common columns except id; empty and embedded header rows excluded)",
              count=d["n_exact_duplicate_rows_excl_empty"], denominator=d["n_data_rows"],
              severity="medium", rationale="identical records across partitions leak; within a partition they reweight training",
              evidence="results/audit/duplicates_by_file.csv", proposed_action="split-aware de-duplication policy decided in Phase 6/8",
              action_type="requires review")
        F.add("DUPLICATES", dataset_family=d["dataset_family"], variant=d["variant"], scope="dataset", column="",
              rule="feature-identical rows (no ids/timestamp/labels; empty and embedded header rows excluded)",
              count=d["n_feature_duplicate_rows"], denominator=d["n_data_rows"], severity="medium", rationale="the model sees only features; feature duplicates are what can leak across splits",
              evidence="results/audit/duplicates_by_file.csv", proposed_action="measure across candidate splits (Phase 6)",
              action_type="requires review")
        if int(num(d["n_rows_in_label_conflict_groups"])):
            F.add("LABEL_CONFLICT", dataset_family=d["dataset_family"], variant=d["variant"], scope="dataset", column="Label",
                  rule="feature-identical rows carrying different labels", count=d["n_rows_in_label_conflict_groups"],
                  denominator=d["n_data_rows"], severity="high",
                  rationale="no classifier can separate them; caps achievable accuracy (cf. CNS2022 Table IV). Binary benign/non-benign conflicts: "
                            + str(d["n_rows_in_binary_conflict_groups"]),
                  evidence="results/audit/duplicates_by_file.csv", proposed_action="report as irreducible error; decide label policy for Attempted",
                  action_type="requires review")
    # --- timestamps -----------------------------------------------------------------------------
    for t in tsq:
        sc = dict(dataset_family=t["dataset_family"], variant=t["variant"], scope=t["file"])
        if int(num(t["n_parse_failures"])):
            F.add("TIMESTAMP", **sc, column="Timestamp", rule="non-empty timestamp text that matches no known format",
                  count=t["n_parse_failures"], denominator=t["n_timestamp_text_nonnull"], severity="medium",
                  rationale="row cannot be placed in time" + (
                      f"; {hdr_rows[t['file']]} of these rows are embedded header rows (Label == 'Label', FORMAT-003)"
                      if t["file"] in hdr_rows else ""),
                  evidence="results/audit/timestamp_quality.csv",
                  proposed_action="exclude from temporal analysis with logged count", action_type="requires review")
        if t["n_date_mismatch_filename"] not in ("", "None") and int(num(t["n_date_mismatch_filename"])):
            F.add("TIMESTAMP", **sc, column="Timestamp", rule="calendar date != date in file name",
                  count=t["n_date_mismatch_filename"], denominator=t["n_parsed"], severity="medium",
                  rationale="flows outside the nominal capture day (timezone shift, clock error or carry-over traffic)",
                  evidence="results/audit/timestamp_quality.csv", proposed_action="inspect; never let windows cross day files",
                  action_type="requires review")
        if t["n_weekday_mismatch_filename"] not in ("", "None") and int(num(t["n_weekday_mismatch_filename"])):
            F.add("TIMESTAMP", **sc, column="Timestamp", rule="weekday != weekday in file name",
                  count=t["n_weekday_mismatch_filename"], denominator=t["n_parsed"], severity="medium",
                  rationale="flows outside the nominal capture day", evidence="results/audit/timestamp_quality.csv",
                  proposed_action="inspect", action_type="requires review")
        if t["variant"] == "original" and int(num(t["n_with_subsecond"])) == 0 and int(num(t["n_parsed"])):
            F.add("TIMESTAMP", **sc, column="Timestamp", rule="no sub-second precision (resolution = format of Phase 2 coverage)",
                  count=t["n_parsed"], denominator=t["n_parsed"], severity="high" if t["dataset_family"] == "CIC-IDS-2017" else "medium",
                  rationale="minute/second resolution cannot order flows inside 2 s windows; original files carry no timezone",
                  evidence="results/audit/timestamp_quality.csv; results/audit/schema_by_file.json",
                  proposed_action="use the improved release (UTC, microseconds) for temporal work", action_type="requires review")
        if int(num(t["n_gaps_gt_300s"])):
            F.add("TIMESTAMP", **sc, column="Timestamp", rule="gap > 300 s between consecutive flow starts (sorted)",
                  count=t["n_gaps_gt_300s"], denominator=t["n_parsed"], severity="low",
                  rationale=f"possible capture interruption; max gap {t['max_gap_sorted_s']} s",
                  evidence="results/audit/timestamp_quality.csv", proposed_action="treat as censoring boundary in window construction",
                  action_type="requires review")
        if t["n_id_present"] not in ("", "0") and int(num(t["n_id_ne_row_order"])):
            F.add("ID_ORDER", **sc, column="id", rule="id != physical row number", count=t["n_id_ne_row_order"],
                  denominator=t["n_id_present"], severity="medium", rationale="id would not be a pure row index",
                  evidence="results/audit/timestamp_quality.csv", proposed_action="investigate", action_type="requires review")
    for t in tsq:
        if t["variant"] == "improved" and int(num(t["n_backward_steps_gt_60s"])):
            F.add("ORDER", dataset_family=t["dataset_family"], variant=t["variant"], scope=t["file"], column="Timestamp",
                  rule="file order goes back in time by > 60 s", count=t["n_backward_steps_gt_60s"],
                  denominator=t["n_parsed"], severity="medium",
                  rationale="rows are not chronological (2018: per-host CSVs concatenated in glob order, DOCUMENTED in labelling code); any sequence must be sorted by Timestamp",
                  evidence="results/audit/timestamp_quality.csv", proposed_action="always sort by Timestamp within file; never use row order",
                  action_type="automatic (analysis rule)")
    for r in lw:
        if int(num(r["n_outside"])):
            F.add("LABEL_WINDOW", dataset_family=r["dataset_family"], variant="improved", scope=r["file"], column="Label",
                  rule="attack-labelled flow whose Timestamp lies outside every documented rule window for that label+category",
                  count=r["n_outside"], denominator=r["n_flows"], severity="high",
                  rationale=f"label {r['label']} / category {r['attempted_category']} not reproducible from the published labelling windows",
                  evidence="results/audit/label_window_consistency.csv", proposed_action="investigate before using this class",
                  action_type="requires review")
    for r in lvr:
        if r["status"] == "data_label_without_rule":
            F.add("LABEL_RULE", dataset_family=r["dataset_family"], variant="improved", scope=r["file"], column="Label",
                  rule="label present in data without a documented labelling rule", count=r["n_flows_in_data"],
                  denominator="", severity="high", rationale="provenance of the label unknown",
                  evidence="results/audit/label_vs_labelling_rules.csv", proposed_action="investigate", action_type="requires review")
    # --- class imbalance ------------------------------------------------------------------------
    for lab in labels:
        if lab["variant"] == "improved" and lab["label"].upper() != "BENIGN" and int(lab["count"]) < 100:
            F.add("IMBALANCE", dataset_family=lab["dataset_family"], variant="improved", scope="dataset", column="Label",
                  rule="class (label, attempted category) with < 100 flows", count=lab["count"],
                  denominator=lab["rows_in_dataset"], severity="medium",
                  rationale=f"'{lab['label']}' (cat {lab['attempted_category']}) too small for per-class metrics with useful CIs",
                  evidence="results/audit/label_distribution_by_dataset.csv",
                  proposed_action="merge into family-level targets or report as descriptive only", action_type="requires review")
    write_csv(o / "findings.csv", F.rows, FINDING_FIELDS)

    summary = {"generated_at_utc": now_utc(), "tool": TOOL, "n_findings": len(F.rows),
               "findings_by_category": dict(F.n),
               "findings_by_severity": {s: sum(1 for r in F.rows if r["severity"] == s) for s in ("critical", "high", "medium", "low")},
               "datasets": {}}
    for s in schemas:
        k = f"{s['dataset_family']}|{s['variant']}"
        e = summary["datasets"].setdefault(k, {"n_files": 0, "n_rows": 0, "read_modes": set(), "lines_not_read": 0})
        e["n_files"] += 1
        e["n_rows"] += s["n_rows"]
        e["read_modes"].add(s["read_mode"])
        e["lines_not_read"] += (s["newline_check"] or {}).get("lines_not_read_as_rows", 0)
    for d in dups:
        if d["scope"] == "dataset":
            summary["datasets"][f"{d['dataset_family']}|{d['variant']}"]["duplicates"] = {
                k: d[k] for k in ("n_all_empty_rows", "n_embedded_header_rows", "n_data_rows",
                                  "n_exact_duplicate_rows_excl_empty", "n_feature_duplicate_rows",
                                  "n_rows_in_label_conflict_groups", "n_rows_in_binary_conflict_groups",
                                  "n_rows_in_cross_file_duplicate_groups")}
    for v in summary["datasets"].values():
        v["read_modes"] = sorted(v["read_modes"])
    (o / "integrity_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    log.info("phase3: %d findings %s", len(F.rows), dict(F.n))
    return 0


# --------------------------------------------------------------------------- phase 6 leakage
def label_defining_columns(root: Path) -> dict[str, set[str]]:
    """Columns referenced by the documented labelling rules (payload filter, extra filters, IP/port lists)."""
    out = defaultdict(set)
    for r in read_csv(root / OUT / "attack_windows_documented.csv"):
        ds = r["dataset"]
        out[ds].add("Timestamp")
        if r["src_ips"] not in ("null", ""):
            out[ds].add("Src IP")
        if r["dst_ips"] not in ("null", ""):
            out[ds].add("Dst IP")
        if r["src_ports"] not in ("null", "", "n/a"):
            out[ds].add("Src Port")
        if r["dst_ports"] not in ("null", ""):
            out[ds].add("Dst Port")
        if r["payload_filter"] == "True":
            out[ds].add("Total Length of Fwd Packet")
        out[ds].update(re.findall(r'\["([^"]+)"\]', r["additional_filters"]))
    return out


def cmd_phase6(root: Path, cfg: dict, overwrite: bool) -> int:
    o = root / OUT
    out = o / "leakage_findings.csv"
    guard([out], overwrite)
    sep = read_csv(o / "feature_separability.csv")
    lab_cols = label_defining_columns(root)
    splits = read_csv(o / "split_duplicate_leakage.csv") if (o / "split_duplicate_leakage.csv").exists() else []
    rows = []

    def add(**kw):
        rows.append({"leak_id": f"LEAK-{len(rows) + 1:03d}", **kw})

    for name, why in [("id", "row index written at export after dropping NaN/Infinity rows; encodes file order (VERIFIED id == row number); 2018 order = per-host CSV concatenation order"),
                      ("Flow ID", "concatenation of IPs, ports, protocol; identity, not behaviour"),
                      ("Src IP", "host identity; attackers are fixed hosts in a testbed; used by the labelling rules"),
                      ("Dst IP", "host identity; victims are fixed hosts; used by the labelling rules"),
                      ("Src Port", "ephemeral client port; specific values are used by the labelling rules (2017)"),
                      ("Timestamp", "attack windows are time-defined by the labelling rules; absolute time identifies the scenario"),
                      ("Label", "target"), ("Attempted Category", "target-derived (sub-label)"),
                      ("file / day name", "scenario identity: in both datasets each day hosts a distinct attack set")]:
        add(dataset_family="both", variant="improved", column=name, category="never_a_model_input",
            evidence=why, metric="", value="", severity="critical" if name in ("Label", "Attempted Category", "id") else "high",
            evidence_status="VERIFIED" if name in ("id",) else "DOCUMENTED",
            action="exclude from features; Timestamp may only order/aggregate windows")
    for ds, cols in lab_cols.items():
        for c in sorted(cols - {"Timestamp", "Src IP", "Dst IP", "Src Port"}):
            add(dataset_family=ds, variant="improved", column=c, category="label_defining_feature",
                evidence="referenced by the documented labelling rules (attack_windows_documented.csv): inside attack windows, the label/Attempted category is a deterministic function of this column",
                metric="", value="", severity="medium", evidence_status="DOCUMENTED",
                action="allowed as input, but report results with and without it; distinguishing 'X' from 'X - Attempted' via this column is learning the labelling rule")
    for r in sep:
        v = r["ovl_benign_vs_attack"]
        if v in ("", "None"):
            continue
        ovl = float(v)
        sev = "high" if ovl < 0.05 else "medium" if ovl < 0.2 else ""
        if r["feature"] in ("id", "hour_of_timestamp") or r["role"] == "context_review" or sev:
            add(dataset_family=r["dataset_family"], variant=r["variant"], column=r["feature"],
                category="single_feature_separability" if r["role"] != "context_review" else "context_feature_review",
                evidence="class-conditional histogram overlap (sign*log2 bins, full scan); low overlap = one feature nearly separates benign from attack",
                metric="OVL(benign, attack)", value=v, severity=sev or "info", evidence_status="VERIFIED",
                action="shortcut/artefact candidate: ablate in Phase 8 and report per-day; never conclude 'learnable' from this feature alone")
    for s in splits:
        if s["share_seen_in_train"] not in ("", "None"):
            add(dataset_family=s["dataset_family"], variant="improved", column="(all features)",
                category="duplicate_leakage_across_split", metric=f"{s['protocol']}: share of {s['eval_partition']} rows whose exact feature vector occurs in train",
                value=s["share_seen_in_train"], severity="high" if float(s["share_seen_in_train"]) > 0.3 else "medium",
                evidence=f"attack rows seen in train: {s['share_attack_seen_in_train']}"
                         + (f"; test rows seen in train+val: {s['share_seen_in_train_or_val']}, attack rows: "
                            f"{s['share_attack_seen_in_train_or_val']}" if s.get("share_seen_in_train_or_val") else ""),
                evidence_status="VERIFIED",
                action=("diagnostic only: never primary evidence (configs/evaluation_protocol.yaml)"
                        if s["protocol"].startswith(("P0", "P1")) else
                        "report this overlap next to every result on this split; give the de-duplicated test score too"))
    write_csv(out, rows, ["leak_id", "dataset_family", "variant", "column", "category", "metric", "value", "severity",
                          "evidence", "evidence_status", "action"])
    log.info("phase6: %d leakage rows", len(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/report.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("identical", "phase3", "phase6"):
        s = sub.add_parser(name)
        s.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    cfg = load_config()
    t0 = time.perf_counter()
    try:
        rc = {"identical": cmd_identical, "phase3": cmd_phase3, "phase6": cmd_phase6}[args.cmd](root, cfg, args.overwrite)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
