"""Phase 2: schema and label audit (read-only; full scans with DuckDB).

For every CSV under the configured data dirs (configs/data_audit.yaml):

* exact header names read in Python; duplicate, whitespace and case issues;
* a full-scan column profile with every value read as text: non-null, blank, untrimmed,
  castable-to-DOUBLE, castable-to-BIGINT and special-token (inf/nan) counts -> inferred type;
* full-column timestamp format coverage (TRY_STRPTIME per candidate format);
* exact label strings and (Label, Attempted Category) counts from a full scan;
* rejected rows (DuckDB store_rejects) and a cross-check against the newline count measured
  during acquisition.

Then, from those results:

* label_vs_labelling_rules.csv: data labels vs the documented labelling rules (improved data);
* schema_diff_original_vs_improved.csv: column-level comparison per dataset family.

Usage (from the project root)
-----------------------------
    python -I src/audit/schema_labels.py scan [--only SUBSTRING] [--overwrite]
    python -I src/audit/schema_labels.py derive [--overwrite]
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

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import (  # noqa: E402
    MANUAL_OVERRIDES, PROJECT_ROOT, DataFile, column_role, columns_option, csv_source,
    discover_data_files, duckdb_connect, load_config, norm_name, qident, read_header, sql_str,
    token_key,
)
from src.audit.encoding import load_check, newline_option, readable_path  # noqa: E402
from src.audit.inventory import now_utc, setup_logging  # noqa: E402

TOOL = "src/audit/schema_labels.py"
OUT = Path("results/audit")
log = logging.getLogger("inventory")

PROFILE_FIELDS = [
    "dataset_family", "variant", "file", "position", "name_exact", "norm_name", "role",
    "inferred_type", "n_rows", "n_nonnull", "n_null_or_empty", "n_blank_whitespace", "n_untrimmed",
    "n_castable_double", "n_integer_literal", "n_special_tokens", "n_nonnumeric_text",
]
LABEL_FIELDS = [
    "dataset_family", "variant", "file", "label", "label_display", "label_bytes_hex",
    "attempted_category", "count", "rows_in_file", "proportion", "method",
]


# --------------------------------------------------------------------------- per-file scan
def label_display(s: str | None, source_encoding: str) -> tuple[str, str]:
    """(display text, hex of the ORIGINAL file bytes) for a label; hex only when non-ASCII."""
    if s is None:
        return "", ""
    if s.isascii():
        return s, ""
    return s, s.encode(source_encoding).hex()


def infer_type(c: dict) -> str:
    """Base type of a column: empty | integer | float | string.

    * string  : fewer than 99% of non-null values parse as numbers;
    * integer : every numeric value is an integer literal (regex ^[+-]?[0-9]+$);
    * float   : otherwise.
    A small number of non-numeric values (e.g. embedded header lines) does not change the base type;
    it is reported in ``n_nonnumeric_text``. DuckDB's TRY_CAST(... AS BIGINT) is NOT used for this,
    because it accepts and rounds decimal strings such as '12.5'.
    """
    nn = c["n_nonnull"]
    if nn == 0:
        return "empty"
    if c["n_castable_double"] < 0.99 * nn:
        return "string"
    return "integer" if c["n_integer_literal"] == c["n_castable_double"] else "float"


def read_newline_check(root: Path) -> dict[str, dict]:
    p = root / "data/manifests/acquisition_verification.csv"
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as fh:
        return {r["dest_relpath"]: r for r in csv.DictReader(fh)}


def scan_file(con, df: DataFile, cfg: dict, newline_info: dict | None) -> tuple[dict, list[dict]]:
    t0 = time.perf_counter()
    hdr = read_header(df.path)
    names = hdr["names"]
    colopt, used = columns_option(names)
    roles = [column_role(n, cfg) for n in names]
    label_idx = next((i for i, n in enumerate(names) if norm_name(n) == "label"), None)
    att_idx = next((i for i, n in enumerate(names) if norm_name(n) == "attemptedcategory"), None)
    ts_idx = next((i for i, n in enumerate(names) if norm_name(n) == "timestamp"), None)
    specials = ", ".join(sql_str(s) for s in cfg["special_numeric_tokens"])

    aggs = ["count(*) AS n_rows"]
    for i, u in enumerate(used):
        c = qident(u)
        aggs += [f"count({c}) AS nn_{i}", f"count_if(trim({c}) = '') AS bl_{i}",
                 f"count_if({c} <> trim({c})) AS ut_{i}",
                 f"count(TRY_CAST({c} AS DOUBLE)) AS db_{i}",
                 f"count_if(regexp_full_match(trim({c}), '[+-]?[0-9]+')) AS il_{i}",
                 f"count_if(lower(trim({c})) IN ({specials})) AS sp_{i}"]
    fmts = cfg["timestamp_formats"]
    if ts_idx is not None:
        tc = qident(used[ts_idx])
        aggs += [f"count(TRY_STRPTIME(trim({tc}), {sql_str(f)})) AS tsf_{k}" for k, f in enumerate(fmts)]
        aggs += [f"count_if(regexp_matches({tc}, '\\.[0-9]{{6}}$')) AS ts6",
                 f"count_if(regexp_matches({tc}, '\\.[0-9]{{1,5}}$')) AS tsshort",
                 f"count_if(NOT contains({tc}, '.')) AS tsnofrac"]

    # Strict read first: any malformed row raises. Only then fall back to ignore_errors, and
    # count what was skipped from the independent newline count (store_rejects is not used:
    # DuckDB 1.5.6 raised an INTERNAL error with it on malformed input, see schema_and_labels.md).
    read_path, enc = readable_path(df)
    colopt = colopt + ", " + newline_option(df)
    strict_error, mode = "", "strict"
    select = "SELECT " + ", ".join(aggs) + " FROM "
    try:
        cur = con.execute(select + csv_source(read_path, "utf-8", extra=colopt))
    except duckdb.InvalidInputException as exc:
        strict_error = str(exc).splitlines()[0]
        log.warning("  %s: strict read failed (%s); re-reading with ignore_errors", df.relpath, strict_error)
        mode = "ignore_errors"
        cur = con.execute(select + csv_source(read_path, "utf-8", extra=colopt + ", ignore_errors=true"))
    cols = [d[0] for d in cur.description]
    prof = dict(zip(cols, cur.fetchone()))
    n_rows = prof["n_rows"]
    columns, profile_rows = [], []
    for i, (name, u) in enumerate(zip(names, used)):
        c = {"position": i, "name_exact": name, "duckdb_name": u, "norm_name": norm_name(name),
             "role": roles[i], "n_rows": n_rows, "n_nonnull": prof[f"nn_{i}"],
             "n_null_or_empty": n_rows - prof[f"nn_{i}"], "n_blank_whitespace": prof[f"bl_{i}"],
             "n_untrimmed": prof[f"ut_{i}"], "n_castable_double": prof[f"db_{i}"],
             "n_integer_literal": prof[f"il_{i}"], "n_special_tokens": prof[f"sp_{i}"]}
        c["n_nonnumeric_text"] = c["n_nonnull"] - c["n_castable_double"]
        c["inferred_type"] = infer_type(c)
        columns.append(c)
        profile_rows.append({"dataset_family": df.dataset_family, "variant": df.variant,
                             "file": df.relpath, **{k: c[k] for k in PROFILE_FIELDS if k in c}})

    # labels (full scan, exact strings)
    labels = []
    if label_idx is not None:
        src = csv_source(read_path, "utf-8",
                         extra=colopt + (", ignore_errors=true" if mode == "ignore_errors" else ""))
        lab = qident(used[label_idx])
        att = qident(used[att_idx]) if att_idx is not None else "NULL"
        for label, attempted, n in con.execute(
                f"SELECT {lab}, {att}, count(*) FROM {src} GROUP BY ALL ORDER BY 3 DESC, 1").fetchall():
            disp, hexb = label_display(label, enc)
            labels.append({"dataset_family": df.dataset_family, "variant": df.variant,
                           "file": df.relpath, "label": label if label is not None else "",
                           "label_display": disp if label is not None else "<NULL/empty>",
                           "label_bytes_hex": hexb, "attempted_category": attempted or "",
                           "count": n, "rows_in_file": n_rows,
                           "proportion": n / n_rows if n_rows else "",
                           "method": f"full scan, DuckDB read_csv all_varchar ({mode}), source encoding={enc}"})
        n_label_rows = sum(r["count"] for r in labels)
        if n_label_rows != n_rows:
            log.error("  %s: label scan rows %d != profile rows %d", df.relpath, n_label_rows, n_rows)

    nl = None
    if newline_info:
        nlb = int(newline_info["n_newline_bytes"])
        expected = nlb - 1 if newline_info["ends_with_newline"] == "True" else nlb
        nl = {"n_newline_bytes": nlb, "ends_with_newline": newline_info["ends_with_newline"] == "True",
              "expected_data_lines": expected, "rows_read": n_rows,
              "lines_not_read_as_rows": expected - n_rows}
    dup_names = sorted({n for n in names if names.count(n) > 1})
    lower = defaultdict(list)
    for n in names:
        lower[n.strip().lower()].append(n)
    rec = {
        "dataset_family": df.dataset_family, "variant": df.variant, "relpath": df.relpath,
        "size_bytes": df.path.stat().st_size, "source_encoding": enc,
        "read_from_transcoded_cache": read_path != df.path, "read_mode": mode,
        "line_ending": load_check()[df.relpath]["line_ending"],
        "strict_read_error": strict_error,
        "header_encoding": hdr["header_encoding"], "header_has_bom": hdr["has_bom"],
        "n_columns": len(names), "header_names_exact": names,
        "duplicate_names": dup_names,
        "names_with_outer_whitespace": [n for n in names if n != n.strip()],
        "case_or_whitespace_collisions": [v for v in lower.values() if len(set(v)) > 1],
        "n_rows": n_rows, "newline_check": nl,
        "label_column": names[label_idx] if label_idx is not None else None,
        "attempted_column": names[att_idx] if att_idx is not None else None,
        "timestamp_column": names[ts_idx] if ts_idx is not None else None,
        "timestamp_format_coverage": {f: prof[f"tsf_{k}"] for k, f in enumerate(fmts)} if ts_idx is not None else {},
        "timestamp_fraction_digits": {"six": prof.get("ts6"), "one_to_five": prof.get("tsshort"),
                                      "none": prof.get("tsnofrac")} if ts_idx is not None else {},
        "n_distinct_label_attempted_pairs": len(labels),
        "columns": columns, "seconds": round(time.perf_counter() - t0, 2),
        "method": "DuckDB read_csv(all_varchar, explicit column names, store_rejects); full scan",
    }
    return rec, labels


# --------------------------------------------------------------------------- derived outputs
def schema_diff(schemas: list[dict]) -> list[dict]:
    rows = []
    by = defaultdict(list)
    for s in schemas:
        by[(s["dataset_family"], s["variant"])].append(s)
    for fam in sorted({s["dataset_family"] for s in schemas}):
        orig, imp = by.get((fam, "original"), []), by.get((fam, "improved"), [])
        if not orig or not imp:
            continue

        def collect(group):
            cols: dict[str, dict] = {}
            for s in group:
                seen = set()
                for c in s["columns"]:
                    n = c["name_exact"]
                    dup = n in seen
                    seen.add(n)
                    key = n + (" [duplicate]" if dup else "")
                    e = cols.setdefault(key, {"name": n, "dup": dup, "files": 0, "types": set(), "pos": c["position"]})
                    e["files"] += 1
                    e["types"].add(c["inferred_type"])
            return cols, len(group)

        ocols, on = collect(orig)
        icols, inn = collect(imp)
        ikey = {}
        for k, e in icols.items():
            ikey.setdefault(token_key(e["name"]), []).append(k)
        matched_i = set()
        for k, e in sorted(ocols.items(), key=lambda kv: kv[1]["pos"]):
            tk = token_key(e["name"])
            basis = ""
            target = None
            if e["dup"]:
                status, basis = "removed", "duplicate column name within original file"
            else:
                exact = [ik for ik in icols if icols[ik]["name"] == e["name"]]
                stripped = [ik for ik in icols if icols[ik]["name"].strip() == e["name"].strip()]
                cased = [ik for ik in icols if icols[ik]["name"].strip().lower() == e["name"].strip().lower()]
                if exact:
                    target, basis = exact[0], "identical name"
                elif stripped:
                    target, basis = stripped[0], "same name after stripping whitespace"
                elif cased:
                    target, basis = cased[0], "same name ignoring case/whitespace"
                elif len(ikey.get(tk, [])) == 1:
                    target, basis = ikey[tk][0], "token-normalised name match (abbreviation/word order)"
                elif tk in MANUAL_OVERRIDES and len(ikey.get(MANUAL_OVERRIDES[tk][0], [])) == 1:
                    target, basis = ikey[MANUAL_OVERRIDES[tk][0]][0], MANUAL_OVERRIDES[tk][1]
                status = ("unchanged" if basis == "identical name" else "renamed") if target else "removed"
                if target:
                    matched_i.add(target)
            it = icols[target] if target else None
            rows.append({
                "dataset_family": fam, "status": status, "original_name": e["name"],
                "original_files_present": f"{e['files']}/{on}",
                "improved_name": it["name"] if it else "",
                "improved_files_present": f"{it['files']}/{inn}" if it else "",
                "match_basis": basis,
                "original_inferred_types": ";".join(sorted(e["types"])),
                "improved_inferred_types": ";".join(sorted(it["types"])) if it else "",
                "type_changed": (sorted(e["types"]) != sorted(it["types"])) if it else "",
                "role": column_role(it["name"] if it else e["name"], load_config()),
            })
        for k, e in sorted(icols.items(), key=lambda kv: kv[1]["pos"]):
            if k not in matched_i:
                rows.append({
                    "dataset_family": fam, "status": "added", "original_name": "",
                    "original_files_present": "", "improved_name": e["name"],
                    "improved_files_present": f"{e['files']}/{inn}", "match_basis": "no original counterpart",
                    "original_inferred_types": "", "improved_inferred_types": ";".join(sorted(e["types"])),
                    "type_changed": "", "role": column_role(e["name"], load_config()),
                })
    return rows


def label_vs_rules(labels: list[dict], rules_path: Path) -> list[dict]:
    with rules_path.open(encoding="utf-8") as fh:
        rules = list(csv.DictReader(fh))
    rule_keys = defaultdict(list)
    for r in rules:
        rule_keys[(r["dataset"], r["file"], r["label"], str(r["attempted_category"]))].append(r["rule_order"])
    data = defaultdict(int)
    for l in labels:
        if l["variant"] == "improved":
            data[(l["dataset_family"], Path(l["file"]).name, l["label"], l["attempted_category"])] += l["count"]
    out = []
    for key in sorted(set(rule_keys) | set(data)):
        ds, f, lab, att = key
        n = data.get(key, 0)
        rk = rule_keys.get(key, [])
        if lab == "BENIGN" and att == "-1" and not rk:
            status = "benign_default (label_rest_as_benign)"
        elif rk and n:
            status = "rule_and_data"
        elif rk:
            status = "rule_matched_no_flows"
        else:
            status = "data_label_without_rule"
        out.append({"dataset_family": ds, "file": f, "label": lab, "attempted_category": att,
                    "n_flows_in_data": n, "rule_orders": ";".join(rk), "status": status})
    return out


# --------------------------------------------------------------------------- CLI
def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def guard(paths: list[Path], overwrite: bool) -> None:
    existing = [p.as_posix() for p in paths if p.exists()]
    if existing and not overwrite:
        raise FileExistsError("refusing to overwrite (pass --overwrite): " + ", ".join(existing))


def cmd_scan(root: Path, only: str | None, overwrite: bool) -> int:
    cfg = load_config()
    out = root / OUT
    targets = [out / "schema_by_file.json", out / "column_profile_by_file.csv",
               out / "label_distribution_by_file.csv"]
    guard(targets, overwrite)
    files = [f for f in discover_data_files(cfg, root) if not only or only in f.relpath]
    nl = read_newline_check(root)
    schemas, profiles, labels = [], [], []
    for f in files:
        log.info("scan: %s (%.2f GiB)", f.relpath, f.path.stat().st_size / 1024**3)
        con = duckdb_connect(cfg)  # fresh connection per file: a fatal error cannot cascade
        try:
            rec, labs = scan_file(con, f, cfg, nl.get(f.relpath))
        finally:
            con.close()
        log.info("  rows=%d mode=%s enc=%s label_pairs=%d (%.1f s) lines_not_read=%s", rec["n_rows"],
                 rec["read_mode"], rec["source_encoding"], len(labs), rec["seconds"],
                 (rec["newline_check"] or {}).get("lines_not_read_as_rows"))
        schemas.append(rec)
        profiles.extend({"dataset_family": f.dataset_family, "variant": f.variant, "file": f.relpath,
                         **{k: c[k] for k in PROFILE_FIELDS if k in c}} for c in rec["columns"])
        labels.extend(labs)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "schema_by_file.json").open("w", encoding="utf-8") as fh:
        json.dump({"generated_at_utc": now_utc(), "tool": TOOL, "files": schemas}, fh, indent=1)
    write_csv(out / "column_profile_by_file.csv", profiles, PROFILE_FIELDS)
    write_csv(out / "label_distribution_by_file.csv", labels, LABEL_FIELDS)
    log.info("scan: wrote %d files' schemas, %d profile rows, %d label rows", len(schemas), len(profiles), len(labels))
    return 0


def cmd_derive(root: Path, overwrite: bool) -> int:
    out = root / OUT
    targets = [out / "label_distribution_by_dataset.csv", out / "label_vs_labelling_rules.csv",
               out / "schema_diff_original_vs_improved.csv"]
    guard(targets, overwrite)
    schemas = json.loads((out / "schema_by_file.json").read_text(encoding="utf-8"))["files"]
    with (out / "label_distribution_by_file.csv").open(encoding="utf-8") as fh:
        labels = [dict(r, count=int(r["count"])) for r in csv.DictReader(fh)]
    totals = defaultdict(int)
    for s in schemas:
        totals[(s["dataset_family"], s["variant"])] += s["n_rows"]
    agg: dict[tuple, dict] = {}
    for l in labels:
        k = (l["dataset_family"], l["variant"], l["label"], l["attempted_category"])
        e = agg.setdefault(k, {"dataset_family": k[0], "variant": k[1], "label": k[2],
                               "label_display": l["label_display"], "label_bytes_hex": l["label_bytes_hex"],
                               "attempted_category": k[3], "count": 0, "n_files": 0})
        e["count"] += l["count"]
        e["n_files"] += 1
    rows = []
    for k, e in agg.items():
        e["rows_in_dataset"] = totals[(k[0], k[1])]
        e["proportion"] = e["count"] / e["rows_in_dataset"]
        rows.append(e)
    rows.sort(key=lambda e: (e["dataset_family"], e["variant"], -e["count"]))
    write_csv(out / "label_distribution_by_dataset.csv", rows,
              ["dataset_family", "variant", "label", "label_display", "label_bytes_hex", "attempted_category",
               "count", "rows_in_dataset", "proportion", "n_files"])
    lv = label_vs_rules(labels, out / "attack_windows_documented.csv")
    write_csv(out / "label_vs_labelling_rules.csv", lv,
              ["dataset_family", "file", "label", "attempted_category", "n_flows_in_data", "rule_orders", "status"])
    sd = schema_diff(schemas)
    write_csv(out / "schema_diff_original_vs_improved.csv", sd,
              ["dataset_family", "status", "original_name", "original_files_present", "improved_name",
               "improved_files_present", "match_basis", "original_inferred_types", "improved_inferred_types",
               "type_changed", "role"])
    log.info("derive: %d dataset label rows, %d label-vs-rule rows, %d schema-diff rows", len(rows), len(lv), len(sd))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/phase2_schema_labels.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--only", help="only files whose path contains this substring (pilot runs)")
    s.add_argument("--overwrite", action="store_true")
    d = sub.add_parser("derive")
    d.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    t0 = time.perf_counter()
    try:
        rc = cmd_scan(root, args.only, args.overwrite) if args.cmd == "scan" else cmd_derive(root, args.overwrite)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
