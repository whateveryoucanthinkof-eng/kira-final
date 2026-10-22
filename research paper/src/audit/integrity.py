"""Phase 3: integrity and quality audit (READ-ONLY; nothing is repaired or dropped).

Subcommands (run from the project root, in this order)
------------------------------------------------------
timeline    Per-file Parquet "timeline" cache under the OS temp dir (outside the project):
            row number in file order, id, raw + parsed timestamp, label, attempted category,
            flow duration, 5-tuple. Single-threaded scan so file order is preserved.
            Disposable and regenerable; it is an audit intermediate, not processed data.
numeric     Numeric summary (per file and per dataset variant), non-finite counts,
            negative/zero/-1 counts, constant columns, plausibility rules, 3xIQR outlier counts.
duplicates  Exact-row duplicates (excluding the row-index column `id`), feature-only
            duplicates, label conflicts among feature-identical rows, all-empty rows,
            within-file and cross-file.
timestamps  Timestamp parse quality, ranges, calendar consistency with file names, file-order
            monotonicity, gaps, sub-second precision, id-vs-row-order check, and consistency
            of attack labels with the documented labelling windows (improved data).

`report.py` (Phase 3 report step) turns these outputs into findings.csv / integrity_summary.json.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import re
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import (  # noqa: E402
    PROJECT_ROOT, DataFile, canonical_names, column_role, columns_option, csv_source,
    discover_data_files, duckdb_connect, load_config, norm_name, portable_temp_path, qident, read_header, sql_str,
)
from src.audit.encoding import newline_option, readable_path  # noqa: E402
from src.audit.inventory import now_utc, setup_logging  # noqa: E402

TOOL = "src/audit/integrity.py"
OUT = Path("results/audit")
QUANTILES = [0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99]
log = logging.getLogger("inventory")


# --------------------------------------------------------------------------- shared helpers
def cache_root() -> Path:
    d = Path(tempfile.gettempdir()) / "nids_audit_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def improved_names(files: list[DataFile]) -> list[str]:
    imp = next(f for f in files if f.variant == "improved")
    return [n.strip() for n in read_header(imp.path)["names"]]


class FileView:
    """Exact names, DuckDB names and canonical names of one file, plus its read expression."""

    def __init__(self, f: DataFile, imp_names: list[str], cfg: dict, extra: str = ""):
        self.f = f
        self.names = read_header(f.path)["names"]
        self.colopt, self.used = columns_option(self.names)
        self.canon = canonical_names(self.names, imp_names)
        self.roles = [column_role(c, cfg) for c in self.canon]
        self.read_path, self.encoding = readable_path(f)
        self.src = csv_source(self.read_path, "utf-8", extra=self.colopt + ", " + newline_option(f) + extra)

    def col(self, canon: str) -> str | None:
        """DuckDB identifier of the column with this canonical name (None if absent)."""
        for u, c in zip(self.used, self.canon):
            if c == canon:
                return qident(u)
        return None


TEXT_COLUMNS = {"Flow ID", "Src IP", "Dst IP", "Timestamp", "Label"}


def hash_expr(v: "FileView", cols: list[str]) -> str:
    """Row hash over canonical columns. Numeric columns are hashed by VALUE (cast to DOUBLE), not
    by text, because number formatting differs between files of the same release (e.g. '0.0' vs '0'
    for Fwd/Bwd RST Flags in the improved Wednesday-28-02-2018.csv, VERIFIED)."""
    parts = [v.col(c) if c in TEXT_COLUMNS else f"TRY_CAST({v.col(c)} AS DOUBLE)" for c in cols]
    return "hash(" + ", ".join(parts) + ")"


def group_by_variant(files: list[DataFile]) -> dict[tuple[str, str], list[DataFile]]:
    g = defaultdict(list)
    for f in files:
        g[(f.dataset_family, f.variant)].append(f)
    return dict(g)


def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def guard(paths: list[Path], overwrite: bool) -> None:
    existing = [p.as_posix() for p in paths if p.exists()]
    if existing and not overwrite:
        raise FileExistsError("refusing to overwrite (pass --overwrite): " + ", ".join(existing))


def schema_info(root: Path) -> dict[str, dict]:
    p = root / OUT / "schema_by_file.json"
    return {s["relpath"]: s for s in json.loads(p.read_text(encoding="utf-8"))["files"]}


def ts_formats_for(schema: dict) -> list[str]:
    """Timestamp formats with non-zero full-scan coverage, most-covering first."""
    cov = schema.get("timestamp_format_coverage") or {}
    return [f for f, n in sorted(cov.items(), key=lambda kv: -kv[1]) if n > 0]


# --------------------------------------------------------------------------- timeline cache
TIMELINE_COLS = {  # canonical name -> (alias, SQL type)
    "id": ("id", "BIGINT"), "Src IP": ("src_ip", "VARCHAR"), "Dst IP": ("dst_ip", "VARCHAR"),
    "Src Port": ("src_port", "INTEGER"), "Dst Port": ("dst_port", "INTEGER"),
    "Protocol": ("protocol", "INTEGER"), "Flow Duration": ("flow_duration", "BIGINT"),
    "Total Fwd Packet": ("fwd_pkts", "BIGINT"), "Total Bwd packets": ("bwd_pkts", "BIGINT"),
    "Total Length of Fwd Packet": ("fwd_bytes", "DOUBLE"), "Total Length of Bwd Packet": ("bwd_bytes", "DOUBLE"),
    "Label": ("label", "VARCHAR"), "Attempted Category": ("attempted", "VARCHAR"),
}


def timeline_path(f: DataFile) -> Path:
    d = cache_root() / "timeline"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{f.dataset_family}__{f.variant}__{Path(f.relpath).stem}.parquet"


def cmd_timeline(root: Path, cfg: dict, only: str | None, overwrite: bool) -> int:
    files = discover_data_files(cfg, root)
    imp = improved_names(files)
    schemas = schema_info(root)
    manifest = root / "data/manifests/timeline_cache_manifest.csv"
    rows = []
    if manifest.exists():
        with manifest.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    done = {r["relpath"]: r for r in rows}
    for f in files:
        if only and only not in f.relpath:
            continue
        out = timeline_path(f)
        if out.exists() and f.relpath in done and not overwrite:
            log.info("timeline: %s cached, skipping", f.relpath)
            continue
        t0 = time.perf_counter()
        v = FileView(f, imp, cfg)
        fmts = ts_formats_for(schemas[f.relpath])
        ts_raw = v.col("Timestamp")
        ts_expr = ("coalesce(" + ", ".join(f"TRY_STRPTIME(trim({ts_raw}), {sql_str(x)})" for x in fmts) + ")"
                   if ts_raw and fmts else "NULL::TIMESTAMP")
        sel = ["row_number() OVER () AS rn", f"{ts_raw or 'NULL'} AS ts_text", f"{ts_expr} AS ts"]
        for canon, (alias, typ) in TIMELINE_COLS.items():
            c = v.col(canon)
            if c is None:
                sel.append(f"NULL::{typ} AS {alias}")
            elif typ == "VARCHAR":
                sel.append(f"{c} AS {alias}")
            else:
                sel.append(f"TRY_CAST({c} AS {typ}) AS {alias}")
        con = duckdb_connect(cfg)
        con.execute("SET threads=1")
        con.execute("SET preserve_insertion_order=true")
        tmp = out.with_suffix(".partial")
        con.execute(f"COPY (SELECT {', '.join(sel)} FROM {v.src}) TO {sql_str(tmp.as_posix())} "
                    "(FORMAT parquet, COMPRESSION zstd)")
        n = con.execute(f"SELECT count(*) FROM read_parquet({sql_str(tmp.as_posix())})").fetchone()[0]
        con.close()
        tmp.replace(out)
        done[f.relpath] = {"relpath": f.relpath, "cache_path": portable_temp_path(out), "rows": n,
                           "timestamp_formats": "|".join(fmts), "created_at_utc": now_utc(),
                           "seconds": round(time.perf_counter() - t0, 1)}
        log.info("timeline: %s -> %d rows (%.1f s)", f.relpath, n, time.perf_counter() - t0)
        write_csv(manifest, [done[k] for k in sorted(done)],
                  ["relpath", "cache_path", "rows", "timestamp_formats", "created_at_utc", "seconds"])
    return 0


# --------------------------------------------------------------------------- numeric summary
def semantics_of(canon: str, cfg: dict) -> str:
    for kind, pats in cfg["semantics"].items():
        if any(re.search(p, canon) for p in pats):
            return kind
    return ""


def numeric_columns(views: list[FileView]) -> list[str]:
    """Canonical numeric-candidate columns present in any file of the group, in first-seen order."""
    out = []
    for v in views:
        for c, r in zip(v.canon, v.roles):
            if c == "id" or r in ("timestamp", "target") or c in ("Flow ID", "Src IP", "Dst IP"):
                continue
            if c not in out:
                out.append(c)
    return out


def cmd_numeric(root: Path, cfg: dict, overwrite: bool) -> int:
    out_sum, out_rules = root / OUT / "numeric_feature_summary.csv", root / OUT / "plausibility_by_file.csv"
    guard([out_sum, out_rules], overwrite)
    files = discover_data_files(cfg, root)
    imp = improved_names(files)
    summary, rule_rows = [], []
    for (fam, var), group in group_by_variant(files).items():
        t0 = time.perf_counter()
        views = [FileView(f, imp, cfg) for f in group]
        cols = numeric_columns(views)
        parts = []
        for v in views:
            sel = [f"{sql_str(v.f.relpath)} AS __file"]
            for c in cols:
                src_c = v.col(c)
                if src_c:
                    sel.append(f"TRY_CAST({src_c} AS DOUBLE) AS {qident(c)}")
            parts.append(f"SELECT {', '.join(sel)} FROM {v.src}")
        union = " UNION ALL BY NAME ".join(f"({p})" for p in parts)
        fin = [f"CASE WHEN isfinite({qident(c)}) THEN {qident(c)} END AS {qident('f::' + c)}" for c in cols]
        aggs = ["count(*) AS n_rows"]
        for i, c in enumerate(cols):
            x, fx = qident(c), qident("f::" + c)
            aggs += [f"count({x}) AS num_{i}", f"count_if({x} = 'inf'::DOUBLE) AS pinf_{i}",
                     f"count_if({x} = '-inf'::DOUBLE) AS ninf_{i}", f"count_if(isnan({x})) AS nan_{i}",
                     f"min({fx}) AS min_{i}", f"max({fx}) AS max_{i}", f"avg({fx}) AS mean_{i}",
                     f"stddev_samp({fx}) AS std_{i}", f"approx_quantile({fx}, {QUANTILES}) AS q_{i}",
                     f"count_if({fx} < 0) AS neg_{i}", f"count_if({fx} = 0) AS zero_{i}",
                     f"count_if({fx} = -1) AS m1_{i}", f"approx_count_distinct({fx}) AS ad_{i}"]
        rules = []
        for r in cfg["plausibility_rules"]:
            refs = re.findall(r'"([^"]+)"', r["expr"])
            if all(ref in cols for ref in refs):
                expr = re.sub(r'"([^"]+)"', lambda m: qident("f::" + m.group(1)), r["expr"])
                need = " AND ".join(f"{qident('f::' + ref)} IS NOT NULL" for ref in dict.fromkeys(refs))
                aggs += [f"count_if({need}) AS reval_{len(rules)}", f"count_if(({expr}) AND {need}) AS rviol_{len(rules)}"]
                rules.append(r)
            else:
                rule_rows.append({"dataset_family": fam, "variant": var, "scope": "dataset", "file": "",
                                  "rule_id": r["id"], "severity": r["severity"], "status": "not_applicable",
                                  "n_evaluable": "", "n_violations": "",
                                  "note": "missing columns: " + ", ".join(x for x in refs if x not in cols)})
        sql = (f"WITH u AS ({union}), f AS (SELECT *, {', '.join(fin)} FROM u) "
               f"SELECT __file, grouping(__file) AS g, {', '.join(aggs)} FROM f GROUP BY GROUPING SETS ((__file), ())")
        con = duckdb_connect(cfg)
        cur = con.execute(sql)
        names = [d[0] for d in cur.description]
        res = [dict(zip(names, row)) for row in cur.fetchall()]
        # dataset-scope 3xIQR outlier counts (second pass, needs the dataset quartiles)
        ds = next(r for r in res if r["g"] == 1)
        out_aggs, bounds = [], {}
        for i, c in enumerate(cols):
            q = ds[f"q_{i}"]
            if q and q[2] is not None and q[4] is not None:
                iqr = q[4] - q[2]
                lo, hi = q[2] - 3 * iqr, q[4] + 3 * iqr
                bounds[i] = (lo, hi)
                fx = qident("f::" + c)
                out_aggs.append(f"count_if({fx} < {lo!r} OR {fx} > {hi!r}) AS out_{i}")
        outl = {}
        if out_aggs:
            cur = con.execute(f"WITH u AS ({union}), f AS (SELECT *, {', '.join(fin)} FROM u) SELECT {', '.join(out_aggs)} FROM f")
            outl = dict(zip([d[0] for d in cur.description], cur.fetchone()))
        con.close()
        count_prefixes = ("num_", "pinf_", "ninf_", "nan_", "neg_", "zero_", "m1_", "ad_", "reval_", "rviol_")
        for r in res:
            # a column absent from a file (UNION BY NAME fills NULL) can yield NULL counts: treat as 0
            for k in list(r):
                if k.startswith(count_prefixes) and r[k] is None:
                    r[k] = 0
            scope = "dataset" if r["g"] == 1 else "file"
            fname = "" if scope == "dataset" else r["__file"]
            for i, c in enumerate(cols):
                n_num = r[f"num_{i}"]
                q = r[f"q_{i}"] or [None] * len(QUANTILES)
                n_fin = n_num - r[f"pinf_{i}"] - r[f"ninf_{i}"] - r[f"nan_{i}"]
                sem = semantics_of(c, cfg)
                row = {"dataset_family": fam, "variant": var, "scope": scope, "file": fname, "column": c,
                       "role": column_role(c, cfg), "semantics": sem, "n_rows": r["n_rows"], "n_numeric": n_num,
                       "n_pos_inf": r[f"pinf_{i}"], "n_neg_inf": r[f"ninf_{i}"], "n_nan": r[f"nan_{i}"],
                       "n_finite": n_fin, "min": r[f"min_{i}"], "max": r[f"max_{i}"], "mean": r[f"mean_{i}"],
                       "std": r[f"std_{i}"], **{f"q{int(p * 100):02d}": v for p, v in zip(QUANTILES, q)},
                       "n_negative": r[f"neg_{i}"], "n_zero": r[f"zero_{i}"], "n_minus_one": r[f"m1_{i}"],
                       "approx_distinct": r[f"ad_{i}"],
                       "is_constant": n_fin > 0 and r[f"min_{i}"] == r[f"max_{i}"] and n_fin == n_num,
                       "n_negative_invalid": r[f"neg_{i}"] if sem == "nonnegative" else "",
                       "n_negative_other_than_sentinel": (r[f"neg_{i}"] - r[f"m1_{i}"]) if sem == "sentinel_minus_one" else "",
                       "n_outlier_3iqr": outl.get(f"out_{i}", "") if scope == "dataset" else "",
                       "outlier_bounds": json.dumps(bounds.get(i)) if scope == "dataset" and i in bounds else ""}
                summary.append(row)
            for k, rule in enumerate(rules):
                rule_rows.append({"dataset_family": fam, "variant": var, "scope": scope, "file": fname,
                                  "rule_id": rule["id"], "severity": rule["severity"], "status": "evaluated",
                                  "n_evaluable": r[f"reval_{k}"], "n_violations": r[f"rviol_{k}"],
                                  "note": rule["rationale"]})
        log.info("numeric: %s/%s %d files, %d columns, %d rules (%.1f s)", fam, var, len(group), len(cols),
                 len(rules), time.perf_counter() - t0)
    write_csv(out_sum, summary)
    write_csv(out_rules, rule_rows)
    return 0


# --------------------------------------------------------------------------- duplicates
def cmd_duplicates(root: Path, cfg: dict, overwrite: bool) -> int:
    out = root / OUT / "duplicates_by_file.csv"
    guard([out], overwrite)
    files = discover_data_files(cfg, root)
    imp = improved_names(files)
    rows = []
    for (fam, var), group in group_by_variant(files).items():
        t0 = time.perf_counter()
        views = [FileView(f, imp, cfg) for f in group]
        common = [c for c in views[0].canon if all(c in v.canon for v in views) and "__dup" not in c]
        full_key = [c for c in common if c != "id"]
        feat_key = [c for c in common if column_role(c, cfg) in ("feature", "context_review")]
        dbfile = cache_root() / f"dups_{fam}_{var}.duckdb"
        if dbfile.exists():
            dbfile.unlink()
        import duckdb
        con = duckdb.connect(dbfile.as_posix())
        d = cfg["duckdb"]
        con.execute(f"SET threads={int(d['threads'])}; SET memory_limit={sql_str(d['memory_limit'])}; "
                    f"SET temp_directory={sql_str((cache_root() / 'duckdb_tmp').as_posix())}; "
                    "SET preserve_insertion_order=false")
        con.execute("CREATE TABLE t (file VARCHAR, hf UBIGINT, hx UBIGINT, lab VARCHAR, allnull BOOLEAN, "
                    "nondata BOOLEAN)")
        for v in views:
            hf = hash_expr(v, full_key)
            hx = hash_expr(v, feat_key)
            lab = v.col("Label") or "NULL"
            alln = "coalesce(" + ", ".join(qident(u) for u in v.used) + ") IS NULL"
            # non-data rows: all-empty rows and header lines repeated inside the data (Label == 'Label')
            nond = f"({alln} OR coalesce(trim({lab}) = 'Label', false))"
            con.execute(f"INSERT INTO t SELECT {sql_str(v.f.relpath)}, {hf}, {hx}, {lab}, {alln}, {nond} FROM {v.src}")
        binlab = "CASE WHEN lab IS NULL THEN NULL WHEN upper(trim(lab)) = 'BENIGN' THEN 'benign' ELSE 'non_benign' END"
        # All duplicate and conflict counts below are over data rows only (NOT nondata). Counts are
        # "rows minus distinct", i.e. redundant copies; *_incl_nondata keeps the raw figure.
        agg = ("count(*), count_if(allnull), count_if(nondata AND NOT allnull), count_if(NOT nondata), "
               "count(DISTINCT hf) FILTER (WHERE NOT nondata), count(DISTINCT hx) FILTER (WHERE NOT nondata), "
               "count(DISTINCT hx)")
        per_file = {r[0]: r for r in con.execute(f"SELECT file, {agg} FROM t GROUP BY file").fetchall()}
        conf = {r[0]: r[1:] for r in con.execute(
            f"SELECT file, count(*), sum(c), sum(bc) FROM (SELECT file, hx, count(*) c, "
            f"CASE WHEN count(DISTINCT {binlab}) > 1 THEN count(*) ELSE 0 END bc "
            f"FROM t WHERE NOT nondata GROUP BY file, hx HAVING count(DISTINCT lab) > 1) GROUP BY file").fetchall()}

        def counts(n, nall, nhdr, nd, dhf, dhx, dhx_all):
            return {"n_rows": n, "n_all_empty_rows": nall, "n_embedded_header_rows": nhdr, "n_data_rows": nd,
                    "n_exact_duplicate_rows_excl_empty": nd - dhf, "n_feature_duplicate_rows": nd - dhx,
                    "n_feature_duplicate_rows_incl_nondata": n - dhx_all}

        for fname, (_, *cnt) in sorted(per_file.items()):
            c = conf.get(fname, (0, 0, 0))
            rows.append({"dataset_family": fam, "variant": var, "scope": "file", "file": fname, **counts(*cnt),
                         "n_label_conflict_groups": c[0], "n_rows_in_label_conflict_groups": c[1] or 0,
                         "n_rows_in_binary_conflict_groups": c[2] or 0,
                         "full_key": f"all {len(full_key)} common columns except id",
                         "feature_key": f"{len(feat_key)} feature columns (no ids, timestamp, labels)"})
        tot = con.execute(f"SELECT {agg} FROM t").fetchone()
        cross = con.execute("SELECT count(*), coalesce(sum(c), 0), coalesce(sum(c - 1), 0) FROM (SELECT hf, count(*) c, "
                            "count(DISTINCT file) nf FROM t WHERE NOT nondata GROUP BY hf HAVING count(*) > 1) WHERE nf > 1").fetchone()
        dconf = con.execute(f"SELECT count(*), coalesce(sum(c), 0), coalesce(sum(bc), 0) FROM (SELECT hx, count(*) c, "
                            f"CASE WHEN count(DISTINCT {binlab}) > 1 THEN count(*) ELSE 0 END bc FROM t WHERE NOT nondata "
                            f"GROUP BY hx HAVING count(DISTINCT lab) > 1)").fetchone()
        rows.append({"dataset_family": fam, "variant": var, "scope": "dataset", "file": "", **counts(*tot),
                     "n_cross_file_duplicate_groups": cross[0], "n_rows_in_cross_file_duplicate_groups": cross[1],
                     "n_label_conflict_groups": dconf[0], "n_rows_in_label_conflict_groups": dconf[1],
                     "n_rows_in_binary_conflict_groups": dconf[2],
                     "full_key": f"all {len(full_key)} common columns except id",
                     "feature_key": f"{len(feat_key)} feature columns: " + "; ".join(feat_key)})
        con.close()
        dbfile.unlink()
        log.info("duplicates: %s/%s done (%.1f s)", fam, var, time.perf_counter() - t0)
    write_csv(out, rows)
    return 0


# --------------------------------------------------------------------------- timestamps
WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def cmd_timestamps(root: Path, cfg: dict, overwrite: bool) -> int:
    out, out_lw = root / OUT / "timestamp_quality.csv", root / OUT / "label_window_consistency.csv"
    guard([out, out_lw], overwrite)
    files = discover_data_files(cfg, root)
    rules_csv = (root / OUT / "attack_windows_documented.csv").as_posix()
    rows, lw_rows = [], []
    con = duckdb_connect(cfg)
    con.execute(f"CREATE TABLE rules AS SELECT dataset, file, label, CAST(attempted_category AS VARCHAR) AS att, "
                f"make_timestamp(start_ns // 1000) AS t0, make_timestamp((end_ns + 999) // 1000) AS t1 "
                f"FROM read_csv({sql_str(rules_csv)}, header=true, auto_detect=true)")
    for f in files:
        p = timeline_path(f)
        if not p.exists():
            log.error("timestamps: missing timeline cache for %s (run `timeline` first)", f.relpath)
            return 1
        t0 = time.perf_counter()
        src = f"read_parquet({sql_str(p.as_posix())})"
        name = Path(f.relpath).name
        m = re.search(r"(\d{2})-(\d{2})-(\d{4})", name)
        file_date = dt.date(int(m.group(3)), int(m.group(2)), int(m.group(1))) if m else None
        wd = next((w for w in WEEKDAY_NAMES if w.lower() in name.lower()), None)
        b = con.execute(
            f"SELECT count(*), count_if(ts_text IS NOT NULL), count(ts), min(ts), max(ts), count(DISTINCT ts), "
            f"count_if(ts IS NOT NULL AND microsecond(ts) % 1000000 <> 0), "
            f"{'count_if(ts IS NOT NULL AND CAST(ts AS DATE) <> DATE ' + sql_str(file_date.isoformat()) + ')' if file_date else 'NULL'}, "
            f"{'count_if(ts IS NOT NULL AND dayname(ts) <> ' + sql_str(wd) + ')' if wd else 'NULL'}, "
            f"count_if(id IS NOT NULL), count_if(id IS NOT NULL AND id <> rn), "
            f"list(DISTINCT CAST(ts AS DATE)) FILTER (WHERE ts IS NOT NULL) FROM {src}").fetchone()
        n, n_txt, n_ts, tmin, tmax, ndist, nsub, ndate_mis, nwd_mis, n_id, id_mis, dates = b
        order = con.execute(
            f"SELECT count_if(d < 0), count_if(d < -60), min(d) FROM (SELECT epoch(ts) - epoch(lag(ts) OVER (ORDER BY rn)) d "
            f"FROM {src} WHERE ts IS NOT NULL)").fetchone()
        gaps = con.execute(
            f"SELECT max(g), count_if(g > 60), count_if(g > 300), count_if(g > 1800) FROM (SELECT epoch(ts) - epoch(lag(ts) "
            f"OVER (ORDER BY ts)) g FROM {src} WHERE ts IS NOT NULL)").fetchone()
        top = con.execute(
            f"SELECT prev, ts, g FROM (SELECT lag(ts) OVER (ORDER BY ts) prev, ts, epoch(ts) - epoch(lag(ts) OVER (ORDER BY ts)) g "
            f"FROM {src} WHERE ts IS NOT NULL) WHERE g IS NOT NULL ORDER BY g DESC LIMIT 5").fetchall()
        hours = con.execute(f"SELECT hour(ts) h, count(*) FROM {src} WHERE ts IS NOT NULL GROUP BY 1 ORDER BY 1").fetchall()
        rows.append({
            "dataset_family": f.dataset_family, "variant": f.variant, "file": f.relpath, "n_rows": n,
            "n_timestamp_text_nonnull": n_txt, "n_parsed": n_ts, "n_parse_failures": n_txt - n_ts,
            "n_missing_timestamp": n - n_txt, "min_ts": tmin, "max_ts": tmax,
            "span_hours": round((tmax - tmin).total_seconds() / 3600, 3) if tmin and tmax else "",
            "n_distinct_ts": ndist, "n_duplicate_ts": n_ts - ndist,
            "n_with_subsecond": nsub, "dates_present": json.dumps(sorted(str(x) for x in (dates or []))),
            "filename_date": file_date.isoformat() if file_date else "", "n_date_mismatch_filename": ndate_mis,
            "filename_weekday": wd or "", "n_weekday_mismatch_filename": nwd_mis,
            "n_backward_steps_file_order": order[0], "n_backward_steps_gt_60s": order[1],
            "max_backward_jump_s": -order[2] if order[2] is not None and order[2] < 0 else 0,
            "max_gap_sorted_s": gaps[0], "n_gaps_gt_60s": gaps[1], "n_gaps_gt_300s": gaps[2], "n_gaps_gt_1800s": gaps[3],
            "top5_gaps": json.dumps([[str(a), str(b2), round(g, 3)] for a, b2, g in top]),
            "hour_histogram_as_parsed": json.dumps({int(h): c for h, c in hours}),
            "n_id_present": n_id, "n_id_ne_row_order": id_mis,
            "timezone_assumption": "UTC (DOCUMENTED for improved files)" if f.variant == "improved" else "UNRESOLVED (original files carry no timezone)",
        })
        if f.variant == "improved":
            fam = f.dataset_family
            res = con.execute(
                f"SELECT t.label, t.attempted, count(*) n, "
                f"count_if(EXISTS (SELECT 1 FROM rules r WHERE r.dataset = {sql_str(fam)} AND r.file = {sql_str(name)} "
                f"AND r.label = t.label AND r.att = t.attempted AND t.ts BETWEEN r.t0 AND r.t1)) n_in, "
                f"count_if(EXISTS (SELECT 1 FROM rules r WHERE r.dataset = {sql_str(fam)} AND r.file = {sql_str(name)} "
                f"AND r.label = t.label AND r.att = t.attempted)) n_has_rule, min(t.ts), max(t.ts) "
                f"FROM {src} t WHERE upper(t.label) <> 'BENIGN' GROUP BY 1, 2 ORDER BY 1, 2").fetchall()
            for lab, att, nn, n_in, n_rule, lo, hi in res:
                lw_rows.append({"dataset_family": fam, "file": name, "label": lab, "attempted_category": att,
                                "n_flows": nn, "n_with_documented_rule": n_rule,
                                "n_timestamp_inside_rule_window": n_in, "n_outside": nn - n_in,
                                "first_ts": lo, "last_ts": hi})
        log.info("timestamps: %s (%.1f s)", f.relpath, time.perf_counter() - t0)
    con.close()
    write_csv(out, rows)
    write_csv(out_lw, lw_rows)
    return 0


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/phase3_integrity.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("timeline")
    t.add_argument("--only")
    t.add_argument("--overwrite", action="store_true")
    for name in ("numeric", "duplicates", "timestamps"):
        s = sub.add_parser(name)
        s.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    cfg = load_config()
    t0 = time.perf_counter()
    try:
        if args.cmd == "timeline":
            rc = cmd_timeline(root, cfg, args.only, args.overwrite)
        elif args.cmd == "numeric":
            rc = cmd_numeric(root, cfg, args.overwrite)
        elif args.cmd == "duplicates":
            rc = cmd_duplicates(root, cfg, args.overwrite)
        else:
            rc = cmd_timestamps(root, cfg, args.overwrite)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
