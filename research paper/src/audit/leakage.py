"""Phase 6: leakage audit and split-design evidence (read-only; no model is trained).

Subcommands (run from the project root)
---------------------------------------
separability  Per-feature class-conditional histograms (sign*log2 bins, plus a 'nonfinite' bin) in
              one pass per dataset variant (GROUPING SETS), turned into the overlap coefficient
              OVL(benign, attack) = sum_b min(p_benign(b), p_attack(b)). OVL near 0 means a single
              feature almost separates the classes (a shortcut / artefact candidate). Coarse bins
              can only *increase* OVL, so low values are conservative flags.
hashes        Disk-backed DuckDB table (OS temp) of (file, ts, feature-hash, label) for improved data.
splits        Candidate split protocols evaluated on that table: rows/attacks/families per partition,
              and the share of evaluation rows whose exact feature vector also occurs in training
              (and, for test, in train + val, the usual refit set). split_family_leakage.csv gives
              the same per attack family, with whether the family occurs in train / val at all.
conflicts     Label composition of feature-identical groups with more than one label (improved data).

`report` content (leakage_findings.csv) is produced by src/audit/report.py.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.audit.common import (  # noqa: E402
    PROJECT_ROOT, column_role, discover_data_files, duckdb_connect, load_config, qident, sql_str,
)
from src.audit.integrity import (  # noqa: E402
    FileView, cache_root, group_by_variant, guard, hash_expr, improved_names, numeric_columns, write_csv,
)
from src.audit.inventory import setup_logging  # noqa: E402

TOOL = "src/audit/leakage.py"
OUT = Path("results/audit")
log = logging.getLogger("inventory")

def class_expr(lab: str) -> str:
    """benign / attempted / attack class of a label expression (NULL stays NULL)."""
    return (f"CASE WHEN {lab} IS NULL THEN NULL WHEN upper(trim({lab})) = 'BENIGN' THEN 'benign' "
            f"WHEN {lab} LIKE '% - Attempted' THEN 'attempted' ELSE 'attack' END")


def bin_expr(x: str) -> str:
    return (f"CASE WHEN {x} IS NULL THEN 'null' WHEN NOT isfinite({x}) THEN 'nonfinite' "
            f"ELSE CAST(CAST(sign({x}) * ceil(log2(abs({x}) + 1)) AS INTEGER) AS VARCHAR) END")


def cmd_separability(root: Path, cfg: dict, overwrite: bool) -> int:
    out = root / OUT / "feature_separability.csv"
    guard([out], overwrite)
    files = discover_data_files(cfg, root)
    imp = improved_names(files)
    rows = []
    for (fam, var), group in group_by_variant(files).items():
        t0 = time.perf_counter()
        views = [FileView(f, imp, cfg) for f in group]
        cols = [c for c in numeric_columns(views)]
        extra = ["id"] if var == "improved" else []
        parts = []
        for v in views:
            sel = [f"{v.col('Label') or 'NULL'} AS lab"]
            for c in cols + extra:
                s = v.col(c)
                if s:
                    sel.append(f"TRY_CAST({s} AS DOUBLE) AS {qident(c)}")
            ts = v.col("Timestamp")
            sel.append(f"TRY_CAST(substr(trim({ts}), 12, 2) AS DOUBLE) AS {qident('hour_of_timestamp')}"
                       if var == "improved" and ts else f"NULL::DOUBLE AS {qident('hour_of_timestamp')}")
            parts.append(f"SELECT {', '.join(sel)} FROM {v.src}")
        union = " UNION ALL BY NAME ".join(f"({p})" for p in parts)
        feats = cols + extra + (["hour_of_timestamp"] if var == "improved" else [])
        bcols = [qident("b::" + c) for c in feats]
        binned = ", ".join(f"{bin_expr(qident(c))} AS {bc}" for c, bc in zip(feats, bcols))
        sets = ", ".join(f"(cls, {bc})" for bc in bcols)
        gcols = ", ".join(f"grouping({bc}) AS {qident('g::' + c)}" for c, bc in zip(feats, bcols))
        sql = (f"WITH u AS ({union}), b AS (SELECT {class_expr('lab')} AS cls, {binned} FROM u WHERE lab IS NOT NULL AND trim(lab) <> 'Label') "
               f"SELECT cls, {', '.join(bcols)}, {gcols}, count(*) n FROM b GROUP BY GROUPING SETS ({sets})")
        con = duckdb_connect(cfg)
        cur = con.execute(sql)
        names = [d[0] for d in cur.description]
        res = [dict(zip(names, r)) for r in cur.fetchall()]
        con.close()
        for c in feats:
            hist: dict[str, dict[str, int]] = {}
            for r in res:
                if r["g::" + c] == 0:
                    hist.setdefault(r["cls"], {})[r["b::" + c]] = r["n"]
            tot = {k: sum(v.values()) for k, v in hist.items()}

            def ovl(a: str, b: str):
                if not tot.get(a) or not tot.get(b):
                    return None
                keys = set(hist[a]) | set(hist[b])
                return round(sum(min(hist[a].get(k, 0) / tot[a], hist[b].get(k, 0) / tot[b]) for k in keys), 6)

            rows.append({"dataset_family": fam, "variant": var, "feature": c,
                         "role": column_role(c, cfg) if c not in ("hour_of_timestamp",) else "derived_from_timestamp",
                         "n_benign": tot.get("benign", 0), "n_attack": tot.get("attack", 0),
                         "n_attempted": tot.get("attempted", 0), "n_bins_used": len({k for h in hist.values() for k in h}),
                         "ovl_benign_vs_attack": ovl("benign", "attack"),
                         "ovl_benign_vs_attempted": ovl("benign", "attempted"),
                         "ovl_attack_vs_attempted": ovl("attack", "attempted"),
                         "binning": "sign(x)*ceil(log2(|x|+1)); separate null / nonfinite bins"})
        log.info("separability: %s/%s %d features (%.1f s)", fam, var, len(feats), time.perf_counter() - t0)
    write_csv(out, rows)
    return 0


def hashes_db() -> Path:
    return cache_root() / "leakage_hashes.duckdb"


def cmd_hashes(root: Path, cfg: dict) -> int:
    import duckdb
    files = [f for f in discover_data_files(cfg, root) if f.variant == "improved"]
    imp = improved_names(files)
    db = hashes_db()
    if db.exists():
        db.unlink()
    con = duckdb.connect(db.as_posix())
    d = cfg["duckdb"]
    con.execute(f"SET threads={int(d['threads'])}; SET memory_limit={sql_str(d['memory_limit'])}; "
                f"SET temp_directory={sql_str((cache_root() / 'duckdb_tmp').as_posix())}; SET preserve_insertion_order=false")
    con.execute("CREATE TABLE h (dataset VARCHAR, file VARCHAR, ts TIMESTAMP, hx UBIGINT, cls VARCHAR, fam VARCHAR)")
    for f in files:
        t0 = time.perf_counter()
        v = FileView(f, imp, cfg)
        feat = [c for c in v.canon if column_role(c, cfg) in ("feature", "context_review") and "__dup" not in c]
        hx = hash_expr(v, feat)  # numeric columns hashed by value, not text (formatting differs across files)
        lab = v.col("Label")
        con.execute(
            f"INSERT INTO h SELECT {sql_str(f.dataset_family)}, {sql_str(Path(f.relpath).name)}, "
            f"TRY_STRPTIME(trim({v.col('Timestamp')}), '%Y-%m-%d %H:%M:%S.%f'), {hx}, "
            f"{class_expr(lab)}, regexp_replace({lab}, ' - Attempted$', '') FROM {v.src}")
        log.info("hashes: %s (%.1f s)", f.relpath, time.perf_counter() - t0)
    n = con.execute("SELECT count(*), count_if(ts IS NULL) FROM h").fetchone()
    con.close()
    log.info("hashes: %d rows (%d with unparsed ts) in %s", n[0], n[1], db)
    return 0


def split_sql(protocol: dict) -> str:
    """SQL CASE assigning each row of `h` to train/val/test/embargo for a protocol definition."""
    kind = protocol["kind"]
    if kind == "random_rows":
        return ("CASE WHEN hash(file, ts, hx) % 100 < 70 THEN 'train' "
                "WHEN hash(file, ts, hx) % 100 < 85 THEN 'val' ELSE 'test' END")
    if kind == "by_file":
        parts = []
        for part in ("train", "val", "test"):
            fl = ", ".join(sql_str(x) for x in protocol[part])
            if fl:
                parts.append(f"WHEN file IN ({fl}) THEN '{part}'")
        return "CASE " + " ".join(parts) + " ELSE 'unused' END"
    if kind == "within_file_time":
        e = int(protocol["embargo_s"])
        a, b = protocol["fractions"][0], protocol["fractions"][0] + protocol["fractions"][1]
        pos = "(epoch(ts) - epoch(fmin)) / nullif(epoch(fmax) - epoch(fmin), 0)"
        cut1 = f"(epoch(fmin) + {a} * (epoch(fmax) - epoch(fmin)))"
        cut2 = f"(epoch(fmin) + {b} * (epoch(fmax) - epoch(fmin)))"
        return (f"CASE WHEN abs(epoch(ts) - {cut1}) <= {e} OR abs(epoch(ts) - {cut2}) <= {e} THEN 'embargo' "
                f"WHEN {pos} < {a} THEN 'train' WHEN {pos} < {b} THEN 'val' ELSE 'test' END")
    if kind == "within_file_flow_quantile":
        # cuts at the times by which 60% / 80% of the file's (non-excluded) flows have started
        e = int(protocol["embargo_s"])
        a, b = protocol["fractions"][0], protocol["fractions"][0] + protocol["fractions"][1]
        q1, q2 = (f"quantile_disc(ts, {x}) FILTER (WHERE NOT excluded) OVER (PARTITION BY file)" for x in (a, b))
        return (f"CASE WHEN abs(epoch(ts) - epoch({q1})) <= {e} OR abs(epoch(ts) - epoch({q2})) <= {e} THEN 'embargo' "
                f"WHEN ts < {q1} THEN 'train' WHEN ts < {q2} THEN 'val' ELSE 'test' END")
    raise ValueError(kind)


def cmd_splits(root: Path, cfg: dict, overwrite: bool) -> int:
    import duckdb
    import yaml
    out_cov, out_dup = root / OUT / "split_design_coverage.csv", root / OUT / "split_duplicate_leakage.csv"
    out_fam = root / OUT / "split_family_leakage.csv"
    guard([out_cov, out_dup, out_fam], overwrite)
    proto = yaml.safe_load((root / "configs/evaluation_protocol.yaml").read_text(encoding="utf-8"))
    con = duckdb.connect(hashes_db().as_posix(), read_only=False)
    d = cfg["duckdb"]
    con.execute(f"SET threads={int(d['threads'])}; SET memory_limit={sql_str(d['memory_limit'])}; "
                f"SET temp_directory={sql_str((cache_root() / 'duckdb_tmp').as_posix())}")
    # configured row exclusions (counted, never silent): excluded rows get partition 'excluded' and do
    # not enter the per-file time span used by within-file cuts
    excl = " OR ".join(f"(dataset = {sql_str(x['dataset'])} AND file = {sql_str(x['file'])} AND "
                       f"ts < TIMESTAMP {sql_str(x['ts_before'])})" for x in proto.get("row_exclusions", [])) or "false"
    con.execute(f"CREATE OR REPLACE TEMP VIEW hx_ AS SELECT h.*, ({excl}) AS excluded FROM h")
    con.execute("CREATE OR REPLACE TEMP VIEW hf AS SELECT hx_.*, min(ts) FILTER (WHERE NOT excluded) OVER (PARTITION BY file) fmin, "
                "max(ts) FILTER (WHERE NOT excluded) OVER (PARTITION BY file) fmax FROM hx_")
    for x in proto.get("row_exclusions", []):
        n = con.execute(f"SELECT count(*) FROM hx_ WHERE excluded AND dataset = {sql_str(x['dataset'])} "
                        f"AND file = {sql_str(x['file'])}").fetchone()[0]
        log.info("splits: row exclusion %s / %s ts < %s: %d rows", x["dataset"], x["file"], x["ts_before"], n)
    cov_rows, dup_rows, fam_rows = [], [], []
    for name, p in proto["split_candidates"].items():
        for ds in p.get("datasets", ["CIC-IDS-2017", "CSE-CIC-IDS-2018"]):
            pp = p.get("per_dataset", {}).get(ds, p)
            t0 = time.perf_counter()
            assign = split_sql(pp)
            con.execute(f"CREATE OR REPLACE TEMP TABLE a AS SELECT file, ts, hx, cls, fam, "
                        f"CASE WHEN excluded THEN 'excluded' ELSE {assign} END AS part "
                        f"FROM hf WHERE dataset = {sql_str(ds)}")
            for r in con.execute(
                    "SELECT part, count(*), count_if(cls = 'attack'), count_if(cls = 'attempted'), "
                    "list(DISTINCT fam ORDER BY fam) FILTER (WHERE cls = 'attack'), min(ts), max(ts), count(DISTINCT file) "
                    "FROM a GROUP BY part ORDER BY part").fetchall():
                cov_rows.append({"protocol": name, "dataset_family": ds, "partition": r[0], "n_rows": r[1],
                                 "n_attack": r[2], "n_attempted": r[3], "attack_families": json.dumps(r[4] or []),
                                 "min_ts": str(r[5]), "max_ts": str(r[6]), "n_files": r[7],
                                 "primary_evidence": p.get("role", "")})
            con.execute("CREATE OR REPLACE TEMP TABLE tr AS SELECT DISTINCT hx FROM a WHERE part = 'train'")
            # train + val: the usual refit set before the final test evaluation
            con.execute("CREATE OR REPLACE TEMP TABLE tv AS SELECT DISTINCT hx FROM a WHERE part IN ('train', 'val')")
            for part in ("val", "test"):
                q = con.execute(
                    f"SELECT count(*), count_if(hx IN (SELECT hx FROM tr)), count_if(cls = 'attack'), "
                    f"count_if(cls = 'attack' AND hx IN (SELECT hx FROM tr)), count_if(hx IN (SELECT hx FROM tv)), "
                    f"count_if(cls = 'attack' AND hx IN (SELECT hx FROM tv)) FROM a WHERE part = '{part}'").fetchone()
                tvcols = ({"n_rows_seen_in_train_or_val": q[4],
                           "share_seen_in_train_or_val": round(q[4] / q[0], 6) if q[0] else None,
                           "n_attack_seen_in_train_or_val": q[5],
                           "share_attack_seen_in_train_or_val": round(q[5] / q[2], 6) if q[2] else None}
                          if part == "test" else {})
                dup_rows.append({"protocol": name, "dataset_family": ds, "eval_partition": part, "n_rows": q[0],
                                 "n_rows_feature_vector_seen_in_train": q[1],
                                 "share_seen_in_train": round(q[1] / q[0], 6) if q[0] else None,
                                 "n_attack": q[2], "n_attack_seen_in_train": q[3],
                                 "share_attack_seen_in_train": round(q[3] / q[2], 6) if q[2] else None, **tvcols})
                # per attack family: is the family present in train / val, and how many of its
                # evaluation flows have a feature vector already present there
                for r in con.execute(
                        "SELECT fam, count(*), count_if(hx IN (SELECT hx FROM tr)), count_if(hx IN (SELECT hx FROM tv)), "
                        "fam IN (SELECT fam FROM a WHERE part = 'train' AND cls = 'attack'), "
                        "fam IN (SELECT fam FROM a WHERE part = 'val' AND cls = 'attack') "
                        f"FROM a WHERE part = '{part}' AND cls = 'attack' GROUP BY fam ORDER BY fam").fetchall():
                    fam_rows.append({"protocol": name, "dataset_family": ds, "eval_partition": part, "family": r[0],
                                     "n_attack": r[1], "family_in_train": r[4], "family_in_val": r[5],
                                     "n_seen_in_train": r[2], "share_seen_in_train": round(r[2] / r[1], 6),
                                     "n_seen_in_train_or_val": r[3] if part == "test" else "",
                                     "share_seen_in_train_or_val": round(r[3] / r[1], 6) if part == "test" else ""})
            log.info("splits: %s / %s (%.1f s)", name, ds, time.perf_counter() - t0)
    con.close()
    write_csv(out_cov, cov_rows)
    write_csv(out_dup, dup_rows)
    write_csv(out_fam, fam_rows)
    return 0


def cmd_conflicts(root: Path, cfg: dict, overwrite: bool) -> int:
    """Which labels collide in feature-identical groups (improved data, from the hashes table)."""
    import duckdb
    out = root / OUT / "label_conflict_composition.csv"
    guard([out], overwrite)
    con = duckdb.connect(hashes_db().as_posix(), read_only=True)
    d = cfg["duckdb"]
    con.execute(f"SET threads={int(d['threads'])}; SET memory_limit={sql_str(d['memory_limit'])}; "
                f"SET temp_directory={sql_str((cache_root() / 'duckdb_tmp').as_posix())}")
    lab = "CASE WHEN cls = 'attempted' THEN fam || ' - Attempted' ELSE fam END"
    # 1) conflicting groups via cheap min/max aggregates; 2) composition only for the rows in them
    rows = []
    for r in con.execute(
            f"WITH l AS (SELECT dataset, file, hx, {lab} lab FROM h), "
            "c AS (SELECT dataset, hx FROM l GROUP BY dataset, hx HAVING min(lab) <> max(lab)), "
            "m AS (SELECT l.* FROM l SEMI JOIN c ON l.dataset = c.dataset AND l.hx = c.hx), "
            "g AS (SELECT dataset, hx, count(*) n, count(DISTINCT file) nf, list(DISTINCT lab ORDER BY lab) labs, "
            "histogram(lab) hist FROM m GROUP BY dataset, hx) "
            "SELECT dataset, array_to_string(labs, ' | '), count(*), sum(n), max(nf), list(hist), "
            "sum(n - list_max(map_values(hist))) "
            "FROM g GROUP BY 1, 2 ORDER BY 1, 4 DESC").fetchall():
        per_label: dict[str, int] = {}
        for hist in r[5]:
            for k, v in hist.items():
                per_label[k] = per_label.get(k, 0) + int(v)
        rows.append({"dataset_family": r[0], "label_set": r[1], "n_groups": r[2], "n_rows": int(r[3]),
                     "max_files_per_group": r[4], "rows_per_label": json.dumps(per_label, sort_keys=True),
                     # rows any single-label-per-feature-vector classifier must get wrong (minority labels)
                     "n_min_error_rows": int(r[6]),
                     "feature_key": "feature + context_review columns (as duplicates_by_file.csv)"})
    con.close()
    write_csv(out, rows)
    log.info("conflicts: %d label sets", len(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/phase6_leakage.log"))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("separability", "splits", "conflicts"):
        s = sub.add_parser(name)
        s.add_argument("--overwrite", action="store_true")
    sub.add_parser("hashes")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    cfg = load_config()
    t0 = time.perf_counter()
    try:
        if args.cmd == "separability":
            rc = cmd_separability(root, cfg, args.overwrite)
        elif args.cmd == "hashes":
            rc = cmd_hashes(root, cfg)
        elif args.cmd == "conflicts":
            rc = cmd_conflicts(root, cfg, args.overwrite)
        else:
            rc = cmd_splits(root, cfg, args.overwrite)
    except FileExistsError as exc:
        log.error("%s", exc)
        rc = 2
    log.info("=== done rc=%d in %.1f s", rc, time.perf_counter() - t0)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
