"""Phase 5: temporal feasibility analysis (read-only; uses the Phase 3 timeline cache).

No sequence dataset is materialised. Per-window label counts are aggregated in DuckDB and only
summaries are written to results/audit/.

Analyses per file
-----------------
* row order: does file order follow flow START (Timestamp) or flow END (Timestamp + Flow Duration)?
  (evidence for what Timestamp means)
* timestamp granularity: sub-second share, ties
* 2-second window viability: bins in span, empty bins, longest empty run, flows per bin,
  flows longer than one window
* attack episodes ("segments"): contiguous runs of a label family separated by > GAP_S seconds,
  benign lead time before each onset, censoring at file start
* next-window target prevalence for horizons 1..5 (2 s steps): share of windows whose future
  window contains attack flows, and the number of benign->attack transitions (onsets)

Usage (from the project root)
-----------------------------
    python -I src/audit/temporal.py [--overwrite]
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
from src.audit.common import PROJECT_ROOT, discover_data_files, duckdb_connect, load_config, sql_str  # noqa: E402
from src.audit.integrity import timeline_path, write_csv  # noqa: E402
from src.audit.inventory import now_utc, setup_logging  # noqa: E402

TOOL = "src/audit/temporal.py"
OUT = Path("results/audit")
WINDOW_S = 2
GAPS_S = (60, 300)
HORIZONS = (1, 2, 3, 4, 5)
MAX_GRID_BINS = 200_000  # ~4.6 days of 2 s bins; larger spans indicate stray timestamps
log = logging.getLogger("inventory")

# label family = label without the " - Attempted" suffix; attack = not BENIGN (case-insensitive)
FAMILY = "regexp_replace(label, ' - Attempted$', '')"
IS_ATTEMPTED = "(label LIKE '% - Attempted')"
IS_BENIGN = "(upper(trim(label)) = 'BENIGN')"


def file_analysis(con, src: str, cfg: dict) -> dict:
    r = {}
    # --- row order vs start / end time ------------------------------------------------------
    o = con.execute(
        f"SELECT count(*), count_if(ts < pts), count_if(te < pte), count_if(ts < pts - INTERVAL 60 SECOND), "
        f"count_if(te < pte - INTERVAL 60 SECOND) FROM (SELECT ts, te, lag(ts) OVER w pts, lag(te) OVER w pte FROM "
        f"(SELECT rn, ts, ts + to_microseconds(coalesce(flow_duration, 0)) te FROM {src} WHERE ts IS NOT NULL) "
        f"WINDOW w AS (ORDER BY rn))").fetchone()
    r["n_flows"] = o[0]
    r["file_order_backward_steps_by_start"] = o[1]
    r["file_order_backward_steps_by_end"] = o[2]
    r["file_order_backward_steps_by_start_gt60s"] = o[3]
    r["file_order_backward_steps_by_end_gt60s"] = o[4]
    # --- granularity ---------------------------------------------------------------------------
    g = con.execute(
        f"SELECT count_if(microsecond(ts) % 1000000 <> 0), count(DISTINCT ts), min(ts), max(ts), "
        f"count_if(flow_duration > {WINDOW_S}*1000000), count_if(flow_duration > {cfg['flow_timeout_us']}), "
        f"count_if(flow_duration > {WINDOW_S}*1000000 AND NOT {IS_BENIGN}), count_if(NOT {IS_BENIGN}), "
        f"count_if({IS_ATTEMPTED}) FROM {src} WHERE ts IS NOT NULL").fetchone()
    r.update({"n_with_subsecond": g[0], "n_distinct_ts": g[1], "min_ts": str(g[2]), "max_ts": str(g[3]),
              "n_duration_gt_window": g[4], "n_duration_gt_flow_timeout": g[5],
              "n_attack_duration_gt_window": g[6], "n_non_benign": g[7], "n_attempted": g[8]})
    # --- 2 s bins ------------------------------------------------------------------------------
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE bins AS SELECT CAST(floor(epoch(ts) / {WINDOW_S}) AS BIGINT) b, count(*) n, "
        f"count_if(NOT {IS_BENIGN} AND NOT {IS_ATTEMPTED}) n_attack, count_if({IS_ATTEMPTED}) n_attempted "
        f"FROM {src} WHERE ts IS NOT NULL GROUP BY 1")
    b = con.execute(
        "SELECT min(b), max(b), count(*), quantile_cont(n, 0.5), quantile_cont(n, 0.95), max(n), "
        "count_if(n_attack > 0), count_if(n_attack > 0 OR n_attempted > 0) FROM bins").fetchone()
    span_bins = b[1] - b[0] + 1
    runs = con.execute(
        "SELECT max(gap) - 1, count_if(gap - 1 >= 30), count_if(gap - 1 >= 150) FROM "
        "(SELECT b - lag(b) OVER (ORDER BY b) gap FROM bins)").fetchone()
    r.update({"bins_in_span": span_bins, "bins_nonempty": b[2], "share_bins_empty": round(1 - b[2] / span_bins, 6),
              "longest_empty_run_bins": runs[0] or 0, "n_empty_runs_ge_60s": runs[1], "n_empty_runs_ge_300s": runs[2],
              "flows_per_nonempty_bin_p50": b[3], "flows_per_nonempty_bin_p95": b[4], "flows_per_bin_max": b[5],
              "bins_with_attack_excl_attempted": b[6], "bins_with_attack_incl_attempted": b[7]})
    # --- next-window prevalence on the FULL bin grid (empty bins count as benign) --------------
    hz = {}
    if span_bins > MAX_GRID_BINS:
        r["next_window_target_excl_attempted"] = {
            "skipped": f"span of {span_bins} bins exceeds {MAX_GRID_BINS}; stray timestamps (see timestamp_quality.csv)"}
        return r
    for h in HORIZONS:
        q = con.execute(
            f"WITH grid AS (SELECT g.b, coalesce(bins.n_attack, 0) > 0 AS a FROM range({b[0]}, {b[1]} + 1) g(b) "
            f"LEFT JOIN bins ON bins.b = g.b), s AS (SELECT a, lead(a, {h}) OVER (ORDER BY b) fa FROM grid) "
            f"SELECT count(fa), count_if(fa), count_if(fa AND NOT a), count_if(fa AND a) FROM s").fetchone()
        hz[str(h)] = {"n_windows_with_target": q[0], "n_positive_target": q[1],
                      "n_onset_like (benign now, attack at t+h)": q[2], "n_persistent (attack now and at t+h)": q[3],
                      "positive_rate": round(q[1] / q[0], 6) if q[0] else None}
    r["next_window_target_excl_attempted"] = hz
    return r


def segments(con, src: str, file: str, family_rows: list, gap_s: int) -> list[dict]:
    rows = con.execute(
        f"WITH a AS (SELECT {FAMILY} fam, ts FROM {src} WHERE ts IS NOT NULL AND NOT {IS_BENIGN} AND NOT {IS_ATTEMPTED}), "
        f"s AS (SELECT fam, ts, CASE WHEN epoch(ts) - epoch(lag(ts) OVER (PARTITION BY fam ORDER BY ts)) > {gap_s} "
        f"OR lag(ts) OVER (PARTITION BY fam ORDER BY ts) IS NULL THEN 1 ELSE 0 END brk FROM a), "
        f"k AS (SELECT fam, ts, sum(brk) OVER (PARTITION BY fam ORDER BY ts ROWS UNBOUNDED PRECEDING) seg FROM s) "
        f"SELECT fam, seg, min(ts), max(ts), count(*) FROM k GROUP BY 1, 2 ORDER BY 3").fetchall()
    fmin = con.execute(f"SELECT min(ts) FROM {src} WHERE ts IS NOT NULL").fetchone()[0]
    out, prev_end = [], None
    for fam, seg, t0, t1, n in rows:
        lead_ref = prev_end if prev_end and prev_end < t0 else fmin
        lead = (t0 - lead_ref).total_seconds()
        out.append({"file": file, "gap_threshold_s": gap_s, "label_family": fam, "segment": seg, "start": str(t0),
                    "end": str(t1), "duration_s": round((t1 - t0).total_seconds(), 3), "n_attack_flows": n,
                    "lead_since_prev_attack_or_file_start_s": round(lead, 3),
                    "lead_windows_2s": int(lead // WINDOW_S),
                    "censored_at_file_start": (t0 - fmin).total_seconds() < 120,
                    "overlaps_previous_segment": bool(prev_end and t0 <= prev_end)})
        prev_end = max(prev_end, t1) if prev_end else t1
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=PROJECT_ROOT)
    p.add_argument("--log", type=Path, default=Path("logs/phase5_temporal.log"))
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    setup_logging(args.log if args.log.is_absolute() else root / args.log)
    log.info("=== %s %s", TOOL, " ".join(sys.argv[1:] if argv is None else argv))
    out_json, out_seg = root / OUT / "temporal_feasibility.json", root / OUT / "attack_segments.csv"
    for o in (out_json, out_seg):
        if o.exists() and not args.overwrite:
            log.error("refusing to overwrite %s (pass --overwrite)", o)
            return 2
    cfg = load_config()
    con = duckdb_connect(cfg)
    per_file, segs = {}, []
    for f in discover_data_files(cfg, root):
        t0 = time.perf_counter()
        src = f"read_parquet({sql_str(timeline_path(f).as_posix())})"
        res = file_analysis(con, src, cfg)
        res.update({"dataset_family": f.dataset_family, "variant": f.variant})
        per_file[f.relpath] = res
        if f.variant == "improved":
            for gap in GAPS_S:
                segs.extend({"dataset_family": f.dataset_family, **s}
                            for s in segments(con, src, Path(f.relpath).name, [], gap))
        log.info("temporal: %s (%.1f s)", f.relpath, time.perf_counter() - t0)
    con.close()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps({"generated_at_utc": now_utc(), "tool": TOOL, "window_s": WINDOW_S,
                                    "segment_gap_thresholds_s": GAPS_S, "horizons_windows": HORIZONS,
                                    "per_file": per_file}, indent=1, default=str), encoding="utf-8")
    write_csv(out_seg, segs)
    log.info("=== done: %d files, %d segments", len(per_file), len(segs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
