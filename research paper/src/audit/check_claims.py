"""Self-review: do the reports quote the numbers the result tables contain?

Each claim recomputes a headline number from results/audit (or results/literature), formats it the
way the report writes it, and checks that this exact text occurs in the named report. A mismatch
means a report drifted from the data (or the data changed after the report was written).

Usage (from the project root)
    python -I src/audit/check_claims.py [--overwrite]   ->  results/audit/report_claims_check.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
R = ROOT / "results/audit"
OUT = R / "report_claims_check.csv"


def rc(name: str, base: Path = R) -> pd.DataFrame:
    return pd.read_csv(base / name, keep_default_na=False)


def rj(name: str) -> dict:
    return json.loads((R / name).read_text(encoding="utf-8"))


def n(x) -> str:
    return f"{int(x):,}"


def pct(x, d=2) -> str:
    return f"{100 * x:.{d}f}%"


def claims() -> list[tuple[str, str, str]]:
    """(claim, report, exact text that must appear in the report)."""
    S = rj("schema_by_file.json")["files"]
    rows = {}
    for s in S:
        k = (s["dataset_family"], s["variant"])
        rows[k] = rows.get(k, 0) + s["n_rows"]
    D = rc("duplicates_by_file.csv")
    D = D[D.scope == "dataset"].set_index(["dataset_family", "variant"])
    share = {k: int(D.loc[k, "n_feature_duplicate_rows"]) / int(D.loc[k, "n_data_rows"]) for k in D.index}
    LW = rc("label_window_consistency.csv")
    C = rc("label_conflict_composition.csv")
    floor = C.groupby("dataset_family")["n_min_error_rows"].sum()
    SP = rc("split_duplicate_leakage.csv")
    p0 = SP[(SP.protocol == "P0_random_rows") & (SP.eval_partition == "test")].set_index("dataset_family")
    SEG = rc("attack_segments.csv")
    seg = SEG[SEG.gap_threshold_s == 300].groupby("dataset_family").size()
    TF = rj("temporal_feasibility.json")["per_file"]
    pers, longs = {}, []
    for f, v in TF.items():
        if v["variant"] != "improved":
            continue
        longs.append(v["n_duration_gt_window"] / v["n_flows"])
        for h, x in v["next_window_target_excl_attempted"].items():
            a = pers.setdefault((v["dataset_family"], h), [0, 0])
            a[0] += x["n_persistent (attack now and at t+h)"]
            a[1] += x["n_positive_target"]
    ps = {ds: [pers[(ds, h)][0] / pers[(ds, h)][1] for h in "12345"] for ds in ("CIC-IDS-2017", "CSE-CIC-IDS-2018")}
    F = rc("findings.csv")
    cap = sum(1 for s in S if s["variant"] == "original" and s["n_rows"] == 1048575)
    SEP = rc("feature_separability.csv")
    ovl = SEP[(SEP.variant == "improved") & (SEP.feature == "Dst Port")].set_index("dataset_family")["ovl_benign_vs_attack"]
    COV = rc("split_design_coverage.csv")
    p1b = COV[(COV.protocol == "P1b_within_day_flow_quantile")].set_index(["dataset_family", "partition"])
    M = rc("row_matching_feasibility.csv").set_index("original_file")
    T = rc("timestamp_quality.csv")
    stray = int(T[T.file.str.endswith("CSE-CIC-IDS-2018/Friday-23-02-2018.csv")].n_date_mismatch_filename.iloc[0])
    L = rc("citing_works_screened.csv", ROOT / "results/literature")
    i17, i18, o17, o18 = (("CIC-IDS-2017", "improved"), ("CSE-CIC-IDS-2018", "improved"),
                          ("CIC-IDS-2017", "original"), ("CSE-CIC-IDS-2018", "original"))
    A = "reports/dataset_audit_report.md"
    E = "reports/evaluation_protocol.md"
    O = "reports/original_vs_improved.md"
    TP = "reports/temporal_feasibility.md"
    LR = "reports/literature_review.md"
    return [
        ("2017 improved rows", A, n(rows[i17])),
        ("2018 improved rows", A, n(rows[i18])),
        ("2017 original rows", A, n(rows[o17])),
        ("2018 original rows", A, n(rows[o18])),
        ("2017 original data rows", A, n(D.loc[o17, "n_data_rows"])),
        ("2017 original empty rows", A, n(D.loc[o17, "n_all_empty_rows"])),
        ("2018 original data rows", A, n(D.loc[o18, "n_data_rows"])),
        ("attack + Attempted flows inside windows", A, n(pd.to_numeric(LW.n_flows).sum())),
        ("feature-identical share 2017 improved", A, pct(share[i17])),
        ("feature-identical share 2018 improved", A, pct(share[i18])),
        ("feature-identical share 2017 original", A, pct(share[o17])),
        ("feature-identical share 2018 original", A, pct(share[o18])),
        ("conflict rows 2018 improved", A, n(D.loc[i18, "n_rows_in_label_conflict_groups"])),
        ("conflict rows 2018 original", A, n(D.loc[o18, "n_rows_in_label_conflict_groups"])),
        ("conflict floor 2017", A, n(floor["CIC-IDS-2017"]) + " rows"),
        ("conflict floor 2018", A, n(floor["CSE-CIC-IDS-2018"]) + " rows"),
        ("P0 test rows seen in train 2017 / 2018", A,
         f"{100 * p0.loc['CIC-IDS-2017', 'share_seen_in_train']:.1f}% (2017) and "
         f"{100 * p0.loc['CSE-CIC-IDS-2018', 'share_seen_in_train']:.1f}% (2018)"),
        ("episodes at 300 s", A, f"**24 (2017) and 38 (2018) attack episodes**" if (seg["CIC-IDS-2017"], seg["CSE-CIC-IDS-2018"]) == (24, 38) else f"{seg.to_dict()}"),
        ("persistence share 2017 range", TP, f"{100 * min(ps['CIC-IDS-2017']):.0f}–{100 * max(ps['CIC-IDS-2017']):.0f}% in 2017"),
        ("persistence share 2018 range", TP, f"{100 * min(ps['CSE-CIC-IDS-2018']):.0f}–{100 * max(ps['CSE-CIC-IDS-2018']):.0f}% in 2018"),
        ("long-flow share range, all improved files", A, f"{100 * min(longs):.0f}–{100 * max(longs):.0f}% of flows last longer than a 2 s window"),
        ("number of findings", A, f"**{len(F)} findings**"),
        ("capped 2018 original files", A, f"{cap} of 10 2018 original files"),
        ("stray rows Friday-23-02", A, n(stray) + " flows dated 21–22 Feb"),
        ("Dst Port OVL 2018 / 2017 improved", E, f"OVL is {ovl['CSE-CIC-IDS-2018']:.3f} (2018) and {ovl['CIC-IDS-2017']:.3f} (2017)"),
        ("P1b test attacks 2017", E, n(p1b.loc[("CIC-IDS-2017", "test"), "n_attack"])),
        ("P1b test attacks 2018", E, n(p1b.loc[("CSE-CIC-IDS-2018", "test"), "n_attack"])),
        ("P1b embargoed attack flows 2018", E, n(p1b.loc[("CSE-CIC-IDS-2018", "embargo"), "n_attack"])),
        ("Thuesday unique match", O, f"{M.loc['Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv', 'unique_coverage']:.3f}"),
        ("PortScan unique match", O, f"**{M.loc['Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', 'unique_coverage']:.3f}**"),
        ("unique citing works", LR, f"**{len(L)} unique citing works**"),
        ("citing CNS2022 / Engelen 2021", LR, f"**{int(L.cites.str.contains('CNS2022').sum())}** | **{int(L.cites.str.contains('Engelen2021').sum())}**"),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    if OUT.exists() and not a.overwrite:
        print(f"refusing to overwrite {OUT} (pass --overwrite)")
        return 2
    out = []
    for claim, report, text in claims():
        found = text in (ROOT / report).read_text(encoding="utf-8")
        out.append({"claim": claim, "report": report, "expected_text": text, "found_in_report": found})
        print(("OK   " if found else "MISS ") + f"{claim}: '{text}' in {report}")
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)
    miss = sum(not r["found_in_report"] for r in out)
    print(f"{len(out)} claims, {miss} not found verbatim")
    return 1 if miss else 0


if __name__ == "__main__":
    sys.exit(main())
