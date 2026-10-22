"""Generate (and optionally execute) the audit notebooks 01-06.

The notebooks are thin: they load the saved outputs in results/audit and data/manifests, call
functions from src/audit, and re-check one or two numbers independently. Heavy full scans stay
in the scripts (see README).

Usage (from the project root)
-----------------------------
    python -I src/audit/make_notebooks.py            # write notebooks/*.ipynb
    python -I src/audit/make_notebooks.py --execute  # write and execute in place (kernel python3)
    (add --overwrite to replace existing notebooks; the figure in notebook 05 is never overwritten)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import nbformat
from nbformat.v4 import new_code_cell, new_markdown_cell, new_notebook

ROOT = Path(__file__).resolve().parents[2]
NB_DIR = ROOT / "notebooks"

SETUP = """\
import sys, json
from pathlib import Path
import pandas as pd
ROOT = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(ROOT))
R = ROOT / "results/audit"
M = ROOT / "data/manifests"
pd.set_option("display.max_rows", 80); pd.set_option("display.max_columns", 40); pd.set_option("display.width", 200)
print("project root:", ROOT.name)"""

NOTEBOOKS = {
    "01_dataset_inventory.ipynb": [
        ("md", "# 01 Dataset inventory and acquisition\nLoads the Phase 1 manifests and re-hashes one small file "
               "independently to confirm the checksum manifest. Evidence status of each statement is in "
               "`reports/dataset_provenance.md`."),
        ("code", SETUP),
        ("code", "inv = pd.read_csv(M / 'dataset_inventory.csv')\n"
                 "inv.groupby(['record_type','dataset_family','variant'], dropna=False)['size_bytes'].agg(['count','sum'])"),
        ("code", "ver = pd.read_csv(M / 'acquisition_verification.csv')\n"
                 "print('files verified after extraction/copy:', int(ver['verified'].sum()), 'of', len(ver))\n"
                 "ver[['dest_relpath','size_bytes','verified','n_newline_bytes']]"),
        ("code", "s3 = pd.read_csv(M / 'original_2018_s3_etag_check.csv')\n"
                 "s3[['relpath','size_match','s3_etag','etag_match','s3_last_modified']]"),
        ("code", "# independent re-hash of one improved file, compared with the checksum manifest\n"
                 "from src.audit.inventory import sha256_stream, load_checksums\n"
                 "p = ROOT / 'data/raw_improved/CIC-IDS-2017/friday.csv'\n"
                 "with p.open('rb') as fh:\n    digest, n = sha256_stream(fh)\n"
                 "ck = load_checksums(M / 'checksums_sha256.csv')\n"
                 "expected = ck[('archive_member', 'CICIDS2017_improved.zip', 'friday.csv')]['sha256']\n"
                 "print(digest == expected, n)"),
    ],
    "02_provenance_and_schema.ipynb": [
        ("md", "# 02 Provenance, schema and labels (Phase 2)\nProduced by `python -I src/audit/schema_labels.py scan` "
               "and `derive`. This notebook re-reads every header directly and checks it against the saved schema."),
        ("code", SETUP),
        ("code", "S = json.loads((R / 'schema_by_file.json').read_text(encoding='utf-8'))['files']\n"
                 "pd.DataFrame([{k: s[k] for k in ['relpath','n_columns','n_rows','read_mode','source_encoding','line_ending']}\n"
                 "              | {'lines_not_read': s['newline_check']['lines_not_read_as_rows']} for s in S])"),
        ("code", "# independent check: exact header names re-read from disk == saved schema\n"
                 "from src.audit.common import read_header\n"
                 "bad = [s['relpath'] for s in S if read_header(ROOT / s['relpath'])['names'] != s['header_names_exact']]\n"
                 "print('header mismatches:', bad)"),
        ("code", "L = pd.read_csv(R / 'label_distribution_by_dataset.csv', keep_default_na=False)\n"
                 "L[L.variant == 'improved'][['dataset_family','label','attempted_category','count','proportion']]"),
        ("code", "pd.read_csv(R / 'label_vs_labelling_rules.csv').groupby(['dataset_family','status']).size()"),
        ("code", "pd.read_csv(R / 'schema_diff_original_vs_improved.csv').groupby(['dataset_family','status']).size()"),
    ],
    "03_integrity_audit.ipynb": [
        ("md", "# 03 Integrity audit (Phase 3)\nRead-only. Findings: `results/audit/findings.csv`; report: "
               "`reports/dataset_audit_report.md`. Nothing was repaired or dropped."),
        ("code", SETUP),
        ("code", "F = pd.read_csv(R / 'findings.csv')\nF.groupby(['category','severity']).size().unstack(fill_value=0)"),
        ("code", "F[F.severity.isin(['critical','high'])][['finding_id','dataset_family','variant','scope','column','rule','count','denominator','rate']]"),
        ("code", "D = pd.read_csv(R / 'duplicates_by_file.csv').query(\"scope == 'dataset'\")\n"
                 "D = D.assign(feature_dup_share=D.n_feature_duplicate_rows / D.n_data_rows)\n"
                 "D.set_index(['dataset_family','variant']).T"),
        ("code", "T = pd.read_csv(R / 'timestamp_quality.csv')\n"
                 "T[['file','n_rows','n_parse_failures','min_ts','max_ts','n_duplicate_ts','n_backward_steps_gt_60s','max_gap_sorted_s','n_id_ne_row_order']]"),
        ("code", "pd.read_csv(R / 'label_window_consistency.csv')"),
        ("code", "# independent recount of the all-empty rows in the original 2017 web-attack file (plain bytes)\n"
                 "p = ROOT / 'data/raw_original/CIC-IDS-2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'\n"
                 "n_empty = sum(1 for line in p.open('rb') if line.strip(b'\\r\\n') and not line.strip(b',\\r\\n'))\n"
                 "print('comma-only lines:', n_empty)"),
    ],
    "04_original_vs_improved.ipynb": [
        ("md", "# 04 Original versus improved (Phase 4)\nFile- and distribution-level comparison, plus a row-matching "
               "feasibility test. Report: `reports/original_vs_improved.md`."),
        ("code", SETUP),
        ("code", "pd.read_csv(R / 'original_vs_improved_summary.csv')"),
        ("code", "pd.read_csv(R / 'label_family_comparison.csv')"),
        ("code", "FD = pd.read_csv(R / 'feature_distribution_comparison.csv')\n"
                 "FD[['dataset_family','column','original_q50','improved_q50','rel_change_q50','original_q99','improved_q99','original_nonfinite','improved_nonfinite']].head(40)"),
        ("code", "pd.read_csv(R / 'row_matching_feasibility.csv')[['dataset_family','original_file','improved_file','best_offset_hours_added_to_improved_utc','unique_coverage','ambiguous_share','defensible_for_row_level']]"),
        ("code", "tm = R / 'label_transition_matrix.csv'\n"
                 "t = pd.read_csv(tm)\n"
                 "print(len(t), 'rows') ; t.head(40)"),
    ],
    "05_temporal_structure.ipynb": [
        ("md", "# 05 Temporal structure (Phase 5)\nNo sequence dataset is created. Summaries come from "
               "`python -I src/audit/temporal.py`; the figure below reads the disposable timeline cache."),
        ("code", SETUP),
        ("code", "TF = json.loads((R / 'temporal_feasibility.json').read_text(encoding='utf-8'))\n"
                 "rows = []\n"
                 "for f, v in TF['per_file'].items():\n"
                 "    if v['variant'] != 'improved': continue\n"
                 "    rows.append({'file': f.split('/')[-1], **{k: v[k] for k in ['n_flows','share_bins_empty','longest_empty_run_bins','flows_per_nonempty_bin_p50','file_order_backward_steps_by_start','file_order_backward_steps_by_end','n_duration_gt_window','bins_with_attack_excl_attempted']}})\n"
                 "pd.DataFrame(rows)"),
        ("code", "SEG = pd.read_csv(R / 'attack_segments.csv')\n"
                 "SEG[SEG.gap_threshold_s == 60].groupby('dataset_family').agg(n_segments=('segment','count'), median_lead_s=('lead_since_prev_attack_or_file_start_s','median'))"),
        ("code", "import duckdb, matplotlib\nmatplotlib.use('Agg')\nimport matplotlib.pyplot as plt\n"
                 "from src.audit.integrity import timeline_path\nfrom src.audit.common import DataFile\n"
                 "f = DataFile('CIC-IDS-2017', 'improved', 'data/raw_improved/CIC-IDS-2017/wednesday.csv', ROOT / 'data/raw_improved/CIC-IDS-2017/wednesday.csv')\n"
                 "p = timeline_path(f)\n"
                 "if p.exists():\n"
                 "    d = duckdb.sql(f\"SELECT date_trunc('minute', ts) m, count(*) n, count_if(upper(label) <> 'BENIGN' AND label NOT LIKE '% - Attempted') a FROM read_parquet('{p.as_posix()}') GROUP BY 1 ORDER BY 1\").df()\n"
                 "    fig, ax = plt.subplots(figsize=(11, 3)); ax.plot(d.m, d.n, lw=.8, label='all flows / min'); ax.plot(d.m, d.a, lw=.8, label='attack flows / min'); ax.set_yscale('symlog'); ax.legend(); ax.set_title('CIC-IDS-2017 improved, Wednesday (UTC)')\n"
                 "    out = R / 'figures'; out.mkdir(exist_ok=True); fp = out / 'wednesday_2017_flows_per_minute.png'\n"
                 "    if fp.exists():\n        print('figure exists, not overwritten:', fp.name)\n"
                 "    else:\n        fig.savefig(fp, dpi=120, bbox_inches='tight'); print('saved figure', fp.name)\n"
                 "else:\n    print('timeline cache not present; run src/audit/integrity.py timeline')"),
    ],
    "06_leakage_and_split_design.ipynb": [
        ("md", "# 06 Leakage audit and split design (Phase 6)\nNo model is trained. Protocol: "
               "`configs/evaluation_protocol.yaml`, `reports/evaluation_protocol.md`."),
        ("code", SETUP),
        ("code", "LK = pd.read_csv(R / 'leakage_findings.csv')\nLK.groupby(['category','severity']).size()"),
        ("code", "SP = pd.read_csv(R / 'feature_separability.csv')\n"
                 "SP[SP.variant == 'improved'].sort_values('ovl_benign_vs_attack')[['dataset_family','feature','role','ovl_benign_vs_attack','ovl_attack_vs_attempted']].head(25)"),
        ("code", "pd.read_csv(R / 'split_design_coverage.csv')"),
        ("code", "pd.read_csv(R / 'split_duplicate_leakage.csv')"),
        ("code", "FL = pd.read_csv(R / 'split_family_leakage.csv')\n"
                 "FL[FL.eval_partition == 'test'][['protocol','family','n_attack','family_in_train','family_in_val','share_seen_in_train','share_seen_in_train_or_val']]"),
        ("code", "pd.read_csv(R / 'label_conflict_composition.csv').groupby('dataset_family').head(5)"),
    ],
}


def build(names: list[str], overwrite: bool) -> list[Path]:
    NB_DIR.mkdir(exist_ok=True)
    existing = [n for n in names if (NB_DIR / n).exists()]
    if existing and not overwrite:
        raise FileExistsError(f"notebooks exist (use --overwrite): {', '.join(existing)}")
    paths = []
    for name in names:
        cells = NOTEBOOKS[name]
        nb = new_notebook(cells=[new_markdown_cell(s) if k == "md" else new_code_cell(s) for k, s in cells],
                          metadata={"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"}})
        p = NB_DIR / name
        nbformat.write(nb, p)
        paths.append(p)
    return paths


def execute(paths: list[Path]) -> int:
    from nbclient import NotebookClient
    failures = 0
    for p in paths:
        t0 = time.perf_counter()
        nb = nbformat.read(p, as_version=4)
        try:
            NotebookClient(nb, timeout=900, kernel_name="python3", resources={"metadata": {"path": str(NB_DIR)}}).execute()
            status = "executed OK"
        except Exception as exc:  # keep the partially executed notebook so the error is visible
            status = f"FAILED: {type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
            failures += 1
        nbformat.write(nb, p)
        print(f"{p.name}: {status} ({time.perf_counter() - t0:.1f} s)", flush=True)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--only", nargs="+")
    ap.add_argument("--overwrite", action="store_true", help="replace existing notebooks")
    args = ap.parse_args(argv)
    names = [n for n in NOTEBOOKS if not args.only or any(o in n for o in args.only)]
    try:
        paths = build(names, args.overwrite)
    except FileExistsError as exc:
        print(exc)
        return 2
    print("wrote", ", ".join(p.name for p in paths))
    return execute(paths) if args.execute else 0


if __name__ == "__main__":
    raise SystemExit(main())
