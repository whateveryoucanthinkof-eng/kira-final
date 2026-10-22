# Phase 4: Original versus improved releases

Run 2026-10-19. Code: `src/audit/compare.py`. Outputs in `results/audit/`:

- `original_vs_improved_summary.csv`
- `label_family_comparison.csv`
- `feature_distribution_comparison.csv`
- `row_matching_feasibility.csv`
- `label_transition_matrix.csv`

Evidence labels as in the other reports.

> **Scope rule.** No row-level correction is claimed unless rows are matched by a defensible key with stated coverage (§4). Everything else here is a **file-level or distribution-level** comparison. Its differences mix four things that cannot be separated at this level:
>
> 1. relabelling;
> 2. flow re-segmentation by the fixed CICFlowMeter;
> 3. rows dropped before export;
> 4. for 2018, truncation of the original files.

## 1. Headline comparison (VERIFIED counts)

| | CIC-IDS-2017 original | CIC-IDS-2017 improved | CSE-CIC-IDS-2018 original | CSE-CIC-IDS-2018 improved |
|---|---:|---:|---:|---:|
| Files | 8 | 5 | 10 | 10 |
| Flows (excluding empty and header rows) | 2,830,743 | 2,099,976 (−25.8%) | 16,232,943 (capped: 7 files at 1,048,575 rows) | 63,195,145 |
| Columns | 85 | 91 | 80 / 84 | 91 |
| Timestamp | local time **UTC−3**, 12-hour clock without AM/PM, minute resolution (Monday: seconds) | UTC, microseconds | local time **UTC−4**, 12-hour clock without AM/PM, second resolution; 14 values in 1970 | UTC, microseconds |
| Non-finite `Flow Bytes/s` | 2,867 | 5 | 95,760 | 57 |
| Negative values in non-negative columns (cells) | durations, IATs, rates, header lengths | only the int16 header-length overflow (§3.3) | durations, IATs | only the int16 header-length overflow |
| Constant (all-zero) columns | 8 (all 6 Bulk features, Bwd PSH, Bwd URG) | none | 8 (same) | `Bwd URG Flags` |

### 1.1 Duplicates and label conflicts (`duplicates_by_file.csv`; data rows only)

Counts are copies beyond the first. They exclude all-empty rows and repeated header rows.

| | 2017 original | 2017 improved | 2018 original | 2018 improved |
|---|---:|---:|---:|---:|
| Exact duplicate rows | 203 | 0 | 433,195 | 0 |
| Feature-identical rows (no identifiers, timestamp or labels) | 308,848 (10.91%) | 263,004 (12.52%) | 4,265,470 (26.28%) | 17,994,469 (28.47%) |
| Rows in groups with more than one label | 7,018 | 14,140 | 423,290 | 263,772 |
| … of which benign versus non-benign | 7,018 | 22 | 170,766 | 263,772 |

**Reading the table (VERIFIED counts).**

- **Exact duplicates disappear in the improved releases.** They contain microsecond timestamps.
- **The feature-identical share barely moves:** +1.6 points for 2017, +2.2 for 2018. The corrections did not make flows more distinct.
- **The conflict type changes.**
  - In the 2017 original, every conflict is benign versus attack. In 2017 improved, almost all are between non-benign labels.
  - In 2018 improved, all 263,772 conflicting rows are benign versus non-benign, concentrated in 13 groups.
  - The groups' composition is in `results/audit/label_conflict_composition.csv` and `reports/dataset_audit_report.md` §6.1.
- **One caveat on the earlier figure.** A first version of this table counted the 288,602 empty rows of the 2017 original as duplicates, which gave 19.15%. The step was corrected and re-run (`reports/WORK_LOG.md`).

## 2. Labels by attack family (`label_family_comparison.csv`; configs/label_family_map.yaml)

The ratio is (improved non-Attempted + Attempted) / original. **These are count comparisons, not row correspondences.**

| Dataset | Family | Original | Improved (non-Attempted) | Improved Attempted | Ratio |
|---|---|---:|---:|---:|---:|
| 2017 | dos_hulk | 231,073 | 158,468 | 581 | 0.69 |
| 2017 | ddos_loic | 128,027 | 95,144 | 0 | 0.74 |
| 2017 | portscan | 158,930 | 159,066 | 0 | 1.00 |
| 2017 | ftp_bruteforce | 7,938 | 3,972 | 12 | **0.50** |
| 2017 | ssh_bruteforce | 5,897 | 2,961 | 27 | **0.51** |
| 2017 | dos_slowhttptest | 5,499 | 1,740 | 3,368 | 0.93 (0.32 non-Attempted) |
| 2017 | dos_slowloris | 5,796 | 3,859 | 1,847 | 0.98 (0.67 non-Attempted) |
| 2017 | botnet | 1,966 | 736 | 4,067 | 2.44 (0.37 non-Attempted) |
| 2017 | web_bruteforce | 1,507 | 73 | 1,292 | 0.91 (**0.05** non-Attempted) |
| 2017 | web_xss | 652 | 18 | 655 | 1.03 (**0.03** non-Attempted) |
| 2017 | infiltration | 36 | 71,803 | 45 | ≈1,996: new `Infiltration - Portscan` class |
| 2017 | benign | 2,273,097 | 1,582,566 | — | 0.70 |
| 2018 | ssh_bruteforce | 187,589 | 94,197 | 0 | **0.50** |
| 2018 | ddos_loic_http | 576,191 | 289,328 | 0 | **0.50** |
| 2018 | botnet | 286,191 | 142,921 | 262 | **0.50** |
| 2018 | web_xss | 230 | 113 | 4 | **0.51** |
| 2018 | infiltration | 161,934 | 89,663 | 28 | 0.55 |
| 2018 | dos_goldeneye | 41,508 | 22,560 | 4,301 | 0.65 |
| 2018 | ftp_bruteforce | 193,360 | **0** | 298,874 | 1.55 (all Attempted, cat. 1 "port closed") |
| 2018 | dos_slowhttptest | 139,890 | **0** | 0 | no counterpart (DOCUMENTED as FTP attempts) |
| 2018 | dos_hulk, ddos_hoic, benign | 461,912 / 686,012 / 13.5M | 1.80M / 1.08M / 59.4M | | **confounded by the capped originals** |

### Interpretation (with evidence levels)

**Halving (HYPOTHESIS, strongly supported).**

- Several families shrink to **0.50–0.51** of their original count, in both datasets: SSH, FTP, LOIC-HTTP, botnet, XSS (2018).
- A factor of almost exactly ½ fits **each TCP connection having produced two flows** in the original CICFlowMeter: the main flow, plus a "TCP appendix" flow started after the first FIN. The fork merges them, because it terminates a flow only after a mutual FIN exchange. This fix is **DOCUMENTED** in Engelen et al. (2021) and on the release page.
- The feature evidence in §3 points the same way: far fewer flows without backward packets, and more FIN flags per flow.

**"Attempted" absorbs much of the web and DoS-slow classes (VERIFIED counts).** In the 2017 improved release, only 5% of web brute-force and 3% of XSS flow counts remain non-Attempted. This agrees with the paper's Table III corruption rates (95.16% and 94.48%, **DOCUMENTED**).

**2018 originals cannot support count comparisons.** The original 2018 files are capped at the Excel limit (7 of 10 files). Ratios for high-volume families (benign, DoS Hulk, HOIC) therefore mostly reflect the truncation.

## 3. Feature distributions (dataset-level; `feature_distribution_comparison.csv`)

### 3.1 Changes consistent with the documented fixes (VERIFIED values; DOCUMENTED cause)

| Feature | 2017 orig → impr | 2018 orig → impr | Consistent with |
|---|---|---|---|
| Share of flows with 0 backward packets | 14.5% → 2.6% | 25.5% → 1.2% | appendix flows merged (FIN termination) |
| `FIN Flag Count` q99 | 1 → 3.1 | 0 → 2 | flows now contain the full FIN exchange |
| `Flow Duration` median | 32 ms → 64 ms | 22 ms → 141 ms | longer, merged flows |
| `Flow Duration` minimum | −13 µs → 0 | −9.19×10¹¹ µs → 0 | `pcapfix` + `reordercap` (README) |
| `Down/Up Ratio`: share of zeros | 33.6% → 2.6% | 52.2% → 1.3% | fewer one-directional flows |
| `RST Flag Count` q99 | 0 → 3 | 1 → 2 | RST now ends flows and is counted (Fwd/Bwd RST added) |
| Bulk features (6 columns) | constant 0 → informative | constant 0 → informative | the Bulk fix |
| Non-finite rates | 2,867 → 5 | 95,760 → 57 | zero-duration flows reduced; Infinity rows dropped at export |

### 3.2 Changed semantics (do not compare raw values across releases)

- **`FWD/Bwd Init Win Bytes`.** The original uses `−1` for "not observed" (1.0M and 1.4M rows in 2017; 4.4M and 8.3M in 2018). The improved release has **no −1 at all**, and the share of zeros rises to 40–61%. HYPOTHESIS: the fork encodes "not observed" as 0. UNRESOLVED until the fork's source is checked.
- **`Timestamp`.** It moves from local time without a timezone, on a 12-hour clock without AM/PM (both datasets), to UTC with microseconds. **VERIFIED** offsets: 2017 originals = UTC−3; 2018 original = UTC−4 (§4).

### 3.3 A new defect in the improved release (VERIFIED range; DOCUMENTED cause)

- **Range.** `Fwd Header Length` and `Bwd Header Length` lie **entirely within the int16 range [−32,768, 32,767]**: maximum 32,764 and minimum −32,768 in 2018. Negative values occur in 309 and 472 rows (2017) and 10,039 and 17,509 rows (2018).
- **Comparison.** The original releases reach 4,644,908 and 5,838,440 (2017, Fwd and Bwd) and 2,477,032 and 2,462,372 (2018) for the same features.
- **Cause.** The authors' labelling notebooks cast these columns with `astype('int16')` before export. Header lengths above 32,767 bytes therefore **wrapped around**.
- **Hidden corruption.** The negatives are only a **lower bound** on corrupted values, because larger overflows wrap to plausible positive values.
- **Recommendation.** Treat both features as unreliable: exclude them, or recompute them from the PCAPs. This is worth reporting to the dataset authors.

The other int16 casts (`ICMP Code/Type`, range −1 to 13) and the int32 casts (maximum `Flow Duration` 120,000,000 µs) stay within range. **VERIFIED.**

## 4. Row-level matching feasibility (`row_matching_feasibility.csv`)

**Method.**

- **Key:** (src IP, src port, dst IP, dst port, protocol, flow start time) at the original's resolution. The hour is taken modulo 12 for **all** originals, because the code detects from the data that each original file has only hours 1–12.
- **Offset search:** whole-hour offsets from −12 to +12 were tried on a deterministic 5% sample, and the best one was used for the full evaluation.
- **Pre-stated criteria for row-level use:** the original file has 5-tuples, **unique 1:1 coverage ≥ 0.90**, and **ambiguity ≤ 0.02**.

| Original file(s) | Offset (h) | Original rows | Unique 1:1 | Ambiguous | Meets criteria |
|---|---:|---:|---:|---:|---|
| 2017 Monday | −3 | 529,918 | 0.728 | 0.000 | no |
| 2017 Tuesday | −3 | 445,909 | 0.795 | 0.001 | no |
| 2017 Wednesday | −3 | 692,703 | 0.865 | 0.001 | no |
| 2017 Thu-Morning-WebAttacks | −3 | 170,366 | 0.807 | 0.000 | no |
| 2017 Thu-Afternoon-Infilteration | −3 | 288,602 | 0.823 | 0.025 | no |
| 2017 Fri-Morning | −3 | 191,033 | 0.816 | 0.003 | no |
| **2017 Fri-Afternoon-PortScan** | −3 | 286,467 | **0.914** | 0.003 | **yes** |
| 2017 Fri-Afternoon-DDos | −3 | 225,745 | 0.798 | 0.013 | no |
| 2018 `Thuesday-20-02` (has 5-tuples) | **−4** | 7,948,748 | 0.783 | 0.001 | no |
| 2018, the other 9 days (only dst port and protocol) | −4 | 5% samples | ≤ 0.047 | 0.57–0.90 | no: key too weak |

**Findings.**

- **Original clocks (VERIFIED).** The original clocks are **UTC−3** (2017) and **UTC−4** (2018, from the one day that has 5-tuples). **Both** use a 12-hour clock without AM/PM.
  - Modulo 12 h, an offset and the same offset +12 h differ only through the date. The scan still separates them clearly: −3 matches 0.729 of the sample and +9 matches 0.336 (2017 Monday); −4 matches 0.783 and +8 matches 0.352 (2018 Tuesday).
  - A first run treated the 2018 clock as 24-hour and matched only 0.419 of the Tuesday rows (the morning half). The correction is logged in `reports/WORK_LOG.md`.
- **2017 is not row-alignable at scale.** 9–27% of each day's original flows have **no** counterpart, which is expected when appendix flows disappear and flows are re-segmented. Unmatched flows are exactly where the corrections act, so even matched-subset statistics would be biased toward unchanged flows.
- **2018 is not row-alignable.** Nine of the ten original files lack IPs and source ports. The day that has them matches 78.3% uniquely, below the pre-stated 0.90.
- **The single day pair that meets the criteria is 2017 Friday-afternoon PortScan.** Its matched transitions are in `label_transition_matrix.csv`:

| Original label | Improved label | Uniquely matched flows |
|---|---|---:|
| PortScan | Portscan | 158,702 |
| PortScan | BENIGN | 13 |
| BENIGN | BENIGN | 103,009 |
| BENIGN | Botnet - Attempted | 5 |

These transitions cover **91.4%** of that file's rows. They must **not** be generalised to other days or classes. Per-row correction effects elsewhere are **UNRESOLVED** at the row level, and only the distribution-level evidence above is available.

## 5. Consequences for the research design

1. **Temporal modelling must use the improved release.** Only the improved release has full days with sub-second UTC timestamps. The originals have minute resolution (2017) or truncated days (2018).
2. **An original-versus-improved temporal comparison (hypothesis H1) is feasible only for 2017, at ≥ 60 s windows.** The conversion to UTC is:
   - hours 1–7 → 13–19, and hours 8–12 unchanged (the capture runs about 08:00–18:00 local);
   - then add 3 h.

   The offset is VERIFIED. The AM/PM assignment is consistent with the improved day spans (`configs/experiment_matrix.yaml` E3).
3. **Exclude or treat with care:** the header-length features (int16 overflow) and the Init-Win-Bytes sentinel.
4. **Report the "Attempted" policy explicitly.** It changes the size of several attack classes by up to 20×.
