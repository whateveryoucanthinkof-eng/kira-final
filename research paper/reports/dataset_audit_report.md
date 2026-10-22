# Dataset audit report: CNS2022 improved CIC-IDS-2017 and CSE-CIC-IDS-2018

Prepared 2026-10-19. **Start here.**

This report has two parts:

1. **§1–2:** an executive summary of the whole audit (Phases 1–7).
2. **§3 onward:** the detailed Phase 3 integrity audit.

Detail for the other phases is in separate reports:

| Topic | Report |
|---|---|
| Provenance, release identity, row counts | `reports/dataset_provenance.md` |
| Schema, types, labels, labelling rules | `reports/schema_and_labels.md` |
| Original versus improved | `reports/original_vs_improved.md` |
| Time semantics, windows, episodes, targets | `reports/temporal_feasibility.md` |
| Leakage audit and split design | `reports/evaluation_protocol.md` |
| Hypotheses and experiments | `reports/research_questions.md` |
| Scoping literature check | `reports/literature_review.md` |
| Independent recomputation, claim check, open decisions | `reports/self_review.md` |
| Everything done, in order, with errors | `reports/WORK_LOG.md` |

**Evidence labels.**

- **VERIFIED**: measured on the local files by a command recorded in the README or WORK_LOG.
- **DOCUMENTED**: stated by the dataset authors.
- **HYPOTHESIS**: plausible, not tested.
- **UNRESOLVED**: missing or conflicting evidence.

**What this report does not do.**

- Nothing was repaired, dropped or re-labelled; the audit only measures.
- No model was trained. Phase 8 waits for the user's review.

---

## 1. What was audited

| Release | Files | Rows read | Data rows | Read check |
|---|---:|---:|---:|---|
| CIC-IDS-2017 improved (CNS2022, April 2023 files) | 5 | 2,099,976 | 2,099,976 | strict read; every newline accounted for |
| CSE-CIC-IDS-2018 improved (CNS2022, March–April 2023 files) | 10 | 63,195,145 | 63,195,145 | strict read; every newline accounted for |
| CIC-IDS-2017 original (`*.pcap_ISCX.csv`) | 8 | 3,119,345 | 2,830,743 (+288,602 all-empty rows) | strict read; cp1252 file transcoded in a cache |
| CSE-CIC-IDS-2018 original (AWS "Processed Traffic Data for ML") | 10 | 16,233,002 | 16,232,943 (+59 repeated header rows) | strict read; mixed-EOL file normalised in a cache |

**Method (VERIFIED).**

- Every number comes from **full scans**, not samples. DuckDB 1.5.6 was used with every column read as text and an explicit column list.
- Row counts were cross-checked against byte-level newline counts.
- Format problems were handled in a disposable cache under the OS temp directory; the raw files themselves were never touched:
  - one file not valid UTF-8 → transcoded from cp1252;
  - one file with mixed line endings → normalised to LF.
- Every cache transform is listed in `data/manifests/encoding_transcode_manifest.csv`.

## 2. Executive summary

Each finding gives its evidence label and where to look.

### Provenance

1. **The improved files are the official CNS2022 release, in its post-publication form** (VERIFIED). Sizes equal the server's, and all CRCs pass. The archive dates match the authors' fix commits of 2023-03-30, 2023-04-03 and 2023-04-27. **These are not the exact files behind the paper's tables.** Name the release precisely in any publication, because LycoS-IDS2017 and other corrected versions also exist.
2. **The 2018 originals are byte-identical to the AWS Open Data objects** (VERIFIED by 10/10 recomputed S3 ETags). The **2017 originals' identity is UNRESOLVED**, but their non-empty row count equals the paper's published count (2,830,743).

### Labels and time

3. **Labels follow the authors' code exactly** (VERIFIED). All **4,359,069** attack and Attempted flows fall inside a documented labelling window for their label, category and day. 0 data labels lack a rule.
4. **Improved timestamps are UTC with microseconds** (DOCUMENTED; consistency VERIFIED). **Rows are not in time order** in any file, and `id` is just the export row number. Always sort by `Timestamp` within a file.
5. **Both original releases use a 12-hour clock without AM/PM** (VERIFIED: every parsed hour is 1–12, and none is 0 or 13–23). Their local time is UTC−3 (2017) and UTC−4 (2018). The 2017 originals also have only minute resolution (Monday: seconds), and **7 of 10 2018 original files are cut at 1,048,575 rows** (the Excel limit). **Only the improved release supports sub-minute temporal work.**

### Value defects

6. **New defect in the improved release: `Fwd/Bwd Header Length` overflowed int16** (VERIFIED range; DOCUMENTED cause). Every value lies in [−32,768, 32,767], with 781 (2017) and 27,548 (2018) negative cells. The originals reach 5.8 million. The negatives are only a lower bound. **Do not use these two features.**
7. **The `Init Win Bytes` "not observed" sentinel changed from −1 to 0** (VERIFIED). Raw values are therefore not comparable across releases.

### Duplicates

8. **Feature-identical duplicates are common** (VERIFIED). Shares of data rows:

   | Release | Feature-identical share | Rows in label-conflict groups |
   |---|---:|---:|
   | 2017 improved | 12.52% | 14,140 (22 benign versus non-benign) |
   | 2018 improved | 28.47% | 263,772 (all benign versus non-benign) |
   | 2017 original | 10.91% | 7,018 |
   | 2018 original | 26.28% | 423,290 |

   Only the minority labels inside the conflict groups are irreducible error: 4,946 rows (2017, mostly `Portscan` against `Infiltration – Portscan`) and 65 rows (2018) (§6.1).

### Temporal structure

9. **Attacks are scripted blocks** (VERIFIED). At a 300 s gap there are only **24 (2017) and 38 (2018) attack episodes**, and most families occur once.
   - Persistence explains **67–73% (2017) and 91–93% (2018)** of next-window positives.
   - Persistence is therefore a mandatory baseline, and per-family results are anecdotal.
10. **Look-ahead risk in flow features** (VERIFIED counts). **22–38% of flows last longer than a 2 s window**, up to the 120 s flow timeout. Attributing a flow's totals to the window where it starts leaks the future. The protocol defaults to "ended flows only".

### Splits and shortcuts

11. **Random-row splits leak** (VERIFIED). 15.6% (2017) and 30.0% (2018) of evaluation rows have a feature vector already present in training. Within-day chronological splits do not work. Cut by time fraction, the 2018 test part holds no attack flows. Cut at flow quantiles, the split leaks across days and the embargo removes 716,549 attack flows. **Recommended:** forward-chaining by day, plus leave-one-day-out, plus cross-dataset transfer (`reports/evaluation_protocol.md`).
12. **Single-feature shortcuts are stronger in the improved releases** (VERIFIED, OVL = histogram overlap; 0 means separable). The best single feature reaches OVL ≈ 0.09 in the improved releases, against ≈ 0.31–0.39 in the originals. `Dst Port` reaches 0.103 (2018 improved). `id` also separates classes (OVL 0.33 in 2018), because of file order. `id`, IPs, ports, timestamps and file identity are never model inputs.

## 3. Findings table (`results/audit/findings.csv`)

`src/audit/report.py phase3` turns the Phase 2–3 outputs into **200 findings**. Each finding has:

- a rule, a count and a denominator;
- a severity and a rationale;
- an evidence file, a proposed action, and an action type (`requires review` or `deferred`).

**No finding is "critical".** No defect makes a whole release unusable. The defects that matter are specific columns, specific rows, and how results are evaluated.

| Category | n | Severity | What it covers |
|---|---:|---|---|
| FORMAT | 3 | 1 high, 1 medium, 1 low | mixed line endings (2018 orig. `Thuesday`), 59 repeated header rows (2018 orig.), cp1252 bytes (2017 orig. web-attack file) |
| COMPLETENESS | 7 | high | 2018 original files at exactly 1,048,575 rows |
| MISSING | 1 | high | 288,602 all-empty rows (2017 original) |
| NONFINITE | 8 | medium | ±Inf/NaN in `Flow Bytes/s` and `Flow Packets/s` |
| INVALID_VALUE | 18 | high | negative durations, IATs and rates (originals only) |
| EXPORT_OVERFLOW | 4 | high | int16 header-length overflow (improved) |
| SENTINEL / SEMANTICS_CHANGE | 8 / 4 | low / medium | the −1 sentinel and its disappearance |
| PLAUSIBILITY | 4 | medium | flows with no forward packets; TCP header lengths too short |
| CONSTANT / DUPLICATE_COLUMN | 17 / 11 | low | all-constant columns; columns identical row by row |
| DUPLICATES / LABEL_CONFLICT | 8 / 4 | medium / high | exact and feature-identical rows; conflicting labels |
| TIMESTAMP / ORDER | 54 / 15 | 8 high, 13 low, 48 medium | date mismatches, resolution, gaps, unparseable values, file order |
| IMBALANCE | 34 | medium | (label, Attempted category) classes with fewer than 100 flows |

## 4. Format, completeness and missing rows

| Finding | Evidence | Status | Handling |
|---|---|---|---|
| **2017 original: 288,602 all-empty rows**, comma-only lines 170,368–458,969 of `Thursday-WorkingHours-Morning-WebAttacks`. The file has 170,366 flows. | Independently recounted with plain byte reads and `grep`; the same count is in the user's source copy. **The count equals exactly the 288,602 rows of `Thursday-…-Afternoon-Infilteration`.** That suggests an export artefact (HYPOTHESIS). | VERIFIED count | Not data. Excluded from every per-flow statistic (`n_data_rows`) and counted. |
| **2018 original: 59 header lines repeated inside the data** (1 in `Friday-16-02`, 25 in `Thursday-01-03`, 33 in `Wednesday-28-02`) | `Label == 'Label'`. They are also the **only** unparseable timestamps (TIMESTAMP-031/037/052). | VERIFIED | Not data. Excluded from duplicate counts, conflict counts and separability. |
| **2018 original: 7 of 10 files hold exactly 1,048,575 rows** | Identical to the official S3 objects, so the cap is in the published release | VERIFIED | Originals are unusable for day-level temporal work. |
| **2018 original `Thuesday-20-02`: 577,787 CRLF lines, then 7,370,962 LF lines** | Forcing one line terminator made DuckDB silently skip about 600k rows. This was caught by the newline cross-check. | VERIFIED | The cache copy is normalised to LF (manifest-logged). |
| 2017 original web-attack file has 2,180 non-UTF-8 bytes (cp1252 `0x96`, an en dash in labels) | `data/manifests/encoding_check.csv` | VERIFIED | Transcoded in the cache; the labels then read "Web Attack – Brute Force". |
| **2018 original: a few `Timestamp` values in January 1970** (minimum 1970-01-05; 5 rows in `Wednesday-14-02`, 9 in `Thursday-22-02`) | These are the date-mismatch findings TIMESTAMP-042/046 | VERIFIED | Exclude from temporal work (originals are not used for it anyway). |
| Improved releases: **no** empty rows, header rows, exact duplicates, or encoding problems | Full scans | VERIFIED | — |

## 5. Values

### 5.1 Invalid, non-finite and overflowed values

| Finding | 2017 orig. | 2017 impr. | 2018 orig. | 2018 impr. | Notes |
|---|---:|---:|---:|---:|---|
| Non-finite `Flow Bytes/s` (also `Flow Packets/s`) | 2,867 | 5 | 95,760 | 57 | The improved notebooks drop "Infinity" rows before export (DOCUMENTED), but a few non-finite values remain (VERIFIED) |
| Negative `Flow Duration` | 115 | 0 | 14 | 0 | Consistent with packet-reordering problems that `reordercap` fixed (DOCUMENTED cause) |
| Negative `Flow IAT Min` | 2,891 | 0 | 15 | 0 | |
| Negative header length (cells) | 57 | 781 | 0 | 27,548 | The improved negatives are the int16 overflow, finding EXPORT_OVERFLOW (§5.2) |

### 5.2 Header-length overflow in the improved release

**VERIFIED range; DOCUMENTED cause** (`astype('int16')` in the labelling notebooks).

- **Range.** All values lie within [−32,768, 32,767]. Negative rows: Fwd 309 and Bwd 472 (2017); Fwd 10,039 and Bwd 17,509 (2018).
- **Comparison.** The original releases reach 4,644,908 and 5,838,440 (2017) and 2,477,032 and 2,462,372 (2018) for the same features.
- **More wrapped values than the negatives show (HYPOTHESIS, consistent).** Some TCP flows have a positive forward header length below 20 bytes × packets, which is impossible for real TCP headers. That happens in 152 (2017) and 3,951 (2018) rows (PLAUSIBILITY-002/004). Large overflows can wrap to small positive values like these.
- **Action.** Exclude `Fwd Header Length` and `Bwd Header Length` from model inputs, or recompute them from the PCAPs. Consider reporting this to the dataset authors.

### 5.3 Sentinels, constants and redundant columns

- **`FWD/Bwd Init Win Bytes` sentinel.** The originals use −1 for "not observed" (1.0M and 1.4M rows in 2017; 4.4M and 8.3M in 2018). The improved release has no −1, and its share of 0 rises. Encoding "not observed" as 0 is **HYPOTHESIS**. **Do not compare raw values across releases.**
- **ICMP Code/Type.** Both are −1 for non-ICMP flows in the improved release (2,099,373 of 2,099,976 in 2017; 63,089,142 of 63,195,145 in 2018). That is a documented sentinel, not missing data.
- **Constant columns.** All 6 Bulk features plus `Bwd PSH/URG Flags` in both originals. Only `Bwd URG Flags` in 2018 improved; none in 2017 improved.
- **Columns identical row by row.**
  - Originals: `SYN Flag Count == Fwd PSH Flags`, `CWR Flag Count == Fwd URG Flags`, and the subflow counts equal the totals. These are extractor bugs in the original CICFlowMeter.
  - 2018 improved: `URG Flag Count == Fwd URG Flags`.
  - Keep one column of each identical pair (`identical_columns.csv`).

### 5.4 Plausibility rules (`configs/data_audit.yaml`, 11 rules; `plausibility_by_file.csv`)

Only two rules fire in the improved releases:

- **`zero_forward_packets`:** 33 rows (2017) and 54,777 rows (2018). All are TCP. They may be continuation segments after the 120 s timeout or 5 s activity timeout, where the first packet seen is a backward one (HYPOTHESIS). Severity medium.
- **`fwd_header_shorter_than_min_tcp`:** see §5.2.

## 6. Duplicates and label conflicts (`duplicates_by_file.csv`)

**Definitions.**

- **Counts are "copies beyond the first":** rows minus the number of distinct rows. They are computed over **data rows only**, excluding empty rows and repeated header rows.
- **"Feature-identical"** compares all feature and context columns, without `id`, Flow ID, IPs, source port, timestamp or labels.
- **Numbers are compared by value**, not by text, because `0` and `0.0` both appear.

| | 2017 orig. | 2017 impr. | 2018 orig. | 2018 impr. |
|---|---:|---:|---:|---:|
| Data rows | 2,830,743 | 2,099,976 | 16,232,943 | 63,195,145 |
| Exact duplicate rows (all columns except `id`) | 203 | 0 | 433,195 (2.67%) | 0 |
| Feature-identical rows | 308,848 (**10.91%**) | 263,004 (**12.52%**) | 4,265,470 (**26.28%**) | 17,994,469 (**28.47%**) |
| Feature-identical groups with more than one label | 697 | 4,375 | 22,359 | 13 |
| Rows in those groups | 7,018 | 14,140 | 423,290 | 263,772 |
| Rows in benign-versus-non-benign conflict groups | 7,018 | 22 | 170,766 | 263,772 |
| Rows in duplicate groups that span files | 0 | 0 | 0 | 0 |

**Reading the table.**

- **The improved releases contain no exact duplicates** (VERIFIED). Every row has a microsecond timestamp and a 5-tuple, so identical rows are unlikely by construction. Yet many flows are indistinguishable once identifiers are removed.
- **2017 improved conflicts are almost all between two attack classes**, `Infiltration – Portscan` and `Portscan` (§6.1). Only 22 of 14,140 rows are benign versus non-benign.
- **2018 improved conflicts are few groups but very large ones.** 13 groups cover 263,772 rows, all benign versus non-benign. They lie in `Wednesday-14-02` (169,690 rows) and `Friday-16-02` (87,640 rows); the rest of the 263,772 come from groups spanning several files. Their label composition is in `results/audit/label_conflict_composition.csv` (§6.1).
- **What a conflict group means.** No model that sees only these features can classify every row in it correctly. The irreducible part is the minority labels (§6.1). Report it, and decide the Attempted policy explicitly (E4).
- **Across splits, duplicates are what leak.** `reports/evaluation_protocol.md` §4 measures this for each candidate split.

### 6.1 Label composition of the improved conflict groups

Source: `leakage.py conflicts`, computed from the per-row feature hashes. The minimum unavoidable error is the number of rows in the minority labels of each group.

| Dataset | Labels in the group | Groups | Rows | Minimum unavoidable error |
|---|---|---:|---:|---:|
| 2017 improved | `Infiltration – Portscan` (Thursday) and `Portscan` (Friday) | 4,368 | 14,118 | 4,939 |
| 2017 improved | `BENIGN` and `Portscan` | 7 | 22 | 7 |
| 2018 improved | `BENIGN` and `FTP-BruteForce – Attempted` | 9 | 263,736 (263,676 Attempted, 60 benign) | 60 |
| 2018 improved | `BENIGN` and `Infiltration – NMAP Portscan` | 4 | 36 | 5 |

**What this shows (VERIFIED counts).**

- **2017.** The conflicts are identical scan probes labelled by **scenario**, not by behaviour. Every conflicting group spans the Thursday and Friday files. A behaviour-level target should merge the two classes.
- **2018.** The conflict rows are almost all failed FTP connection attempts, CNS2022 Attempted category 1 "port closed". 60 benign flows happen to match them exactly. **The binary benign-versus-attack floor is only 65 rows**, despite the 263,772 rows in conflict groups.
- **Not computed for the originals.** The hash table covers the improved data only.

## 7. Timestamps and row order (`timestamp_quality.csv`, `label_window_consistency.csv`)

| Check | Improved | Original |
|---|---|---|
| Format | `%Y-%m-%d %H:%M:%S.%f`, 6 fractional digits in 100% of rows | 2017: `%d/%m/%Y %H:%M` (Monday `%H:%M:%S`); 2018: `%d/%m/%Y %H:%M:%S` |
| Clock | UTC (DOCUMENTED) | **12-hour without AM/PM** (VERIFIED, both); local UTC−3 (2017) / UTC−4 (2018) (VERIFIED by 5-tuple matching) |
| Unparseable | 0 | 59 = the repeated header rows (2018) |
| Dates differing from the file-name date | 188–2,970 rows in 7 of 10 2018 files: flows after midnight UTC (late-evening local traffic, by 01:15 UTC). **Plus `Friday-23-02`: 2,609 flows dated 21–22 Feb**, about a day before the capture. | 5 and 9 rows dated 1970 (2018) |
| Gaps over 300 s between consecutive flow starts | 0, except the 5 gaps created by the 21–22 Feb stray rows in `Friday-23-02`. The longest gap otherwise is 130 s (`Friday-16-02`). | 1–9 per file: clock and truncation artefacts |
| File order | **Not time order.** In every improved file, 30–45% of consecutive rows go back in time by more than 60 s (ORDER-001…015). | — |
| `id` | Equals the physical row number in 100% of rows | absent |
| Labels versus documented windows | **4,359,069 of 4,359,069** attack and Attempted flows inside a window for the same label, category and file. 0 outside. | not applicable |

**The stray rows in `Friday-23-02-2018`** (2,609 flows, 21 Feb 12:33 to 22 Feb 12:21 UTC) mirror the stray-PCAP problem the authors fixed for 02-03-2018 (DOCUMENTED). Their cause here is a HYPOTHESIS. They are **excluded, with a count, by the split audit** (`configs/evaluation_protocol.yaml` `row_exclusions`). They must also be excluded from windowing.

## 8. Class imbalance

These counts are of (label, Attempted category) classes with fewer than 100 flows in the improved releases (IMBALANCE-001…034): 20 classes in 2017, 14 in 2018. Some are full attack classes:

| Dataset | Attack class | Flows |
|---|---|---:|
| 2017 | Web Attack – Brute Force | 73 |
| 2017 | Infiltration | 36 |
| 2017 | Web Attack – XSS | 18 |
| 2017 | Web Attack – SQL Injection | 13 |
| 2017 | Heartbleed | 11 |
| 2018 | Infiltration – Dropbox Download | 85 |
| 2018 | Web Attack – SQL | 39 |

Classes this small cannot support per-class metrics with useful confidence intervals. Report them as counts, or merge them into families with the merge documented (`configs/label_family_map.yaml`).

## 9. What this means for modelling (input to Phase 8, not yet authorised)

**Use:**

- The improved releases only.
- Rows sorted by `Timestamp` within each file.
- 2 s windows that never cross a file.
- The 2,609 stray `Friday-23-02` rows excluded, with the count logged.

**Never as inputs:**

- `id`, `Flow ID`, `Src IP`, `Dst IP`, `Src Port`, `Timestamp` (except to order and aggregate);
- `Label`, `Attempted Category`;
- file, day or scenario identity.

**Exclude or ablate:**

- Exclude `Fwd/Bwd Header Length` (overflow).
- Ablate `Dst Port`, `Protocol` and `FWD/Bwd Init Win Bytes`; these are shortcut candidates and the sentinel changed.
- Keep only one column of each identical pair.

**Handle explicitly, with counts:**

- the 5 and 57 non-finite rate rows;
- the Attempted policy;
- the irreducible error of the conflict groups (§6.1).

**Evaluate with:**

- forward-chaining by day, leave-one-day-out, and cross-dataset transfer;
- a 130 s embargo;
- the persistence baseline;
- "ended flows only" window features (`reports/evaluation_protocol.md`).

## 10. Errors in this audit's own work, found and corrected

All are logged in `reports/WORK_LOG.md`. They are listed here because some numbers given earlier in the session were wrong.

| Earlier statement | Correction | How it was found |
|---|---|---|
| 2017 original: 19.15% feature-identical rows | **10.91%.** The 288,602 empty rows had been counted as duplicates of each other. 2018 original: the 59 header rows had produced a false "59 rows duplicated across files"; the true count is 0. | Re-checking definitions before writing this report. Code fixed; step re-run. |
| 2018 originals use a 24-hour clock | **12-hour without AM/PM**, like 2017. Hours are only 1–12 in every file. Row matching for `Thuesday-20-02` was re-run with hour mod 12: unique matches rose from 0.419 to 0.783 (`reports/original_vs_improved.md` §4). | Hour histograms in `timestamp_quality.csv` |
| "8 of 10" 2018 original files capped | **7 of 10** | Recount by script |
| Forward-chaining folds "contain seen families" | The recurring family is in the **validation** day, not the training days. It counts as seen only if the model is refit on train + val. Both are now measured. | Reading `split_design_coverage.csv` |
| Within-day split "fails for 2018 with only 158 test attacks" | Those 158 attacks were an artefact of the stray 21–22 Feb rows stretching one file's time span. With the rows excluded, the test part has **0** attack flows. | Adding the logged row exclusion to the split audit |
