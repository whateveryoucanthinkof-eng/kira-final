# Phase 2: Schema and label audit

Run 2026-10-19 (pipeline step `phase2_scan`, 313 s). Evidence labels:

- **VERIFIED**: measured on the local files.
- **DOCUMENTED**: stated by the dataset authors.
- **HYPOTHESIS**: proposed, not yet tested.
- **UNRESOLVED**: not settled by the available evidence.

Outputs are in `results/audit/`:

- `schema_by_file.json`
- `column_profile_by_file.csv`
- `label_distribution_by_file.csv`
- `label_distribution_by_dataset.csv`
- `label_vs_labelling_rules.csv`
- `schema_diff_original_vs_improved.csv`
- `attack_windows_documented.csv`

Code: `src/audit/schema_labels.py`, `src/audit/encoding.py`, `src/audit/labelling_windows.py`.

## 1. Scope and method

- **Files.** All 33 CSVs:
  - 15 improved files, extracted from the verified zips;
  - 18 original files, copied from your folders and verified by SHA-256 after copying.
  The 10 original 2018 files are also content-identical to the official AWS objects. All 10 recomputed S3 multipart ETags match (`data/manifests/original_2018_s3_etag_check.csv`). **VERIFIED.**
- **Reading.** Every file is fully scanned with DuckDB 1.5.6.
  - Every value is read as text (`all_varchar`), under the exact header names. DuckDB does no type guessing and no renaming.
  - Reads are strict, so a malformed row raises an error instead of being skipped.
- **Independent cross-check.** For every file, the rows read are compared with the number of newline bytes counted during acquisition. **All 33 files: 0 lines unaccounted for.**
- **Label counts.** Full scans of the exact strings. For non-ASCII labels, the original bytes are kept as hex (`label_bytes_hex`).

### 1.1 Read-path problems found, and how they were handled

These were found while building the scanner. Each was fixed at read time. No raw file was changed.

| Problem (VERIFIED) | Effect if ignored | Handling |
|---|---|---|
| Original 2017 `Thursday-WorkingHours-Morning-WebAttacks` is not valid UTF-8. It has 2,180 bytes `0x96` (cp1252 en dash) in `Web Attack – …` labels. | DuckDB's UTF-8 mode raised an INTERNAL error that invalidated the connection. Its latin-1 mode rejected the file. | Transcoded cp1252 → UTF-8 into a cache outside the project. The cp1252 choice is DOCUMENTED: the authors' code reads the 2017 CSVs with `encoding='cp1252'`. Both hashes are in `data/manifests/encoding_transcode_manifest.csv`. |
| Original 2018 `Thuesday-20-02-2018` mixes line endings. The first 577,787 lines end in CRLF, then 7,370,962 lines end in bare LF (from byte 244,194,960). | Forcing `new_line='\n'` made DuckDB **silently drop the CRLF section**. That loses all 576,191 `DDoS attacks-LOIC-HTTP` rows plus 22,595 others, while still reporting success. Only the newline cross-check caught it. | The cache copy normalises CRLF → LF. Afterwards, DuckDB's 7,948,748 rows match an independent Python count exactly. |
| DuckDB `store_rejects` hit an INTERNAL assertion on malformed input. | The rejects audit table was unusable. | Strict reads plus the newline-count cross-check are used instead. |
| DuckDB `TRY_CAST('12.5' AS BIGINT)` returns 13, because it rounds. | Mean and std columns were mis-typed as "integer" in the first run. | Integer-ness is now tested with the exact regex `^[+-]?[0-9]+$`. The first run's types were discarded. |

## 2. Files, rows and headers (VERIFIED, full scans)

| Dataset / release | Files | Columns | Rows | Notes |
|---|---:|---:|---:|---|
| CIC-IDS-2017 improved | 5 (one per weekday) | 91 | **2,099,976** | Identical header in all files. LF line endings. |
| CSE-CIC-IDS-2018 improved | 10 (one per day) | 91 | **63,195,145** | Same 91-column header as 2017 improved. |
| CIC-IDS-2017 original | 8 | 85 | 3,119,345 | Includes **288,602 all-empty rows**, so 2,830,743 real rows. That **equals the paper's Table I "Published Flows" (2,830,743)**. 70 of 85 names have leading spaces. `Fwd Header Length` appears twice. |
| CSE-CIC-IDS-2018 original | 10 | 80 (9 files), 84 (`Thuesday-20-02-2018`) | 16,233,002 | Includes **59 embedded header rows**, so 16,232,943 flows. The paper reports 16,232,963 (a 20-row difference, UNRESOLVED). **7 of 10 files have exactly 1,048,575 data rows**, the Excel row limit. |

**Header of the improved release (all 15 files).** The columns are:

- `id, Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp`;
- 76 flow statistics;
- `ICMP Code, ICMP Type, Total TCP Flow Time, Label, Attempted Category`.

There are no duplicate names, no names with surrounding whitespace, no BOM and no quote characters. The full list is in `data/manifests/archive_member_headers.json`.

**Timestamp formats (full-column coverage, VERIFIED):**

| Release | Format (rows parsed / non-empty) | Resolution |
|---|---|---|
| Improved, both datasets | `%Y-%m-%d %H:%M:%S.%f` in 100% of rows, all with exactly 6 fractional digits | Microseconds. The UTC timezone is DOCUMENTED (labelling code: "the CSV files are in the UTC timezone"). |
| Original 2017, Monday | `%d/%m/%Y %H:%M:%S` | Seconds, no timezone |
| Original 2017, the other 7 files | `%d/%m/%Y %H:%M` | **Minutes**, no timezone. The clock is 12-hour without AM/PM (VERIFIED in Phase 3/4: hours 1–12 only). |
| Original 2018 | `%d/%m/%Y %H:%M:%S`, except the 59 header rows | Seconds, no timezone |

## 3. Column roles (preliminary; finalised in Phase 6)

These come from `configs/data_audit.yaml` and are applied to canonical names.

| Role | Columns | Model input? |
|---|---|---|
| identifier | `id`, `Flow ID`, `Src IP`, `Src Port`, `Dst IP` | **Never** |
| timestamp | `Timestamp` | **Never as a value**; only to order and aggregate windows |
| target | `Label`, `Attempted Category` | **Never** |
| context_review | `Dst Port`, `Protocol` | Only after the leakage review (Phase 6) |
| feature | The remaining 77 columns | Yes, subject to the Phase 3/6 findings |

`id` is a 1-based row number written at export, after rows with Infinity or NaN were dropped. That is **DOCUMENTED** in the labelling code and **VERIFIED** by Phase 3's id-equals-row-number check, so it is a file-order artefact.

## 4. Types

- **Improved data.** Every column has one consistent base type across files. Integer columns hold only integer literals; float columns hold only decimal or rate values.
- **Infinity and NaN in the improved data.** The `special_tokens` counts are reported in Phase 3. The authors' code drops rows with `Infinity` or NaN before export (**DOCUMENTED**), so the improved release is the authors' "cleaned" flow set.
- **Originals versus improved.** 21 columns per dataset change type. In the originals, some integer counts are written as decimals in some files; the improved release is consistent. This is a representational change.
- **2018 originals.** 234 column-file cells hold some non-numeric text. That is exactly the 59 embedded header rows: 3 files × 78 numeric columns. **VERIFIED.**
- **Values.** No value in any file has surrounding whitespace.

## 5. Labels (VERIFIED full-scan counts; exact strings)

### 5.1 CIC-IDS-2017 improved: 2,099,976 flows, 39 (label, Attempted Category) pairs

| Label | Cat. | Flows | Share |
|---|---:|---:|---:|
| BENIGN | -1 | 1,582,566 | 75.36% |
| Portscan | -1 | 159,066 | 7.57% |
| DoS Hulk | -1 | 158,468 | 7.55% |
| DDoS | -1 | 95,144 | 4.53% |
| Infiltration - Portscan | -1 | 71,767 | 3.42% |
| DoS GoldenEye | -1 | 7,567 | 0.36% |
| Botnet - Attempted | 1 | 4,067 | 0.19% |
| FTP-Patator | -1 | 3,972 | 0.19% |
| DoS Slowloris | -1 | 3,859 | 0.18% |
| SSH-Patator | -1 | 2,961 | 0.14% |
| DoS Slowhttptest - Attempted | 6 | 2,804 | 0.13% |
| DoS Slowhttptest | -1 | 1,740 | 0.08% |
| DoS Slowloris - Attempted | 0 | 1,705 | 0.08% |
| Web Attack - Brute Force - Attempted | 0 | 1,214 | 0.06% |
| Botnet | -1 | 736 | 0.04% |
| 24 smaller pairs (each ≤ 651) | — | 2,340 in total | 0.11% |

**Classes with fewer than 100 flows include:**

| Class | Flows |
|---|---:|
| Web Attack - Brute Force | 73 |
| Infiltration | 36 |
| Web Attack - XSS | 18 |
| Web Attack - SQL Injection | 13 |
| Heartbleed | 11 |

Per-class metrics for these classes would carry very wide uncertainty. The full list is in `label_distribution_by_dataset.csv`.

### 5.2 CSE-CIC-IDS-2018 improved: 63,195,145 flows, 33 pairs

| Label | Cat. | Flows | Share |
|---|---:|---:|---:|
| BENIGN | -1 | 59,353,486 | 93.92% |
| DoS Hulk | -1 | 1,803,160 | 2.85% |
| DDoS-HOIC | -1 | 1,082,293 | 1.71% |
| FTP-BruteForce - Attempted | 1 | 298,844 | 0.47% |
| DDoS-LOIC-HTTP | -1 | 289,328 | 0.46% |
| Botnet Ares | -1 | 142,921 | 0.23% |
| SSH-BruteForce | -1 | 94,197 | 0.15% |
| Infiltration - NMAP Portscan | -1 | 89,374 | 0.14% |
| DoS GoldenEye | -1 | 22,560 | 0.04% |
| DoS Slowloris | -1 | 8,490 | 0.01% |
| DoS GoldenEye - Attempted | 4 | 4,248 | 0.01% |
| DDoS-LOIC-UDP | -1 | 2,527 | < 0.01% |
| 21 smaller pairs (each ≤ 2,280) | — | 3,717 in total | < 0.01% |

**Classes with fewer than 250 flows:**

| Class | Flows |
|---|---:|
| Infiltration - Communication Victim Attacker | 204 |
| Web Attack - Brute Force | 131 |
| Web Attack - XSS | 113 |
| Infiltration - Dropbox Download | 85 |
| Web Attack - SQL | 39 |

**What changed between releases.** These are observed differences in labels, not row-level corrections, which are covered in Phase 4.

- **No successful FTP brute force in the improved 2018.** All 298,844 FTP flows are `FTP-BruteForce - Attempted`, category 1 (port closed).
- **No SlowHTTPTest class in the improved 2018.** The original's 139,890 `DoS attacks-SlowHTTPTest` flows have no counterpart. The paper (Table III) says these were FTP attempts to a closed port. **DOCUMENTED.**
- **Heartbleed** appears in neither 2018 release.
- **New class in the improved 2017:** `Infiltration - Portscan`, with 71,767 flows.
- **Botnet in 2017:** the original's `Bot` (1,966 flows) corresponds to `Botnet` (736) plus `Botnet - Attempted` (4,067) in the improved release.

### 5.3 Labels against the documented labelling rules

The authors' labelling notebooks were parsed statically. Nothing was executed. The parse yielded **121 rules**, each with an exact UTC window, IP lists, ports and filters (`attack_windows_documented.csv`, repository commit `f0ce502`, whose tree is identical to `7f862bf` of 2023-04-27).

| Check (improved data, per file) | Result |
|---|---|
| (label, category) present in the data **and** a rule exists for it in that file | 85 |
| Rule exists but matches 0 flows | 18. These are narrow "Attempted" sub-rules, e.g. `Heartbleed - Attempted` and `DDoS-HOIC - Attempted`. |
| Benign default (`label_rest_as_benign`) | 15 |
| **Label in the data with no documented rule** | **0. VERIFIED: every non-benign label in the improved release is explained by a published rule for the same day file.** |

Whether each flow's **timestamp** falls inside its rule's window is checked in Phase 3 (`label_window_consistency.csv`).

### 5.4 Originals

- **CIC-IDS-2017 original.** 15 classes plus 288,602 empty rows. The web-attack labels contain byte `0x96`.
- **CSE-CIC-IDS-2018 original.** 15 classes plus 59 `Label` header rows. The class `Infilteration` is misspelled in the release.

## 6. Schema differences, original versus improved

Full table: `schema_diff_original_vs_improved.csv`. Columns are matched by name: exact, then whitespace or case, then token-normalised abbreviations.

| | CIC-IDS-2017 | CSE-CIC-IDS-2018 |
|---|---|---|
| Unchanged name | 11 | 36 |
| Renamed (same quantity by name) | 73 (50 whitespace only, 22 abbreviation or word order, 1 HYPOTHESIS: `CWE Flag Count` → `CWR Flag Count`) | 48 (47 abbreviation, 1 CWE → CWR) |
| Removed | 1 (the duplicate `Fwd Header Length`) | 0 |
| Added in improved | 7: `id`, `Fwd RST Flags`, `Bwd RST Flags`, `ICMP Code`, `ICMP Type`, `Total TCP Flow Time`, `Attempted Category` | the same 7 |
| Present in only some original files | none | `Flow ID`, `Src IP`, `Src Port`, `Dst IP` (only in `Thuesday-20-02-2018`) |

**Same name does not mean same values.** The fork changed:

- flow termination: a bidirectional FIN exchange is now required, and RST ends a flow;
- the Bulk feature calculations;
- the timestamp, which is now UTC with microsecond precision.

These changes are **DOCUMENTED**. Phase 4 compares the resulting distributions.

## 7. Open items carried forward

1. Is the original 2017 clock 12-hour without AM/PM? What timezone do the original timestamps use? (Phase 4/5)
2. Do flow timestamps sit inside the documented labelling windows? (Phase 3)
3. The 20-row difference from the paper's 2018 published count. (UNRESOLVED; low impact)
4. Label policy for "Attempted" flows: a separate class, benign, or excluded. (Phase 6 decision)
