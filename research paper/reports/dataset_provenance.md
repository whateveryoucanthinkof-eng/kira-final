# Dataset provenance: improved and original CIC-IDS-2017 / CSE-CIC-IDS-2018

First prepared 2026-10-19 (Phase 1); revised the same day with Phase 2–4 evidence. Evidence labels:

- **VERIFIED**: checked directly against local files, or by a reproducible command recorded here.
- **DOCUMENTED**: stated by the dataset authors (paper, release pages, labelling code) but not independently re-checked.
- **HYPOTHESIS**: plausible, not yet tested.
- **UNRESOLVED**: the evidence is missing or conflicting.

---

## 1. What is in the project

| Release | Location | Files | Bytes (uncompressed) | Provenance status |
|---|---|---:|---:|---|
| CIC-IDS-2017, **improved** (CNS2022) | `CICIDS2017_improved.zip` → `data/raw_improved/CIC-IDS-2017/` | 5 | 1,152,270,765 | **VERIFIED** official release file (§2) |
| CSE-CIC-IDS-2018, **improved** (CNS2022) | `CSECICIDS2018_improved.zip` → `data/raw_improved/CSE-CIC-IDS-2018/` | 10 | 36,044,466,483 | **VERIFIED** official release file (§2) |
| CSE-CIC-IDS-2018, **original** | `data/raw_original/CSE-CIC-IDS-2018/`, copied from `../research_P1/data/01_raw/` | 10 | 6,886,649,507 | **VERIFIED** identical to the official AWS Open Data objects (§5) |
| CIC-IDS-2017, **original** | `data/raw_original/CIC-IDS-2017/`, copied from `../gnn/cic2017csv/` | 8 | 1,203,105,382 | Copy integrity **VERIFIED**. Identity with an official release **UNRESOLVED** (§5) |

**How the files were acquired.** Every extracted or copied file went through the same steps:

- it was written to a `.partial` file and hashed while being written;
- it was renamed into place only after the hash matched;
- it was set read-only;
- it was re-read from disk and its hash verified again.

All **33/33** files passed (`data/manifests/acquisition_manifest.csv`, `acquisition_verification.csv`). The checks were repeated at the end of the audit (`acquisition_verification_final.csv`) and after the raw folders were moved out of OneDrive to `C:\nids_data\` behind junctions (`acquisition_verification_after_relocation.csv`). Both times, 33/33 were unchanged. No raw file was modified. The only exclusion was the 0-byte `.gitkeep`, which was skipped and logged.

## 2. The improved releases (CNS2022)

| Claim | Status | Evidence |
|---|---|---|
| These are the "improved" datasets of Liu, Engelen, Lynar, Essam, Joosen, *Error Prevalence in NIDS datasets*, IEEE CNS 2022, pp. 254–263, DOI 10.1109/CNS56114.2022.9947235 | **VERIFIED** | The paper points to `intrusion-detection.distrinet-research.be/CNS2022/`. That site's `Datasets/` index lists exactly `CICIDS2017_improved.zip` and `CSECICIDS2018_improved.zip`. A snapshot is in `references/release_site_snapshot_2026-10-19/`. |
| Local zips are byte-for-byte the size the server reports | **VERIFIED** | HTTP `Content-Length` is 343,549,013 and 10,426,851,729, equal to the local sizes. |
| Downloads are complete and uncorrupted | **VERIFIED** | All 15 archive members stream-decompress with matching CRC-32 and size. Archive SHA-256 values: 2017 `97fdb91d…c48883`, 2018 `7f7b6f80…344f6e` (`data/manifests/checksums_sha256.csv`). |
| Content is cryptographically identical to the server copy | **UNRESOLVED** (high confidence) | No checksum is published. The ETag is Apache's size-plus-mtime form, not a content hash. |
| **Which release this is** | **VERIFIED** dates / **HYPOTHESIS** (strongly supported) that the content equals the post-publication fix commits | The labelling repository `github.com/GintsEngelen/CNS2022_Code` has commits titled "First round of Post Publication Fixes" (2023-03-30), "Added rest of residual labelling fixes to CICIDS2018" (2023-04-03 15:38 +0200) and "fixed CICIDS2017 residual issues" (2023-04-27 16:47 +0200). Those dates match the archive-member timestamps (2018: 2023-03-30 to 2023-04-03; 2017: 2023-04-27 16:16–16:17) and the server Last-Modified times (2023-04-03 14:53 GMT; 2023-04-27 14:41 GMT). **These are post-publication corrected releases, not the exact files behind the paper's tables.** |
| The labelling code at repository HEAD is the release-time logic | **VERIFIED** (tree identity) | The HEAD `f0ce502` tree is identical to `7f862bf` (2023-04-27): a later "Traffic duplication removal (CIC-IDS-2017)" change was merged on 2023-07-20 and reverted on 2023-07-31. |
| Every non-benign label in the data has a documented labelling rule for the same day | **VERIFIED** | 121 rules were parsed statically from the notebooks (nothing executed). 85 (label, category, file) pairs appear in both the rules and the data; 0 data labels lack a rule (`results/audit/label_vs_labelling_rules.csv`). |
| Licence or terms of use | **UNRESOLVED** | None is stated on the release pages or in the repository (GitHub API: `license: null`). |

## 3. How the improved files were generated

| Claim | Status | Evidence |
|---|---|---|
| Produced by the authors' corrected CICFlowMeter fork (`github.com/GintsEngelen/CICFlowMeter`) | **VERIFIED** (schema) + **DOCUMENTED** | All 15 headers contain the fork's added features: `Fwd/Bwd RST Flags`, `ICMP Code/Type`, `Total TCP Flow Time`. |
| PCAPs were cleaned with `pcapfix` and `reordercap` (packets reordered by timestamp) before flow extraction. For 2018, a stray PCAP containing the previous day's traffic was removed from 02-03-2018. | **DOCUMENTED** | `CNS2022_Code/README.md` |
| **Flow timeout 120 s; activity timeout 5 s** | **DOCUMENTED** | README: "Flow TimeOut … 120000000 and Activity Timeout … 5000000". |
| TCP flows end after a bidirectional FIN exchange or an RST; the Bulk features are fixed; timestamps are UTC with microsecond precision; ICMP support; TCP Segmentation Offload fix | **DOCUMENTED** | Release Tools & Documentation page; paper §IV-B |
| Every timestamp has exactly 6 fractional digits | **VERIFIED** | Full scan; 65,295,121 of 65,295,121 rows (Phase 2) |
| **Timestamps are UTC** | **DOCUMENTED** + consistency **VERIFIED** | The labelling code says "the CSV files are in the UTC timezone", and its windows are UTC epoch nanoseconds. Phase 3 checks every attack flow against those windows (`label_window_consistency.csv`). Day spans in 2017 are about 11:42–20:10 UTC, i.e. 08:42–17:10 at UTC−3, which matches working hours. |
| `id` is the 1-based row number written at export | **DOCUMENTED** + **VERIFIED** | Labelling code: `reset_index` then `index += 1`, named `id`. In the timeline cache, `id` equals the physical row number in 100% of rows. |
| Rows containing `Infinity` or NaN were **dropped** before export | **DOCUMENTED** | Both labelling notebooks: `df.replace('Infinity', np.nan) … return df.dropna()`. The number dropped is not published (**UNRESOLVED**). |
| 2018 day files are several per-host CICFlowMeter CSVs concatenated in `glob` order | **DOCUMENTED** + **VERIFIED** | Labelling code. Phase 3 measures the time-order breaks in the 2018 files. |
| Labels come from time windows plus IP/port/feature filters; `Attempted Category` codes −1, 0–6 | **DOCUMENTED** | Codes: −1 not attempted; 0 no payload sent by attacker; 1 port/system closed; 2 attack startup/teardown artefact; 3 no malicious payload; 4 attack artefact; 5 attack implemented incorrectly; 6 target system unresponsive (release pages, saved snapshot). The rules are in `results/audit/attack_windows_documented.csv`. |
| Release documentation pages have minor copy errors (e.g. a truncated unix time "499262299…"; GoldenEye's end time repeated under Slowloris) | **VERIFIED** (on the pages) | The code, not the prose, is treated as authoritative. |

## 4. Row counts (VERIFIED by full scan; cross-checked against newline counts)

| Release | Rows | Comparison with the paper (Table I) |
|---|---:|---|
| 2017 improved | 2,099,976 | Not stated in the paper. 25.8% fewer than the original 2,830,743 (flow termination changes; see Phase 4). |
| 2018 improved | 63,195,145 | Not stated. The paper's *full* 2018 version had 65,042,705 flows (64,561,010 cleaned). |
| 2017 original | 3,119,345 = 2,830,743 flows + 288,602 empty rows | **2,830,743 = the paper's "Published Flows" exactly** |
| 2018 original | 16,233,002 = 16,232,943 flows + 59 header rows | The paper's 16,232,963 differs by 20 (UNRESOLVED) |

## 5. The original releases

**CSE-CIC-IDS-2018 original: VERIFIED.**

- All 10 files match the official public AWS Open Data objects (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`, Last-Modified 2018-10-11) in both size and recomputed S3 multipart ETag (16 MiB parts) (`data/manifests/original_2018_s3_etag_check.csv`; `src/audit/s3_etag_check.py`).
- 7 of the 10 files hold exactly 1,048,575 data rows, the Excel row limit. Since the files are identical to the official objects, this cap is in the **published release**. The paper says the published version is about 25% of the full flow set.

**CIC-IDS-2017 original: UNRESOLVED identity, consistent evidence.**

- The 85-column `*.pcap_ISCX.csv` files, with `Flow ID`, `Source IP` and `Timestamp`, match the CIC "GeneratedLabelledFlows / TrafficLabelling" variant by schema.
- The non-empty row count equals the paper's published count.
- No official checksum was compared. Doing so would mean downloading the official archive, which has not been done.

**Timestamps of the originals (VERIFIED in Phase 3/4).**

| Release | Clock | Timezone (best whole-hour offset from 5-tuple matching against the improved UTC data) |
|---|---|---|
| 2017 original | **12-hour without AM/PM**: hours parse only as 1–5 and 8–12. Minute resolution, except Monday, which has seconds. | Local time **UTC−3** |
| 2018 original | **12-hour without AM/PM** as well: hours parse only as 1–12 (afternoon traffic appears as 1–7). Second resolution. 14 values dated 1970. | **UTC−4**, from the only file with 5-tuples (`Thuesday-20-02-2018`, 78.3% unique matches with hour mod 12) |

Both offsets fit the testbed's location in New Brunswick: summer time in July (2017) and standard time in February (2018). That location is **HYPOTHESIS** context; the offsets themselves are measured.

## 6. Open questions

1. How many Infinity/NaN rows were dropped from each improved day before export? (Not published.)
2. What licence or terms of use apply to the improved releases?
3. Does the 2017 original copy match an official checksum? (Would need the official archive.)
4. Why is there a 20-row difference from the paper's published 2018 count?
