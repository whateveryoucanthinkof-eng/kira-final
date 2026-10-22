# Phase 5: Temporal feasibility and forecasting-target design

Run 2026-10-19.

- **Code:** `src/audit/temporal.py` (summaries) and `src/audit/integrity.py timestamps`.
- **Outputs (`results/audit/`):** `temporal_feasibility.json`, `attack_segments.csv`, `timestamp_quality.csv`, `label_window_consistency.csv`, and `figures/wednesday_2017_flows_per_minute.png` (made by notebook 05).
- **No sequence dataset was generated.** All numbers are aggregate counts.
- **Unless stated otherwise, everything below concerns the improved releases.** §8 explains why the originals cannot support this work.

## 1. What a row is

| Question | Answer | Status |
|---|---|---|
| Unit | One **bidirectional flow** from CICFlowMeter. The first packet defines the forward direction. A flow ends at a mutual FIN exchange, an RST, the **120 s flow timeout**, or the **5 s activity timeout** (which splits it into sub-flows). | DOCUMENTED (paper §II-A; CNS2022_Code README) |
| `Timestamp` | Flow **start** time (first packet), UTC, microsecond resolution | Start-time semantics and UTC: **DOCUMENTED** (labelling windows are defined as "Time Start UTC (First Packet)"). Format: **VERIFIED** (6 fractional digits in 100% of rows). |
| Consistency with labels | All **4,359,069** attack and Attempted flows lie inside a documented labelling window for the same label, category and day file: **0 outside, 0 without a rule** | **VERIFIED** (full scan) |
| Can file order reveal start versus end semantics? | **No.** In file order, about 45% of consecutive rows step backwards in time whether rows are ordered by start time or by end time (start + duration). Rows are in neither order. | **VERIFIED.** 2018 day files are concatenations of per-host CSVs (DOCUMENTED). |
| Duration bound | Maximum `Flow Duration` = 120,000,000 µs, equal to the flow timeout. No flow is longer. | **VERIFIED** |
| `id` | Row number at export (equal to the physical row number in 100% of rows). **Not** a time index. | **VERIFIED** |

**Rule for every later step:** sort by `Timestamp` within each day file, and **never** rely on row order or `id`.

## 2. Capture boundaries and overlaps

| Dataset | Days | Span per day (UTC) | Notes |
|---|---|---|---|
| 2017 improved | 5 files, 3–7 July 2017, one file per day | about 11:42–20:10. At UTC−3 that is about 08:42–17:10 local, matching the documented working day. | No overlap between files. No date or weekday mismatches. Largest gap between consecutive flow starts: 24–59 s. |
| 2018 improved | 10 files, 14 Feb–2 Mar 2018 | start 12:15–12:46 UTC; end 22:15 UTC (`Friday-16-02`) to 01:15 UTC the next day. At UTC−4 that is about 08:15–21:15 local. | 7 files spill past midnight UTC: 188–2,970 rows per file, ending by 01:15 UTC. That is ordinary late-evening traffic, not an error. |
| 2018 `Friday-23-02-2018` | — | — | **Contains 2,609 benign flows timestamped 21 Feb 12:33 to 22 Feb 12:21 UTC**: sparse traffic with external IPs, about 24 hours **before** the 23 Feb capture. It creates a 23.9 h gap. VERIFIED. This mirrors the stray-PCAP problem the authors documented for 02-03; HYPOTHESIS about the cause. |

**Implications.**

- **Windows never cross day files.** Capture days do not overlap and are separated by about 12-hour nightly gaps, so continuity across days does **not** exist.
- **Each file is analysed over its main capture interval.** The stray 21–22 Feb rows in `Friday-23-02-2018` must be excluded, with a logged count. If they are kept, they create 80% empty windows and inflate lead times.

## 3. Viability of 2-second windows

Flows are assigned to the window in which they **start**. The table is per day file, improved release.

| | 2017 (5 days) | 2018 (10 days; `Friday-23-02` reported separately) |
|---|---|---|
| 2 s windows in span | 14,486–15,227 per day | 17,656–23,151 per day |
| Share of windows with no flow start | 11.5–19.9% | 2.6–14.9% |
| Longest run of empty windows | 11–29 windows (22–58 s) | 10–64 windows (20–128 s) |
| Flows lasting longer than one window (> 2 s) | **23.9–30.7%** of flows | **22.3–38.1%** (`Friday-23-02`: 36.3%) |
| Windows containing ≥ 1 attack flow (non-Attempted) | Mon 0, Tue 2,652, Wed 1,148, Thu 557, Fri 1,366 | 125–10,193 per day |

**Assessment (VERIFIED from the counts).**

- 2-second windows are **viable as a regular time grid**: traffic is nearly continuous within each day, except for the stray rows above. The longest gap between consecutive flow starts is 130 s (`Friday-16-02`), and the longest run of empty windows is 64 (128 s).
- But **a quarter to a third of flows last longer than a window**. A "flow-start" window state therefore does not represent *all activity* in that window. A long flow contributes only at its start, and its features summarise its whole future duration (up to 120 s).
- **A flow-level feature such as `Flow Duration` or total bytes, read at the window where the flow starts, contains information from the future** relative to that window. For an honest *forecasting* setup:
  1. build window features only from flows that have **ended** by the window's end, using start + duration; or
  2. restrict to "flow-start" counts and header-level features; or
  3. lag every window feature by at least the 120 s flow timeout.

  This is a central design decision. Making no choice silently leaks future information.

## 4. Attack episodes and onsets (`attack_segments.csv`)

**Definition of an episode.** An episode ("segment") is a run of flows of one attack family (label without "- Attempted") in which consecutive attack flows are no more than *G* seconds apart. Attempted flows are excluded.

| | 2017, G = 60 s | 2017, G = 300 s | 2018, G = 60 s | 2018, G = 300 s |
|---|---:|---:|---:|---:|
| Episodes | 98 | **24** | 285 | **38** |
| Families | 15 | 15 | 14 | 14 |
| Overlapping a previous episode | 12 | 2 | 73 | 12 |
| Starting within 120 s of the file start (censored) | 0 | 0 | 0 | 0 |
| Lead ≥ 60 s before onset (from the previous attack or the file start) | 91 | 24 | 264 | 37 |
| Median lead | 120 s | 1,536 s | 120 s | 6,889 s |

- **Attacks are scripted blocks.** At G = 300 s, each day holds 1–9 episodes lasting from seconds to 5.7 h. Most families occur in **one** episode on **one** day. For example, 2017 DoS Hulk is a single 1,091 s block; 2018 HOIC is a single 3,285 s block.
- **Onset forecasting has very few events:** 24 (2017) and 38 (2018) onsets in total, with many families contributing exactly one. Any onset metric needs exact counts and bootstrap CIs over episodes, and per-family onset results are anecdotal.
- **No onset is censored at the file start**, so every episode has benign history before it.
- **Two lead-time caveats.** Overlapping episodes, such as the infiltration stages, have lead times measured from the file start, which overstates them. The 178,235 s lead of `Friday-23-02` web brute force is an artefact of the stray rows.

## 5. Next-window target prevalence (2 s windows, horizons h = 1…5)

The target is y(t+h) = 1 if any non-Attempted attack flow starts in window t+h. Empty windows count as benign. These are summed over the improved days.

| | Windows | Positive | Positive rate | "Onset-like": benign at t, attack at t+h | Share of positives where window t is already an attack (persistence) |
|---|---:|---:|---:|---:|---:|
| 2017 h = 1 | 73,450 | 5,723 | 7.79% | 1,643 | 71.3% |
| 2017 h = 5 | 73,430 | 5,723 | 7.79% | 1,548 | 73.0% |
| 2018 h = 1 | 214,422 | 22,183 | 10.35% | 1,621 | 92.7% |
| 2018 h = 5 | 214,382 | 22,183 | 10.35% | 1,747 | 92.1% |

- **Stray rows excluded.** The 2018 rows exclude the 2,609 stray flows of `Friday-23-02` (21–22 Feb).
  - A first version included their span: 300,254 windows and a 7.39% positive rate. That diluted the rate with about 86,000 empty windows.
  - The corrected figures were recomputed independently in the self-review (`results/audit/self_review_checks.csv`, R09c/R09d; `reports/self_review.md`).
- **Ranges across all horizons h = 1…5:**

  | | Persistence share | Onset-like transitions |
  |---|---:|---:|
  | 2017 | 66.9–73.0% | 1,548–1,895 |
  | 2018 | 90.9–93.1% | 1,529–2,009 |

- **Persistence explains most positives**: 67–73% in 2017, 91–93% in 2018. A model that copies the current window's state will look strong at every horizon. **The persistence baseline is mandatory.**
- **"Onset-like" transitions far outnumber true episode onsets** (1,529–2,009 per horizon, against 24 or 38 episode onsets). Most are attack-flow intermittency *inside* an episode, where slow or low-rate attacks leave 2 s windows with no new attack flow start. Next-window "early warning" scores therefore mostly measure **within-episode re-occurrence**, not anticipation of a new attack.

## 6. Recommended target definitions

| Target | Supported? | Definition and conditions |
|---|---|---|
| **Current-window detection** (h = 0) | **Yes** | Label each 2 s window by whether any attack flow starts in it. Features may use only information available by the window's end (§3). |
| **Next-window attack-state prediction** (h = 1…5) | **Yes, with caveats** | As above at t+h. It **must** be compared with persistence, and scores must be reported separately for (a) all windows, (b) windows where t is benign, and (c) true episode onsets. |
| **Attack-onset forecasting** | **Weakly** | Only on the episode onsets in §4: 24 and 38, each with ≥ 60 s of benign lead. Report onset recall at fixed false alerts per hour, with exact counts and CIs. Too few events for per-family claims. |
| **Attack-stage / trajectory prediction** | **Only for the multi-stage scenarios** | 2017 infiltration (Dropbox download → portscan → …) and 2018 infiltration (Dropbox → C2 → NMAP portscan): a handful of sequences. Treat as case studies, not a benchmark. |

A label cannot provide a precise onset **inside** a flow. Onsets are defined at flow-start granularity, not packet granularity.

## 7. Censoring, missing periods, ambiguous transitions

- **No capture outage longer than 130 s inside any improved day**, apart from the stray-row gap in `Friday-23-02`. The nightly gaps between days are boundaries, never interiors.
- **Attempted flows near onsets.** Category 2 "startup artefacts" (e.g. a first visit to DVWA, a test login) **precede** some attack episodes by design. A model could learn them as precursors. That is legitimate attacker activity, but it should be reported separately, because it reflects the testbed's scripting.
- **Overlapping families.** 2018 infiltration stages overlap in time (12 of 38 episodes at G = 300 s). A multi-class window label needs a precedence rule, or else a multi-label target.

## 8. Why the originals cannot support temporal work

| | 2017 original | 2018 original |
|---|---|---|
| Resolution | **minutes** (Monday: seconds) | seconds |
| Clock | 12-hour **without AM/PM**, local time UTC−3 (VERIFIED) | 12-hour **without AM/PM**, local time UTC−4 (VERIFIED on the one day with 5-tuples) |
| Completeness | full days | **7 of 10 files capped at 1,048,575 rows** |

The original releases therefore cannot form 2 s windows: 2017 for lack of resolution, 2018 for lack of complete days. An original-versus-improved temporal comparison is possible only for **2017 at ≥ 60 s windows**, after converting to UTC (hours 1–7 → 13–19, then +3 h; see `configs/experiment_matrix.yaml` E3).
