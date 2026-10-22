"""Download the open-access study papers into study/ (one sub-folder per study-guide step).

Only legal open sources are used: arXiv, open-access publishers (SciTePress, PLOS, MDPI, BMJ),
the RFC Editor, the ACM open backfile, and author / institutional repositories (KU Leuven Lirias,
HAL, Edinburgh ERA). Third-party uploads of paywalled papers are NOT used; those papers are listed
in study/README.md for library access.

Every file is written to <name>.partial, checked (PDF magic bytes, or HTML for web chapters),
then renamed. Existing files are never overwritten. One attempt per URL: a refusal (e.g. HTTP 403)
is recorded, not worked around. Results: study/download_log.csv.

Usage (from the project root)
    python -I src/lit/fetch_study_papers.py
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STUDY = ROOT / "study"
UA = "Mozilla/5.0 (research-paper study reading list; single download per file)"

# (folder, file name, url or local path, kind, citation)
ITEMS = [
    ("01_networking_and_flows", "RFC7011_IPFIX_2013.txt", "https://www.rfc-editor.org/rfc/rfc7011.txt", "text",
     "Claise, Trammell, Aitken. RFC 7011: Specification of the IP Flow Information Export (IPFIX) Protocol. IETF, 2013."),
    ("02_datasets_and_their_errors", "Sharafaldin2018_CICIDS2017_ICISSP.pdf",
     "https://www.scitepress.org/Papers/2018/66398/66398.pdf", "pdf",
     "Sharafaldin, Habibi Lashkari, Ghorbani. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018."),
    ("02_datasets_and_their_errors", "Engelen2021_Troubleshooting_CICIDS2017_SPW.pdf",
     "https://lirias.kuleuven.be/retrieve/713070", "pdf",
     "Engelen, Rimmer, Joosen. Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study. IEEE SPW 2021 (author version, KU Leuven Lirias)."),
    ("02_datasets_and_their_errors", "Liu2022_Error_Prevalence_CNS2022.pdf",
     "local:Error_Prevalence_in_NIDS_datasets_A_Case_Study_on_CIC-IDS-2017_and_CSE-CIC-IDS-2018.pdf", "pdf",
     "Liu, Engelen, Lynar, Essam, Joosen. Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018. IEEE CNS 2022 (copy of the PDF already in the project)."),
    ("02_datasets_and_their_errors", "Rosay2022_LycoS_CICIDS2017_ICISSP.pdf",
     "https://www.scitepress.org/Papers/2022/107740/107740.pdf", "pdf",
     "Rosay, Cheval, Carlier, Leroux. Network Intrusion Detection: A Comprehensive Analysis of CIC-IDS2017. ICISSP 2022 (SciTePress open access)."),
    ("02_datasets_and_their_errors", "Lanvin2022_Errors_in_CICIDS2017_CRiSIS.pdf",
     "https://hal.science/hal-03775466v1/file/CRiSIS_2022_Maxime_Lanvin.pdf", "pdf",
     "Lanvin et al. Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes. CRiSIS 2022 (HAL)."),
    ("02_datasets_and_their_errors", "Flood_PhD_thesis_Edinburgh_incl_Bad_Design_Smells.pdf",
     "https://era.ed.ac.uk/bitstreams/f235af63-4123-4f6a-a795-433e8b930ec7/download", "pdf",
     "Flood. Enhancing trust in NIDS: from flawed benchmarks to formal guarantees. PhD thesis, University of Edinburgh (contains the EuroS&P 2024 'Bad Design Smells' work)."),
    ("04_leakage_and_evaluation", "Arp2022_Dos_and_Donts_ML_Security_USENIX.pdf", "https://arxiv.org/pdf/2010.09470", "pdf",
     "Arp et al. Dos and Don'ts of Machine Learning in Computer Security. USENIX Security 2022 (arXiv 2010.09470)."),
    ("04_leakage_and_evaluation", "Geirhos2020_Shortcut_Learning.pdf", "https://arxiv.org/pdf/2004.07780", "pdf",
     "Geirhos et al. Shortcut Learning in Deep Neural Networks. Nature Machine Intelligence 2020 (arXiv 2004.07780)."),
    ("04_leakage_and_evaluation", "Cantone2024_Cross_Dataset_Generalization_NIDS.pdf", "https://arxiv.org/pdf/2402.10974", "pdf",
     "Cantone et al. On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection. arXiv 2402.10974, 2024."),
    ("05_forecasting_basics", "FPP3_5.2_Some_simple_forecasting_methods.html", "https://otexts.com/fpp3/simple-methods.html", "manual",
     "Hyndman, Athanasopoulos. Forecasting: Principles and Practice, 3rd ed., section 5.2 (free online book; print from a browser)."),
    ("05_forecasting_basics", "FPP3_5.10_Time_series_cross_validation.html", "https://otexts.com/fpp3/tscv.html", "manual",
     "Hyndman, Athanasopoulos. Forecasting: Principles and Practice, 3rd ed., section 5.10 (free online book; print from a browser)."),
    ("06_metrics_for_rare_attacks", "Saito2015_Precision_Recall_Imbalanced_PLOSONE.pdf",
     "https://journals.plos.org/plosone/article/file?id=10.1371/journal.pone.0118432&type=printable", "pdf",
     "Saito, Rehmsmeier. The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets. PLOS ONE 2015."),
    ("06_metrics_for_rare_attacks", "Axelsson2000_Base_Rate_Fallacy_TISSEC.pdf", "https://dl.acm.org/doi/pdf/10.1145/357830.357849", "manual",
     "Axelsson. The Base-Rate Fallacy and the Difficulty of Intrusion Detection. ACM TISSEC 3(3), 2000 (ACM open backfile)."),
    ("07_forecasting_literature_and_gap", "Moczkodan2026_Transformers_Temporal_CICIDS2017_arXiv.pdf", "https://arxiv.org/pdf/2606.11098", "pdf",
     "Moczkodan, Ragab. Do Transformers Actually Help Intrusion Detection? A Temporal Sequence Evaluation on CIC-IDS2017. arXiv 2606.11098, 2026."),
    ("07_forecasting_literature_and_gap", "Ahmed2024_Rapid_Forecasting_Cyber_Events_Information.pdf",
     "https://www.open-access.bcu.ac.uk/15482/1/information-15-00036.pdf", "pdf",
     "Ahmed, Azad, Asyhari. Rapid Forecasting of Cyber Events Using Machine Learning-Enabled Features. Information 15(1):36, 2024 (BCU open access)."),
    ("07_forecasting_literature_and_gap", "Ji2023_Temporal_Features_Forecast_Network_Events_AppliedSci.pdf",
     "https://www.mdpi.com/2076-3417/13/18/10411/pdf", "manual",
     "Ji, Jeong, Jeong. An Analysis of Temporal Features in Multivariate Time Series to Forecast Network Events. Applied Sciences 13(18):10411, 2023."),
    ("07_forecasting_literature_and_gap", "Youssef2026_Stream_Assembly_Streaming_IDS_arXiv.pdf", "https://arxiv.org/pdf/2605.24696", "pdf",
     "Youssef. Stream Assembly Is an Uncontrolled Treatment in Streaming Intrusion-Detection Benchmarks. arXiv 2605.24696, 2026."),
    ("07_forecasting_literature_and_gap", "Survey2026_Contextualized_NetFlow_NIDS_arXiv.pdf", "https://arxiv.org/pdf/2602.05594", "pdf",
     "Deep Learning for Contextualized NetFlow-Based Network Intrusion Detection: Methods, Data, Evaluation and Deployment. arXiv 2602.05594, 2026."),
    ("07_forecasting_literature_and_gap", "Wang2025_Modular_Intrusion_Predictors_arXiv.pdf", "https://arxiv.org/pdf/2511.23000", "pdf",
     "Wang, Stadler. A Modular Framework for Rapidly Building Intrusion Predictors. arXiv 2511.23000, 2025."),
    ("08_research_method", "Page2021_PRISMA2020_statement_BMJ.pdf", "https://www.bmj.com/content/372/bmj.n71.full.pdf", "manual",
     "Page et al. The PRISMA 2020 statement: an updated guideline for reporting systematic reviews. BMJ 372:n71, 2021."),
    ("08_research_method", "Kitchenham2007_SLR_Guidelines_EBSE.pdf",
     "https://www.elsevier.com/__data/promis_misc/525444systematicreviewsguide.pdf", "pdf",
     "Kitchenham, Charters. Guidelines for performing Systematic Literature Reviews in Software Engineering. EBSE Technical Report EBSE-2007-01, v2.3, 2007."),
]


def fetch(url: str) -> tuple[bytes, str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/pdf,text/html;q=0.9,*/*;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read(), r.geturl(), r.headers.get("Content-Type", "")
    except urllib.error.URLError as e:
        if "CERTIFICATE_VERIFY_FAILED" not in str(e.reason):
            raise
        # This Python lacks the issuing CA; curl uses the Windows certificate store. Verification stays on.
        import subprocess
        out = subprocess.run(["curl", "-sS", "-L", "--fail", "-A", UA, url], capture_output=True, timeout=300, check=True)
        return out.stdout, url, "via curl"


def main() -> int:
    STUDY.mkdir(exist_ok=True)
    log_path = STUDY / "download_log.csv"
    log = []
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    for folder, name, src, kind, cite in ITEMS:
        dest = STUDY / folder / name
        row = {"file": f"{folder}/{name}", "source": src, "citation": cite, "utc": stamp}
        if kind == "manual":  # the site refused an automated download on the first attempt; never retried
            row.update(status="manual: site refused automated download (HTTP 403 / challenge page); download in a browser",
                       bytes=0, sha256="")
            log.append(row)
            print(f"MANUAL {row['file']}")
            continue
        if dest.exists():
            row.update(status="exists, not overwritten", bytes=dest.stat().st_size,
                       sha256=hashlib.sha256(dest.read_bytes()).hexdigest())
            log.append(row)
            print(f"SKIP  {row['file']} (exists)")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if src.startswith("local:"):
                data, final, ctype = (ROOT / src[6:]).read_bytes(), src, "application/pdf"
            else:
                data, final, ctype = fetch(src)
        except urllib.error.HTTPError as e:
            row.update(status=f"HTTP {e.code} (not retried)", bytes=0, sha256="")
            log.append(row)
            print(f"FAIL  {row['file']}: HTTP {e.code}")
            continue
        except Exception as e:  # network errors
            row.update(status=f"error: {type(e).__name__}", bytes=0, sha256="")
            log.append(row)
            print(f"FAIL  {row['file']}: {type(e).__name__}: {e}")
            continue
        ok = (data[:5] == b"%PDF-") if kind == "pdf" else (b"<html" in data[:2000].lower()) if kind == "html"             else data[:200].isascii() and b"<html" not in data[:2000].lower()
        if not ok:
            row.update(status=f"rejected: not a {kind} (content-type {ctype}, first bytes {data[:15]!r})",
                       bytes=len(data), sha256="")
            log.append(row)
            print(f"FAIL  {row['file']}: not a {kind}")
            continue
        part = dest.with_name(dest.name + ".partial")
        part.write_bytes(data)
        part.rename(dest)
        row.update(status="downloaded" if not src.startswith("local:") else "copied from project",
                   bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), final_url=final)
        log.append(row)
        print(f"OK    {row['file']} ({len(data) / 1e6:.1f} MB)")
    fields = ["file", "status", "bytes", "sha256", "source", "final_url", "citation", "utc"]
    new = not log_path.exists()
    with log_path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if new:
            w.writeheader()
        for r in log:
            w.writerow({k: r.get(k, "") for k in fields})
    n_ok = sum(r["status"] in ("downloaded", "copied from project") for r in log)
    print(f"{n_ok} of {len(log)} obtained; log: study/download_log.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
