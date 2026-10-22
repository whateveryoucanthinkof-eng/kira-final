"""Systematic citation search for the literature review (Phase 7, item "systematic search").

Forward citation tracking of the seed papers in two open bibliographic databases, plus a
transparent keyword screen of title + abstract. Nothing here decides inclusion on its own: the
screen only orders the candidates; the manual decisions are recorded separately in
results/literature/manual_screening.csv.

Sources (public APIs, read-only GET requests, no API key, no personal data sent)
    OpenAlex          https://api.openalex.org/works?filter=cites:<id>
    Semantic Scholar  https://api.semanticscholar.org/graph/v1/paper/DOI:<doi>/citations

Usage (from the project root)
    python -I src/lit/citation_search.py fetch  [--out-dir references/literature_search_<date>]
    python -I src/lit/citation_search.py screen [--overwrite]
    python -I src/lit/citation_search.py search [--overwrite]   # OpenAlex keyword queries (KEYWORD_QUERIES)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEEDS = {
    "CNS2022": "10.1109/CNS56114.2022.9947235",   # Liu, Engelen et al., Error Prevalence in NIDS datasets
    "Engelen2021": "10.1109/SPW53761.2021.00009",  # Engelen, Rimmer, Joosen, Troubleshooting ... CICIDS2017
}
UA = "research-paper-literature-audit/1.0 (no contact supplied)"
OUT_CSV = ROOT / "results/literature/citing_works_screened.csv"

# Screening vocabulary (lower-case regexes on title + abstract). Kept deliberately broad.
TERMS = {
    "temporal": [r"forecast", r"\bpredict(?:ion|ing|ive)? (?:of )?(?:future |upcoming )?(?:attack|intrusion|threat)",
                 r"early[- ](?:warning|prediction|detection|stage)", r"next[- ](?:window|step|stage)",
                 r"time[- ]series", r"\btemporal", r"\bsequen(?:ce|tial)", r"\blstm\b", r"\bgru\b", r"\brnn\b",
                 r"\btcn\b", r"recurrent", r"transformer", r"chronolog", r"time[- ]aware", r"concept drift",
                 r"\bdrift\b", r"sliding window", r"time window", r"attack (?:stage|projection|progression)",
                 r"multi-?stage", r"kill[- ]chain"],
    "dataset_quality": [r"improved (?:version|dataset|cic)", r"corrected", r"distrinet", r"relabel", r"label(?:l)?ing (?:error|issue|noise)",
                        r"label noise", r"error prevalence", r"lycos", r"flaw", r"artefact|artifact", r"data quality",
                        r"cicflowmeter", r"\bcns ?2022\b"],
    "evaluation": [r"leak", r"data snooping", r"\bsplit", r"generali[sz]", r"cross[- ]dataset", r"shortcut",
                   r"spurious", r"pitfall", r"benchmark", r"realistic evaluation", r"overestimat", r"out[- ]of[- ]distribution"],
}
RX = {k: [re.compile(t) for t in v] for k, v in TERMS.items()}


def get_json(url: str, raw_path: Path, retries: int = 6) -> dict:
    """GET with polite retries; the raw response is saved verbatim (never overwritten)."""
    if raw_path.exists():
        return json.loads(raw_path.read_text(encoding="utf-8"))
    delay = 3.0
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read().decode("utf-8")
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(body, encoding="utf-8")
            return json.loads(body)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError(url)


def abstract_from_index(inv: dict | None) -> str:
    if not inv:
        return ""
    pos = sorted((i, w) for w, idx in inv.items() for i in idx)
    return " ".join(w for _, w in pos)


def fetch(out_dir: Path) -> int:
    log = []
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    for seed, doi in SEEDS.items():
        # OpenAlex: resolve the seed, then page through works citing it (cursor paging)
        w = get_json(f"https://api.openalex.org/works/https://doi.org/{doi}?select=id,display_name,cited_by_count",
                     out_dir / "raw" / f"openalex_{seed}_seed.json")
        oid = w["id"].rsplit("/", 1)[-1]
        cursor, page = "*", 0
        sel = "id,doi,display_name,publication_year,primary_location,type,abstract_inverted_index,cited_by_count"
        while cursor:
            url = (f"https://api.openalex.org/works?filter=cites:{oid}&per-page=200&select={sel}"
                   f"&cursor={urllib.parse.quote(cursor)}")
            d = get_json(url, out_dir / "raw" / f"openalex_{seed}_p{page:02d}.json")
            log.append({"utc": stamp, "source": "OpenAlex", "seed": seed, "query": url, "n_results": len(d["results"]),
                        "reported_total": d["meta"]["count"]})
            cursor = d["meta"].get("next_cursor") if d["results"] else None
            page += 1
        # Semantic Scholar: offset paging (max 1000 per call)
        offset, page = 0, 0
        while offset is not None:
            url = (f"https://api.semanticscholar.org/graph/v1/paper/DOI:{doi}/citations?"
                   f"fields=title,year,venue,externalIds,abstract,url,publicationTypes&limit=500&offset={offset}")
            d = get_json(url, out_dir / "raw" / f"s2_{seed}_p{page:02d}.json")
            n = len(d.get("data", []))
            log.append({"utc": stamp, "source": "SemanticScholar", "seed": seed, "query": url, "n_results": n,
                        "reported_total": ""})
            offset = d.get("next")
            page += 1
            time.sleep(1.5)
    with (out_dir / "query_log.csv").open("a", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(log[0]))
        if fh.tell() == 0:
            wr.writeheader()
        wr.writerows(log)
    print(f"fetched {len(log)} pages into {out_dir}")
    return 0


def norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def screen(out_dir: Path, overwrite: bool) -> int:
    if OUT_CSV.exists() and not overwrite:
        print(f"refusing to overwrite {OUT_CSV} (pass --overwrite)")
        return 2
    works: dict[str, dict] = {}

    def add(key, title, year, venue, doi, url, abstract, seed, source):
        w = works.setdefault(key, {"title": title, "year": year, "venue": venue, "doi": doi, "url": url,
                                   "abstract": "", "seeds": set(), "sources": set()})
        if abstract and len(abstract) > len(w["abstract"]):
            w["abstract"] = abstract
        for f, v in (("doi", doi), ("venue", venue), ("year", year), ("url", url)):
            if v and not w[f]:
                w[f] = v
        w["seeds"].add(seed)
        w["sources"].add(source)

    raw = out_dir / "raw"
    by_title: dict[str, str] = {}

    def key_for(doi: str, title: str) -> str:
        nt = norm_title(title)
        if doi:
            k = "doi:" + doi.lower()
            by_title.setdefault(nt, k)
            return k
        return by_title.get(nt, "title:" + nt)

    for p in sorted(raw.glob("openalex_*_p*.json")):
        seed = p.stem.split("_")[1]
        for r in json.loads(p.read_text(encoding="utf-8"))["results"]:
            doi = (r.get("doi") or "").replace("https://doi.org/", "")
            loc = r.get("primary_location") or {}
            venue = ((loc.get("source") or {}).get("display_name")) or ""
            add(key_for(doi, r.get("display_name") or ""), r.get("display_name") or "", r.get("publication_year"),
                venue, doi, r["id"], abstract_from_index(r.get("abstract_inverted_index")), seed, "OpenAlex")
    for p in sorted(raw.glob("s2_*_p*.json")):
        seed = p.stem.split("_")[1]
        for c in json.loads(p.read_text(encoding="utf-8")).get("data", []):
            r = c.get("citingPaper") or {}
            if not r.get("title"):
                continue
            doi = ((r.get("externalIds") or {}).get("DOI") or "")
            arxiv = (r.get("externalIds") or {}).get("ArXiv") or ""
            add(key_for(doi, r["title"]), r["title"], r.get("year"), r.get("venue") or "", doi,
                r.get("url") or (f"https://arxiv.org/abs/{arxiv}" if arxiv else ""), r.get("abstract") or "", seed,
                "SemanticScholar")
    rows = []
    for k, w in works.items():
        text = (w["title"] + " " + w["abstract"]).lower()
        hits = {cat: sorted({m.group(0) for rx in rxs for m in rx.finditer(text)}) for cat, rxs in RX.items()}
        t, q, e = (bool(hits[c]) for c in ("temporal", "dataset_quality", "evaluation"))
        tier = ("A: temporal + (dataset quality or evaluation)" if t and (q or e) else "B: temporal" if t
                else "C: dataset quality / evaluation" if (q or e) else "X: none of the screening topics")
        rows.append({"key": k, "title": w["title"], "year": w["year"], "venue": w["venue"], "doi": w["doi"],
                     "url": w["url"], "cites": "+".join(sorted(w["seeds"])), "sources": "+".join(sorted(w["sources"])),
                     "has_abstract": bool(w["abstract"]), "temporal_terms": "; ".join(hits["temporal"]),
                     "dataset_quality_terms": "; ".join(hits["dataset_quality"]),
                     "evaluation_terms": "; ".join(hits["evaluation"]), "screen_tier": tier,
                     "abstract": w["abstract"][:3000]})
    rows.sort(key=lambda r: (r["screen_tier"], -(r["year"] or 0), r["title"].lower()))
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    from collections import Counter
    print(f"{len(rows)} unique citing works ->", dict(Counter(r["screen_tier"][0] for r in rows)),
          "| no abstract:", sum(not r["has_abstract"] for r in rows))
    return 0


KEYWORD_QUERIES = [
    '"attack forecasting" network',
    '"attack prediction" network intrusion "time series"',
    '"next window" intrusion detection',
    '"early warning" network intrusion flows',
    '"network security situation" forecasting',
    '"CSE-CIC-IDS2018" forecasting',
    '"CIC-IDS2017" forecasting',
    '"CIC-IDS2017" "temporal split"',
    '"CIC-IDS2018" chronological split',
    '"Distrinet-CIC-IDS2017"',
    '"improved CIC-IDS2017"',
    '"corrected CIC-IDS2017"',
    'intrusion prediction "sliding window" "CIC-IDS"',
    'attack onset prediction network traffic',
]
OUT_KW = ROOT / "results/literature/keyword_search_results.csv"


def keyword_search(out_dir: Path, overwrite: bool) -> int:
    """OpenAlex title/abstract search for each query (first 200 hits by relevance)."""
    if OUT_KW.exists() and not overwrite:
        print(f"refusing to overwrite {OUT_KW} (pass --overwrite)")
        return 2
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    rows, log = [], []
    sel = "id,doi,display_name,publication_year,primary_location,abstract_inverted_index,cited_by_count"
    for qi, q in enumerate(KEYWORD_QUERIES):
        url = (f"https://api.openalex.org/works?filter=title_and_abstract.search:{urllib.parse.quote(q)}"
               f"&per-page=200&select={sel}&sort=relevance_score:desc")
        d = get_json(url, out_dir / "raw" / f"openalex_kw{qi:02d}.json")
        log.append({"utc": stamp, "source": "OpenAlex search", "seed": f"kw{qi:02d}: {q}", "query": url,
                    "n_results": len(d["results"]), "reported_total": d["meta"]["count"]})
        for r in d["results"]:
            text = ((r.get("display_name") or "") + " " + abstract_from_index(r.get("abstract_inverted_index"))).lower()
            hits = {c: sorted({m.group(0) for rx in rxs for m in rx.finditer(text)}) for c, rxs in RX.items()}
            loc = r.get("primary_location") or {}
            rows.append({"query_id": f"kw{qi:02d}", "query": q, "title": r.get("display_name") or "",
                         "year": r.get("publication_year"), "venue": ((loc.get("source") or {}).get("display_name")) or "",
                         "doi": (r.get("doi") or "").replace("https://doi.org/", ""), "url": r["id"],
                         "cited_by": r.get("cited_by_count"),
                         "temporal_terms": "; ".join(hits["temporal"]),
                         "dataset_quality_terms": "; ".join(hits["dataset_quality"]),
                         "evaluation_terms": "; ".join(hits["evaluation"]),
                         "mentions_cic": bool(re.search(r"cic-?ids|cse-cic|cicids", text)),
                         "abstract": abstract_from_index(r.get("abstract_inverted_index"))[:3000]})
        time.sleep(0.5)
    with (out_dir / "query_log.csv").open("a", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(log[0]))
        wr.writerows(log)
    OUT_KW.parent.mkdir(parents=True, exist_ok=True)
    with OUT_KW.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(rows[0]))
        wr.writeheader()
        wr.writerows(rows)
    for l in log:
        print(l["seed"], "->", l["n_results"], "of", l["reported_total"])
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=["fetch", "screen", "search"])
    ap.add_argument("--out-dir", type=Path, default=ROOT / "references/literature_search_2026-10-19")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "search":
        return keyword_search(a.out_dir, a.overwrite)
    return fetch(a.out_dir) if a.cmd == "fetch" else screen(a.out_dir, a.overwrite)


if __name__ == "__main__":
    sys.exit(main())
