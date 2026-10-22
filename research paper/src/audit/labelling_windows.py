"""Extract the documented attack windows from the authors' labelling notebooks (static parse).

The CNS2022 labelling notebooks label flows with calls such as
``label_flows(df, "DoS Hulk", <start_ns>, <end_ns>, [src ips], [dst ips], ...)``.
This module parses the notebooks with ``ast`` (NOTHING is executed), binds each call's
arguments to the parameter list of that notebook's own ``def label_flows``, and writes
one row per labelling rule.

Rules are applied in order and later rules overwrite earlier ones, so ``rule_order``
is kept. Time windows are UTC Unix nanoseconds per the notebooks' own comments.

Usage (from the project root)
-----------------------------
    python -I src/audit/labelling_windows.py
"""
from __future__ import annotations

import argparse
import ast
import csv
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_NOTEBOOKS = {
    "CIC-IDS-2017": "references/CNS2022_Code/Labelling/CICIDS2017_labelling_fixed_CICFlowMeter.ipynb",
    "CSE-CIC-IDS-2018": "references/CNS2022_Code/Labelling/CICIDS2018_labelling_fixed_CICFlowMeter.ipynb",
}
FIELDS = [
    "dataset", "file", "rule_order", "label", "attempted_category", "start_ns", "end_ns",
    "start_utc", "end_utc", "duration_s", "src_ips", "dst_ips", "src_ports", "dst_ports",
    "payload_filter", "additional_filters", "notebook", "cell_index", "lineno", "repo_commit",
    "evidence_status",
]


def safe_value(node: ast.AST):
    """Evaluate literals and simple integer arithmetic (e.g. ``1518618806*(10**9)``).

    Raises ValueError for anything else, so arbitrary code is never evaluated.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, str, bool, type(None))):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        return [safe_value(e) for e in node.elts]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -safe_value(node.operand)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Pow, ast.Add, ast.Sub)):
        a, b = safe_value(node.left), safe_value(node.right)
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (a, b)):
            raise ValueError("non-integer arithmetic")
        if isinstance(node.op, ast.Pow):
            if not 0 <= b <= 64:
                raise ValueError("exponent out of range")
            return a**b
        if isinstance(node.op, ast.Mult):
            return a * b
        return a + b if isinstance(node.op, ast.Add) else a - b
    raise ValueError(f"unsupported node {type(node).__name__}")


def _string_constants(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def ns_to_utc(ns) -> str:
    if not isinstance(ns, int):
        return ""
    secs, rem = divmod(ns, 10**9)
    base = dt.datetime.fromtimestamp(secs, tz=dt.timezone.utc).replace(tzinfo=None)
    return f"{base.isoformat()}.{rem:09d}"


def extract_rules(nb_path: Path, dataset: str, commit: str = "") -> list[dict]:
    """Return one dict per ``label_flows`` call, in notebook order."""
    nb = json.loads(nb_path.read_text(encoding="utf-8"))
    cells = [(i, "".join(c["source"])) for i, c in enumerate(nb["cells"]) if c["cell_type"] == "code"]
    params: list[str] | None = None
    defaults: dict[str, object] = {}
    calls, writes, dir_name = [], {}, None
    for idx, src in cells:
        tree = ast.parse(src)
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef) and stmt.name == "label_flows":
                params = [a.arg for a in stmt.args.args]
                for a, d in zip(stmt.args.args[-len(stmt.args.defaults):], stmt.args.defaults):
                    try:
                        defaults[a.arg] = safe_value(d)
                    except ValueError:
                        defaults[a.arg] = ast.get_source_segment(src, d)
            elif (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                  and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == "dir_name"):
                dir_name = safe_value(stmt.value)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
                    and isinstance(stmt.value.func, ast.Name):
                call, name = stmt.value, stmt.value.func.id
                if name == "label_flows":
                    calls.append((idx, src, call))
                elif name == "label_rest_as_benign_and_write_csv":
                    var = call.args[0].id
                    consts = _string_constants(call.args[1])
                    if consts == [".csv"] and dir_name:
                        writes[var] = f"{dir_name}.csv"
                    else:
                        writes[var] = Path(consts[-1]).name if consts else ""
    if params is None:
        raise ValueError(f"no `def label_flows` found in {nb_path}")

    rows = []
    for order, (idx, src, call) in enumerate(calls, start=1):
        bound = dict(defaults)
        for pname, arg in zip(params, call.args):
            bound[pname] = arg
        for kw in call.keywords:
            bound[kw.arg] = kw.value

        def val(name):
            v = bound.get(name)
            if isinstance(v, ast.AST):
                try:
                    return safe_value(v)
                except ValueError:
                    return ast.get_source_segment(src, v)
            return v

        df_var = bound["df"].id if isinstance(bound.get("df"), ast.Name) else ""
        start, end = val("attack_start_time_nanoseconds"), val("attack_end_time_nanoseconds")
        filters = bound.get("additional_filters")
        filt_src = ast.get_source_segment(src, filters) if isinstance(filters, ast.AST) else ""
        rows.append({
            "dataset": dataset, "file": writes.get(df_var, ""), "rule_order": order,
            "label": val("label"), "attempted_category": val("attempted_category"),
            "start_ns": start, "end_ns": end, "start_utc": ns_to_utc(start), "end_utc": ns_to_utc(end),
            "duration_s": round((end - start) / 1e9, 6) if isinstance(start, int) and isinstance(end, int) else "",
            "src_ips": json.dumps(val("src_ip_list")), "dst_ips": json.dumps(val("dst_ip_list")),
            "src_ports": json.dumps(val("src_port_list")) if "src_port_list" in params else "n/a",
            "dst_ports": json.dumps(val("dst_port_list")),
            "payload_filter": bool(val("payload_filter")),
            "additional_filters": " ".join((filt_src or "").split()),
            "notebook": nb_path.as_posix(), "cell_index": idx, "lineno": call.lineno,
            "repo_commit": commit, "evidence_status": "DOCUMENTED",
        })
    return rows


def repo_commit(repo: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--out", type=Path, default=Path("results/audit/attack_windows_documented.csv"))
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args(argv)
    root = args.root.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    if out.exists() and not args.overwrite:
        print(f"refusing to overwrite {out} (pass --overwrite)", file=sys.stderr)
        return 2
    commit = repo_commit(root / "references/CNS2022_Code")
    rows = []
    for dataset, nb in DEFAULT_NOTEBOOKS.items():
        found = extract_rules(root / nb, dataset, commit)
        for r in found:  # record the notebook relative to the project root (no absolute paths in outputs)
            r["notebook"] = Path(nb).as_posix()
        rows.extend(found)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} labelling rules to {out.relative_to(root).as_posix()} (commit {commit[:10]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
