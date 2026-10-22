"""Tests for SQL-building helpers in integrity.py / leakage.py / temporal.py (tiny in-memory data)."""
from __future__ import annotations

import duckdb

from src.audit import leakage, temporal
from src.audit.common import load_config
from src.audit.integrity import semantics_of


def test_semantics_patterns():
    cfg = load_config()
    assert semantics_of("Flow Duration", cfg) == "nonnegative"
    assert semantics_of("Total Bwd packets", cfg) == "nonnegative"
    assert semantics_of("FWD Init Win Bytes", cfg) == "sentinel_minus_one"
    assert semantics_of("ICMP Type", cfg) == "sentinel_minus_one"
    assert semantics_of("Dst Port", cfg) == ""


def test_class_expr():
    con = duckdb.connect()
    rows = con.execute(
        f"SELECT l, {leakage.class_expr('l')} FROM (VALUES ('BENIGN'), ('Benign'), ('DoS Hulk'), "
        "('DoS Hulk - Attempted'), (NULL)) t(l)").fetchall()
    assert dict(rows) == {"BENIGN": "benign", "Benign": "benign", "DoS Hulk": "attack",
                          "DoS Hulk - Attempted": "attempted", None: None}


def test_bin_expr_handles_sign_zero_nonfinite_and_null():
    con = duckdb.connect()
    vals = con.execute(
        f"SELECT x, {leakage.bin_expr('x')} FROM (VALUES (0.0), (1.0), (3.0), (-3.0), ('inf'::DOUBLE), "
        "('nan'::DOUBLE), (NULL)) t(x)").fetchall()
    got = {str(x): b for x, b in vals}
    assert got["0.0"] == "0" and got["1.0"] == "1" and got["3.0"] == "2" and got["-3.0"] == "-2"
    assert got["inf"] == "nonfinite" and got["nan"] == "nonfinite" and got["None"] == "null"


def test_within_file_time_split_with_embargo():
    con = duckdb.connect()
    con.execute("CREATE TABLE hf AS SELECT 'f' AS file, TIMESTAMP '2017-07-04 00:00:00' + to_seconds(i) AS ts, "
                "TIMESTAMP '2017-07-04 00:00:00' AS fmin, TIMESTAMP '2017-07-04 00:00:00' + to_seconds(999) AS fmax "
                "FROM range(1000) r(i)")
    sql = leakage.split_sql({"kind": "within_file_time", "fractions": [0.6, 0.2, 0.2], "embargo_s": 10})
    parts = dict(con.execute(f"SELECT {sql} p, count(*) FROM hf GROUP BY 1").fetchall())
    # cuts at 599.4 s and 799.2 s; rows within +-10 s of a cut are embargoed
    assert parts["embargo"] == 40
    assert parts["train"] + parts["val"] + parts["test"] + parts["embargo"] == 1000
    assert con.execute(f"SELECT max(ts) FROM hf WHERE {sql} = 'train'").fetchone()[0] < \
        con.execute(f"SELECT min(ts) FROM hf WHERE {sql} = 'val'").fetchone()[0]


def test_within_file_flow_quantile_split_ignores_excluded_rows():
    con = duckdb.connect()
    # 1000 flows, one per second; plus 50 excluded stray rows a day earlier that must not move the cuts
    con.execute("CREATE TABLE hf AS SELECT 'f' AS file, TIMESTAMP '2017-07-04 00:00:00' + to_seconds(i) AS ts, "
                "false AS excluded FROM range(1000) r(i) UNION ALL SELECT 'f', TIMESTAMP '2017-07-03 00:00:00' "
                "+ to_seconds(i), true FROM range(50) r(i)")
    sql = leakage.split_sql({"kind": "within_file_flow_quantile", "fractions": [0.6, 0.2, 0.2], "embargo_s": 10})
    parts = dict(con.execute(f"SELECT p, count(*) FROM (SELECT {sql} p, excluded FROM hf) WHERE NOT excluded "
                             "GROUP BY 1").fetchall())
    # cuts at the 60% / 80% flow quantiles (~599 s and ~799 s); +-10 s around each is embargoed
    assert parts["embargo"] == 42
    assert 580 <= parts["train"] <= 600 and 170 <= parts["val"] <= 200 and 180 <= parts["test"] <= 200
    assert sum(parts.values()) == 1000


def test_by_file_split():
    con = duckdb.connect()
    sql = leakage.split_sql({"kind": "by_file", "train": ["a.csv"], "val": ["b.csv"], "test": ["c.csv"]})
    got = dict(con.execute(f"SELECT file, {sql} FROM (VALUES ('a.csv'), ('b.csv'), ('c.csv'), ('d.csv')) t(file)").fetchall())
    assert got == {"a.csv": "train", "b.csv": "val", "c.csv": "test", "d.csv": "unused"}


def test_temporal_segments_and_lead_time(tmp_path):
    con = duckdb.connect()
    p = (tmp_path / "t.parquet").as_posix()
    con.execute(
        f"COPY (SELECT * FROM (VALUES "
        "(TIMESTAMP '2018-02-14 10:00:00', 'BENIGN'), (TIMESTAMP '2018-02-14 10:05:00', 'SSH-BruteForce'), "
        "(TIMESTAMP '2018-02-14 10:05:30', 'SSH-BruteForce'), (TIMESTAMP '2018-02-14 10:20:00', 'SSH-BruteForce'), "
        "(TIMESTAMP '2018-02-14 10:21:00', 'SSH-BruteForce - Attempted')) t(ts, label)) "
        f"TO '{p}' (FORMAT parquet)")
    segs = temporal.segments(con, f"read_parquet('{p}')", "x.csv", [], 60)
    assert [(s["start"][-8:], s["n_attack_flows"]) for s in segs] == [("10:05:00", 2), ("10:20:00", 1)]
    assert segs[0]["lead_since_prev_attack_or_file_start_s"] == 300.0   # from file start 10:00
    assert segs[1]["lead_since_prev_attack_or_file_start_s"] == 870.0   # from previous segment end 10:05:30
    assert segs[0]["lead_windows_2s"] == 150


def test_hash_expr_hashes_numbers_by_value_not_text():
    from src.audit.integrity import hash_expr

    class FakeView:
        def col(self, c):
            return '"' + c + '"'

    expr = hash_expr(FakeView(), ["Fwd RST Flags", "Src IP"])
    con = duckdb.connect()
    a, b, c = con.execute(
        f"SELECT {expr} FROM (VALUES ('0', '1.2.3.4'), ('0.0', '1.2.3.4'), ('1', '1.2.3.4')) t(\"Fwd RST Flags\", \"Src IP\")"
    ).fetchall()
    assert a == b and a != c
