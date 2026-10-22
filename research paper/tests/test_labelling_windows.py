"""Tests for src/audit/labelling_windows.py (synthetic notebooks only; nothing is executed)."""
from __future__ import annotations

import ast
import json

import pytest

from src.audit import labelling_windows as lw


def write_nb(path, cells):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {},
          "cells": [{"cell_type": "code", "metadata": {}, "outputs": [], "execution_count": None,
                     "source": src} for src in cells]}
    path.write_text(json.dumps(nb), encoding="utf-8")


DEF_2018 = (
    "def label_flows(df, label, attack_start_time_nanoseconds, attack_end_time_nanoseconds, src_ip_list=None,\n"
    "                dst_ip_list=None, dst_port_list=None, attempted_category=-1, additional_filters=[], payload_filter = False):\n"
    "    pass\n"
)


def test_safe_value_arithmetic_and_rejects_code():
    assert lw.safe_value(ast.parse("1518618806*(10**9)", mode="eval").body) == 1518618806 * 10**9
    assert lw.safe_value(ast.parse("['a', 'b']", mode="eval").body) == ["a", "b"]
    with pytest.raises(ValueError):
        lw.safe_value(ast.parse("__import__('os').system('x')", mode="eval").body)
    with pytest.raises(ValueError):
        lw.safe_value(ast.parse("2**10000", mode="eval").body)


def test_extract_binds_positional_and_keyword_args(tmp_path):
    nb = tmp_path / "nb.ipynb"
    write_nb(nb, [
        DEF_2018,
        'dir_name = "Wednesday-14-02-2018"\n'
        'wed_df = read(DATASET_PATH + dir_name + "/csv")\n'
        'label_flows(wed_df, "SSH-BruteForce", 1518631310*(10**9), 1518636750*(10**9), ["13.58.98.64"], ["172.31.69.25"], [22])\n'
        'label_flows(wed_df, "SSH-BruteForce - Attempted", 1518631310*(10**9), 1518636750*(10**9), ["13.58.98.64"],\n'
        '            ["172.31.69.25"], [22], attempted_category=0, payload_filter=True,\n'
        '            additional_filters=[wed_df["Src Port"] != 68])\n'
        'label_rest_as_benign_and_write_csv(wed_df, DATASET_PATH + dir_name + ".csv")\n',
    ])
    rows = lw.extract_rules(nb, "CSE-CIC-IDS-2018", "abc")
    assert [r["rule_order"] for r in rows] == [1, 2]
    a, b = rows
    assert a["file"] == "Wednesday-14-02-2018.csv" and a["label"] == "SSH-BruteForce"
    assert a["attempted_category"] == -1 and a["payload_filter"] is False
    assert json.loads(a["dst_ports"]) == [22] and a["src_ports"] == "n/a"
    assert a["start_utc"] == "2018-02-14T18:01:50.000000000"
    assert a["duration_s"] == 5440.0
    assert b["attempted_category"] == 0 and b["payload_filter"] is True
    assert 'wed_df["Src Port"] != 68' in b["additional_filters"]


def test_ns_to_utc_keeps_nanoseconds():
    assert lw.ns_to_utc(1499170672838272000) == "2017-07-04T12:17:52.838272000"
    assert lw.ns_to_utc("x") == ""
