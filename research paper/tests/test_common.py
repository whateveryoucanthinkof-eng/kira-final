"""Tests for src/audit/common.py name handling (no data files needed)."""
from __future__ import annotations

from src.audit import common

IMPROVED = ["id", "Flow ID", "Src IP", "Src Port", "Dst Port", "Timestamp", "Total Fwd Packet",
            "Total Bwd packets", "Total Length of Fwd Packet", "Packet Length Min", "Fwd Segment Size Avg",
            "FWD Init Win Bytes", "Fwd Bytes/Bulk Avg", "CWR Flag Count", "Packet Length Variance",
            "Average Packet Size", "Fwd Header Length", "Label"]


def test_canonical_names_original_2017_style():
    orig = ["Flow ID", " Source IP", " Source Port", " Destination Port", " Timestamp", " Total Fwd Packets",
            " Total Backward Packets", "Total Length of Fwd Packets", " Min Packet Length", " Avg Fwd Segment Size",
            "Init_Win_bytes_forward", "Fwd Avg Bytes/Bulk", " CWE Flag Count", " Fwd Header Length",
            " Fwd Header Length", " Label"]
    assert common.canonical_names(orig, IMPROVED) == [
        "Flow ID", "Src IP", "Src Port", "Dst Port", "Timestamp", "Total Fwd Packet", "Total Bwd packets",
        "Total Length of Fwd Packet", "Packet Length Min", "Fwd Segment Size Avg", "FWD Init Win Bytes",
        "Fwd Bytes/Bulk Avg", "CWR Flag Count", "Fwd Header Length", "Fwd Header Length__dup1", "Label"]


def test_canonical_names_original_2018_abbreviations():
    orig = ["Dst Port", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "Pkt Len Min", "Fwd Seg Size Avg",
            "Init Fwd Win Byts", "Fwd Byts/b Avg", "Pkt Len Var", "Pkt Size Avg", "Fwd Header Len", "Label"]
    assert common.canonical_names(orig, IMPROVED) == [
        "Dst Port", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "Packet Length Min",
        "Fwd Segment Size Avg", "FWD Init Win Bytes", "Fwd Bytes/Bulk Avg", "Packet Length Variance",
        "Average Packet Size", "Fwd Header Length", "Label"]


def test_unknown_name_is_kept_stripped():
    assert common.canonical_names([" Something New "], IMPROVED) == ["Something New"]


def test_column_role():
    cfg = common.load_config()
    assert common.column_role(" Label", cfg) == "target"
    assert common.column_role("Attempted Category", cfg) == "target"
    assert common.column_role(" Source IP", cfg) == "identifier"
    assert common.column_role("Dst Port", cfg) == "context_review"
    assert common.column_role("Flow Duration", cfg) == "feature"
