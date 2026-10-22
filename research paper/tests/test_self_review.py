"""Tests for the independent re-computation helpers in src/audit/self_review.py (synthetic data only)."""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.audit import self_review as sr


def test_is_attack_excludes_benign_and_attempted():
    lab = pd.Series(["BENIGN", "Benign ", "DoS Hulk", "DoS Hulk - Attempted", "Portscan"])
    assert sr.is_attack(lab).tolist() == [False, False, True, False, True]


def test_next_window_grid_counts_positives_and_persistence():
    # bins (2 s): 0 attack, 1 attack, 2 benign, 3 empty, 4 attack  -> grid 0..4
    ts = np.array([0, 2_000_000, 4_500_000, 8_100_000]) + 10 * sr.WINDOW_US
    att = np.array([True, True, False, True])
    out = sr.next_window(ts, att)
    # future windows 1..4 = [A, B, empty, A] -> 2 positives; persistent = (1 after 0) -> 1
    assert out == {"windows": 4, "positive": 2, "persistent": 1}


def test_window_check_inclusive_microsecond_bounds():
    rules = pd.DataFrame({"label": ["X", "X - Attempted"], "attempted_category": [-1, 1],
                          "start_ns": [1_000_000_000, 5_000_000_000], "end_ns": [2_000_000_500, 6_000_000_000]})
    df = pd.DataFrame({"Label": ["X", "X", "X", "X - Attempted", "BENIGN"],
                       "Attempted Category": ["-1", "-1", "-1", "1", "-1"],
                       "ts_us": [1_000_000, 2_000_001, 2_000_002, 7_000_000, 0]})
    # end_ns 2_000_000_500 rounds UP to 2_000_001 us (inclusive); 2_000_002 is outside; the attempted flow is outside
    assert sr.window_check(df, rules) == (4, 2)
