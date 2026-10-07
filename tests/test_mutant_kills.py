"""Tests added so that every mutant in mutants.py is killed."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import assure  # noqa: E402


def test_dropped_negation_never_is_flagged():
    art = "The depot never missed a shipment in 12 weeks of Q2 operations."
    src = "The depot missed a shipment in 12 weeks of Q2 operations."
    assert assure.check_source_grounding(art, src).status == "FLAG"


def test_low_token_overlap_with_matching_number_is_flagged():
    art = "The warehouse handled 1250 crates during Q2 operations."
    src = "The depot processed 1250 pallets in Q2 2025."
    assert assure.check_source_grounding(art, src).status == "FLAG"


def test_verbatim_sentence_is_supported():
    s = "The depot processed 1250 pallets in Q2 2025."
    assert assure.check_source_grounding(s, s).status == "PASS"
