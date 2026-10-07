"""Adversarial regression tests: one test per attack."""
import json
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import assure  # noqa: E402

TOK = "ghp_" + "A1b2C3d4E5" * 3
SRC = "Quarterly operating margin for the northern region was 12% in Q3 2024.\n"


def cli(tmp_path, art_text, src_text=None, *extra, art_bytes=None):
    art = tmp_path / "a.md"
    if art_bytes is not None:
        art.write_bytes(art_bytes)
    else:
        art.write_text(art_text, encoding="utf-8")
    args = [sys.executable, os.path.join(ROOT, "assure.py"), str(art)]
    if src_text is not None:
        src = tmp_path / "s.md"
        src.write_text(src_text, encoding="utf-8")
        args += ["--source", str(src)]
    args += list(extra)
    return subprocess.run(args, capture_output=True, text=True, timeout=60, cwd=tmp_path)


def status(r, check):
    for line in r.stdout.splitlines():
        if line.startswith(f"| {check} |"):
            return "FLAG" if "**FLAG**" in line else "PASS"
    raise AssertionError(r.stdout + r.stderr)


def grounding(tmp_path, art, src=SRC):
    r = cli(tmp_path, art, src)
    return r, status(r, "Source-grounding")


def test_k1_markdown_escaped_secret(tmp_path):
    r = cli(tmp_path, "deploy token ghp\\_" + "A1b2C3d4E5" * 3 + "\n", "ok\n")
    assert status(r, "Secret / PII scan") == "FLAG"
    assert TOK not in r.stdout and TOK.replace("_", "\\_") not in r.stdout


@pytest.mark.parametrize("ch", ["\u034f", "\ufe0f", "\u3164", "\u115f", "\u1160", "\uffa0"])
def test_k2_invisible_joiner_in_secret(tmp_path, ch):
    r = cli(tmp_path, "deploy token ghp_A1b2C3d4E5" + ch + "A1b2C3d4E5" * 2 + "\n", "ok\n")
    assert status(r, "Secret / PII scan") == "FLAG"
    assert TOK not in r.stdout
    assert "A1b2C3d4E5" * 3 not in r.stdout


def test_k3_supported_quote_does_not_clear_sentence(tmp_path):
    art = ('The board memo states "operating margin for the northern region was 12%" '
           "and revenue fell 90% with 7000 customers lost.\n")
    r, s = grounding(tmp_path, art)
    assert s == "FLAG"


def test_h1_sign_flip(tmp_path):
    r, s = grounding(tmp_path, "Quarterly operating margin for the northern region was -12% in Q3 2024.\n")
    assert s == "FLAG"
    r, s = grounding(tmp_path, "Quarterly operating margin for the northern region was \u221212% in Q3 2024.\n")
    assert s == "FLAG"


def test_h2_scale_flip(tmp_path):
    src = "Total contract value for the northern region was $5M in fiscal year 2024 overall.\n"
    art = "Total contract value for the northern region was $5B in fiscal year 2024 overall.\n"
    assert grounding(tmp_path, art, src)[1] == "FLAG"
    assert grounding(tmp_path, src + "Noted.\n", src)[1] == "PASS"
    assert grounding(tmp_path, art.replace("$5B", "$5 million"), src)[1] == "PASS"


def test_h3_direction_flip(tmp_path):
    src = "Quarterly operating margin for the northern region rose to 12% in Q3 2024.\n"
    art = "Quarterly operating margin for the northern region fell to 12% in Q3 2024.\n"
    assert grounding(tmp_path, art, src)[1] == "FLAG"
    assert grounding(tmp_path, src + "Noted.\n", src)[1] == "PASS"


def test_h4_superscript_digits(tmp_path):
    r, s = grounding(tmp_path, "The northern region margin was \u00b9\u00b2% overall.\n", "ok\n")
    assert s == "FLAG"


@pytest.mark.parametrize("q", ["\u00ab{}\u00bb", "'{}'", "\u2018{}\u2019", "\u201e{}\u201c"])
def test_h5_other_quote_styles(tmp_path, q):
    art = "The CEO said " + q.format("we have never had a single outage in our history") + ".\n"
    assert grounding(tmp_path, art, "Uptime report.\n")[1] == "FLAG"


def test_h5_apostrophes_are_not_quotes(tmp_path):
    art = "The vendor's invoice and the client's order matched.\n"
    assert grounding(tmp_path, art, "Uptime report.\n")[1] == "PASS"


def test_m1_source_equals_artifact(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("Revenue was 999% and we never failed.\n")
    py = [sys.executable, os.path.join(ROOT, "assure.py")]
    r = subprocess.run(py + [str(art), "--source", str(art)], capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2
    twin = tmp_path / "b.md"
    twin.write_bytes(art.read_bytes())
    r = subprocess.run(py + [str(art), "--source", str(twin)], capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2


@pytest.mark.parametrize("data", [b"", b"\x00\x00\x00"])
def test_m2_empty_artifact_fails(tmp_path, data):
    r = cli(tmp_path, "", "ok\n", art_bytes=data)
    assert r.returncode == 1
    assert "empty" in r.stdout.lower()
    assert "Traceback" not in r.stderr


def test_m3_separated_ssn_and_card(tmp_path):
    for text in ("SSN 123 45 6789\n", "SSN 123.45.6789\n", "card 4111.1111.1111.1111\n",
                 "card 4111 1111 1111 1111\n"):
        r = cli(tmp_path, text)
        assert status(r, "Secret / PII scan") == "FLAG", text
        assert "4111 1111 1111 1111" not in r.stdout


def test_m3_non_luhn_card_shape_passes(tmp_path):
    r = cli(tmp_path, "ref 4111.1111.1111.1112\n")
    assert status(r, "Secret / PII scan") == "PASS"


def test_m4_json_stdout_is_only_json(tmp_path):
    r = cli(tmp_path, "Nothing here.\n", None, "--json")
    data = json.loads(r.stdout)
    assert data["flag_count"] == 0
    assert "# AI-Output Assurance Report" in r.stderr


def test_m5_ci_runs_everywhere_and_asserts_exit():
    ci = open(os.path.join(ROOT, ".github", "workflows", "ci.yml"), encoding="utf-8").read()
    assert "|| true" not in ci
    assert "branches: [main]" not in ci
    assert "-eq 1" in ci


def test_m6_time_series_is_not_a_conflict(tmp_path):
    r = cli(tmp_path, "Revenue was 10 in 2023. Revenue was 12 in 2024.\n")
    assert status(r, "Internal consistency") == "PASS"
    r = cli(tmp_path, "Revenue was 10 in 2024. Revenue was 12 in 2024.\n")
    assert status(r, "Internal consistency") == "FLAG"


def test_m7_binary_artifact_exact_rc(tmp_path):
    r = cli(tmp_path, "", None, art_bytes=b"\xff\xfe\x00bad\x00" * 50)
    assert r.returncode == 0
    assert "Traceback" not in r.stderr


def test_m7_timing_matches_readme_claim():
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert "2 to 3 seconds per 400 KB" in readme
    s = time.time()
    assure.extract_metrics("word " * 80000)
    assert time.time() - s < 6  # claim upper bound 3 s, margin 2x for slow CI
