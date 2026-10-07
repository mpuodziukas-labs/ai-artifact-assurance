"""
Red-team tests for assure.py. Each test names a weakness found by attacking the
tool. A test marked xfail(strict) documents a gap that is NOT fixed: the day it
starts passing, strict mode fails the run so the README Limitations get updated.
"""
import os
import re
import stat
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import assure  # noqa: E402

SCRIPT = os.path.join(ROOT, "assure.py")
ABS_PREFIX = "/" + "Users" + "/"  # built at runtime, never written literally


def secret_status(text):
    return assure.check_secrets_pii(text).status


def grounding(art, src):
    return assure.check_source_grounding(art, src)


def consistency(text):
    return assure.check_internal_consistency(text).status


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, SCRIPT, *args], capture_output=True, text=True, cwd=cwd
    )


# --------------------------------------------------------------------------- #
# Secret scan: evasion by shape
# --------------------------------------------------------------------------- #

TAIL = "Ab1_-" * 8
SECRET_SHAPES = {
    "anthropic-style sk-ant": "key sk-ant-api03-" + TAIL,
    "openai-style sk-proj": "key sk-proj-" + TAIL,
    "stripe test key": "key sk_test_" + "Ab1" * 8,
    "aws temporary key ASIA": "id ASIA" + "A1B2C3D4E5F6G7H8",
    "slack bot token": "tok xo" + "xb-1234567890-1234567890-" + "abcDEF" * 4,
    "google api key": "key AIza" + "Sy" + "A1b2C3d4E5" * 3 + "abc",
    "jwt": "tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
    "dsa private key": "-----BEGIN " + "DSA PRIVATE KEY-----",
    "encrypted private key": "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
    "pgp private key": "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
    "token followed by underscore": "ghp_" + "A1b2C3d4E5" * 3 + "_",
    "token preceded by underscore": "_ghp_" + "A1b2C3d4E5" * 3,
    "key with hyphens in body": "sk-" + "abcd-efgh-" * 3,
}


@pytest.mark.parametrize("name", sorted(SECRET_SHAPES))
def test_secret_shape_is_flagged(name):
    assert secret_status(SECRET_SHAPES[name]) == "FLAG", name


# Secret scan: evasion by invisible or look-alike characters
def test_zero_width_space_inside_token_is_flagged():
    tok = "ghp_" + "A1b2C3d4E5" + "\u200b" + "A1b2C3d4E5"
    assert secret_status(tok) == "FLAG"


def test_soft_hyphen_inside_token_is_flagged():
    tok = "AKIA" + "ABCDEFGH" + "\u00ad" + "IJKLMNOP"
    assert secret_status(tok) == "FLAG"


def test_fullwidth_token_is_flagged():
    tok = "\uff47\uff48\uff50_" + "A1b2C3d4E5" * 3  # fullwidth g h p
    assert secret_status(tok) == "FLAG"


def test_zero_width_inside_email_is_flagged():
    assert secret_status("mail alice@exam\u200bple.com") == "FLAG"


def test_redaction_never_echoes_full_secret_through_invisible_chars():
    tok = "ghp_" + "A1b2C3d4E5" + "\u200b" + "A1b2C3d4E5"
    f = assure.check_secrets_pii(tok)
    joined = " ".join(f.items)
    assert "A1b2C3d4E5A1b2C3d4E5" not in joined
    assert "A1b2C3d4E5" + "\u200b" + "A1b2C3d4E5" not in joined


# Secret scan: false positives
def test_13_digit_order_id_is_not_a_card():
    assert secret_status("order id 1234567890123 shipped") == "PASS"


def test_unix_timestamp_milliseconds_is_not_a_card():
    assert secret_status("created at 1700000000000 ms") == "PASS"


def test_luhn_valid_card_is_still_flagged():
    assert secret_status("card 4111 1111 1111 1111") == "FLAG"
    assert secret_status("card 4111-1111-1111-1111") == "FLAG"


def test_luhn_invalid_16_digit_number_is_not_flagged():
    assert secret_status("card 4111 1111 1111 1112") == "PASS"


# Secret scan: documented gaps (not fixed)
@pytest.mark.xfail(strict=True, reason="base64-wrapped secrets are not decoded")
def test_base64_wrapped_token_is_flagged():
    import base64

    enc = base64.b64encode(("ghp_" + "A1b2C3d4E5" * 3).encode()).decode()
    assert secret_status("blob " + enc) == "FLAG"


@pytest.mark.xfail(strict=True, reason="spelled-out emails ([at]) are not matched")
def test_obfuscated_email_is_flagged():
    assert secret_status("write to alice [at] example [dot] com") == "FLAG"


# --------------------------------------------------------------------------- #
# Source grounding
# --------------------------------------------------------------------------- #

def test_changed_number_inside_quote_is_flagged():
    art = 'The report says "revenue was 15,000 dollars last year across the group".'
    src = "Revenue was 5,000 dollars last year across the group."
    assert grounding(art, src).status == "FLAG"


def test_changed_number_in_long_sentence_is_flagged():
    art = "The team processed roughly 9,000 invoices per day across all three regions."
    src = "The team processed roughly 5,000 invoices per day across all three regions."
    assert grounding(art, src).status == "FLAG"


def test_number_that_is_a_substring_of_a_larger_source_number_is_flagged():
    assert grounding("We processed 500 invoices.", "We processed 5,000 invoices.").status == "FLAG"


def test_matching_number_with_and_without_comma_is_supported():
    art = "We processed roughly 5000 invoices per day across all three regions."
    src = "We processed roughly 5,000 invoices per day across all three regions."
    assert grounding(art, src).status == "PASS"


def test_negation_flip_in_quote_is_flagged():
    art = 'The audit found "the controls did not operate effectively during the period".'
    src = "The audit found the controls operate effectively during the period."
    assert grounding(art, src).status == "FLAG"


def test_report_echo_of_unsupported_span_is_truncated():
    art = 'x "' + "A" * 400000 + '" y'
    f = grounding(art, "unrelated source text")
    assert f.status == "FLAG"
    assert all(len(i) <= 300 for i in f.items)
    assert sum(len(i) for i in f.items) < 5000


def test_grounding_supported_claim_still_passes():
    art = 'The note says "the migration completed in 12 weeks".'
    src = "The migration completed in 12 weeks across all regions."
    assert grounding(art, src).status == "PASS"


@pytest.mark.xfail(strict=True, reason="lexical check cannot see a swapped subject")
def test_swapped_subject_with_same_words_is_flagged():
    art = "The vendor paid the customer."
    src = "The customer paid the vendor."
    assert grounding(art, src).status == "FLAG"


# --------------------------------------------------------------------------- #
# Internal consistency
# --------------------------------------------------------------------------- #

def test_step_numbers_are_not_conflicting_metrics():
    assert consistency("Step 1 install it. Step 2 run it. Step 3 test it.") == "PASS"


def test_section_and_figure_numbers_are_not_conflicting_metrics():
    assert consistency("See Figure 1 and Figure 2. Section 3 and Section 4 follow.") == "PASS"


def test_real_conflict_is_still_flagged():
    assert consistency("Uptime was 99.9%. Later, uptime was 95.0%.") == "FLAG"


def test_conflict_with_units_still_flagged():
    assert consistency("The latency was 12 ms. The latency was 40 ms.") == "FLAG"


# --------------------------------------------------------------------------- #
# CLI: exit codes and robustness
# --------------------------------------------------------------------------- #

def test_missing_source_is_a_usage_error(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("hello 5\n")
    r = run_cli(str(art), "--source", str(tmp_path / "nope.md"))
    assert r.returncode == 2


def test_missing_source_does_not_produce_a_pass_report(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("hello 5\n")
    r = run_cli(str(art), "--source", str(tmp_path / "nope.md"))
    assert "AI-Output Assurance Report" not in r.stdout


def test_unreadable_artifact_is_exit_2_not_a_traceback(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("x")
    art.chmod(0)
    try:
        r = run_cli(str(art))
    finally:
        art.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if os.geteuid() == 0:
        pytest.skip("root can read mode 000 files")
    assert r.returncode == 2
    assert "Traceback" not in r.stderr


def test_directory_as_artifact_is_exit_2(tmp_path):
    assert run_cli(str(tmp_path)).returncode == 2


def test_out_equal_to_artifact_is_refused_and_artifact_intact(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("original content 5\n")
    r = run_cli(str(art), "--out", str(art))
    assert r.returncode == 2
    assert art.read_text() == "original content 5\n"


def test_out_equal_to_source_is_refused_and_source_intact(tmp_path):
    art = tmp_path / "a.md"
    src = tmp_path / "s.md"
    art.write_text("claim 5\n")
    src.write_text("source of record\n")
    r = run_cli(str(art), "--source", str(src), "--out", str(src))
    assert r.returncode == 2
    assert src.read_text() == "source of record\n"


def test_out_through_symlink_to_artifact_is_refused(tmp_path):
    art = tmp_path / "a.md"
    art.write_text("original 5\n")
    link = tmp_path / "link.md"
    link.symlink_to(art)
    r = run_cli(str(art), "--out", str(link))
    assert r.returncode == 2
    assert art.read_text() == "original 5\n"


def test_empty_artifact_is_handled(tmp_path):
    art = tmp_path / "e.md"
    art.write_text("")
    r = run_cli(str(art))
    assert r.returncode == 1  # an empty artifact is a FLAG, not a clean pass
    assert "empty" in r.stdout.lower()
    assert "Traceback" not in r.stderr


def test_binary_artifact_does_not_crash(tmp_path):
    art = tmp_path / "b.bin"
    art.write_bytes(b"\xff\xfe\x00bad\x00" * 50)
    r = run_cli(str(art))
    assert r.returncode in (0, 1)
    assert "Traceback" not in r.stderr


def test_exit_1_when_flagged_and_0_when_clean(tmp_path):
    bad = tmp_path / "bad.md"
    bad.write_text("token ghp_" + "A1b2C3d4E5" * 3 + "\n")
    good = tmp_path / "good.md"
    good.write_text("Nothing sensitive here.\n")
    assert run_cli(str(bad)).returncode == 1
    assert run_cli(str(good)).returncode == 0


# --------------------------------------------------------------------------- #
# Paths in output
# --------------------------------------------------------------------------- #

def test_report_has_no_absolute_path_for_inputs_outside_cwd(tmp_path):
    art = tmp_path / "a.md"
    src = tmp_path / "s.md"
    art.write_text("claim 5\n")
    src.write_text("claim 5\n")
    r = run_cli(str(art), "--source", str(src), "--json")
    assert str(tmp_path) not in r.stdout


def test_path_with_dotdot_is_not_echoed_as_traversal(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    art = tmp_path / "a.md"
    art.write_text("claim 5\n")
    r = run_cli("../a.md", cwd=str(sub))
    assert "../" not in r.stdout.split("## Findings")[0]


def test_stamp_failure_detail_does_not_echo_absolute_paths(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    ots = fake / "ots"
    ots.write_text(
        "#!/bin/sh\necho \"cannot open " + ABS_PREFIX + "someone/secret/dir/file.md\" >&2\nexit 3\n"
    )
    ots.chmod(0o755)
    art = tmp_path / "a.md"
    art.write_text("hello\n")
    env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"])
    r = subprocess.run(
        [sys.executable, SCRIPT, str(art), "--stamp"], capture_output=True, text=True, env=env
    )
    assert "someone/secret/dir" not in r.stdout
    assert ABS_PREFIX not in r.stdout


# --------------------------------------------------------------------------- #
# Honesty: README counts must match the code
# --------------------------------------------------------------------------- #

NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16,
}


def _readme():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


def test_readme_secret_shape_count_matches_code():
    m = re.search(r"\((\w+) secret\s+shapes", _readme())
    assert m, "README must state the secret shape count"
    assert NUMBER_WORDS[m.group(1).lower()] == len(assure._SECRET_PATTERNS)


def test_readme_pii_shape_count_matches_code():
    m = re.search(r"(\w+) PII\s+shapes", _readme())
    assert m, "README must state the PII shape count"
    assert NUMBER_WORDS[m.group(1).lower()] == len(assure._PII_PATTERNS)


def test_readme_test_count_claim_is_absent_or_true():
    for m in re.finditer(r"(\d+) tests", _readme()):
        pytest.fail("README quotes a test count that will drift: " + m.group(0))


def test_sample_report_matches_regenerated_output(tmp_path):
    out = tmp_path / "r.md"
    r = subprocess.run(
        [sys.executable, SCRIPT, "samples/artifact.md", "--source", "samples/source.md",
         "--out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert r.returncode == 1
    mask = lambda s: re.sub(r"\d{4}-\d\d-\d\dT[\d:]+Z", "TS", s)
    with open(os.path.join(ROOT, "samples", "sample-report.md"), encoding="utf-8") as fh:
        assert mask(out.read_text()) == mask(fh.read())


# --------------------------------------------------------------------------- #
# Added guards: new rules must not over-fire, long sentences keep negation
# --------------------------------------------------------------------------- #

def test_negation_flip_in_long_sentence_is_flagged():
    art = "The controls did not operate effectively during the entire audit period for all 3 regions."
    src = "The controls operate effectively during the entire audit period for all 3 regions."
    assert grounding(art, src).status == "FLAG"


@pytest.mark.parametrize("text", [
    "Our risk-assessment-framework-document is attached.",
    "Use the task-management-integration-guide for details.",
    "The eyJ prefix marks base64 JSON headers.",
    "Slack workspace xoxo is a joke, not a token.",
    "AIza is a prefix; AKIA is another prefix.",
])
def test_benign_text_with_secret_like_words_passes(text):
    assert secret_status(text) == "PASS"


def test_secret_in_unsupported_span_is_still_redacted_in_report():
    tok = "ghp_" + "A1b2C3d4E5" * 3
    f = grounding('The note says "deploy with ' + tok + ' today".', "nothing relevant")
    assert f.status == "FLAG"
    assert tok not in " ".join(f.items)
