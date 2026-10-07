"""
Tests for assure.py.

Strategy: every check is exercised with a planted POSITIVE (the check must
FLAG) and a clean NEGATIVE (the check must PASS). Plus determinism of the
provenance hash and an end-to-end CLI run.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import assure  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# --------------------------------------------------------------------------- #
# 1. Provenance - hash determinism
# --------------------------------------------------------------------------- #


def test_sha256_bytes_known_vector():
    # SHA-256("") is well-known and fixed.
    assert (
        assure.sha256_bytes(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_file_is_deterministic(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("hello assurance\n")
    h1 = assure.sha256_file(str(p))
    h2 = assure.sha256_file(str(p))
    assert h1 == h2
    assert h1 == assure.sha256_bytes(b"hello assurance\n")


def test_timestamp_is_iso_utc_z():
    ts = assure.utc_now_iso()
    assert ts.endswith("Z")
    assert "T" in ts
    # parseable back
    import datetime as dt

    dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- #
# 2. Source-grounding
# --------------------------------------------------------------------------- #


def test_grounding_flags_unsupported_claim():
    artifact = 'The system achieved "a 99.99% uptime guarantee" last year.'
    sources = "The system was generally reliable. No specific uptime figure was published."
    f = assure.check_source_grounding(artifact, sources)
    assert f.status == "FLAG"
    assert f.items  # at least one unsupported span listed


def test_grounding_passes_supported_claim():
    artifact = 'The report notes "the migration completed in 12 weeks" overall.'
    sources = "Project notes: the migration completed in 12 weeks across all regions."
    f = assure.check_source_grounding(artifact, sources)
    assert f.status == "PASS"


# --------------------------------------------------------------------------- #
# 3. Secret / PII scan
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "planted",
    [
        "token=ghp_" + "a" * 36,
        "key: sk-" + "B" * 32,
        "stripe sk_live_" + "c" * 24,
        "aws AKIA" + "Z" * 16,
        "contact me at jane.doe@example.com",
        "ssn 123-45-6789",
    ],
)
def test_secrets_pii_flags_planted_positive(planted):
    f = assure.check_secrets_pii(f"Some text {planted} and more text.")
    assert f.status == "FLAG", planted
    assert f.items


def test_secrets_pii_does_not_echo_full_secret():
    secret = "ghp_" + "a" * 36
    f = assure.check_secrets_pii(secret)
    assert f.status == "FLAG"
    # full secret must never appear verbatim in the redacted output
    assert secret not in " ".join(f.items)


def test_secrets_pii_clean_negative():
    clean = "This is an ordinary paragraph with no secrets and no personal data."
    f = assure.check_secrets_pii(clean)
    assert f.status == "PASS"


# --------------------------------------------------------------------------- #
# 4. Internal consistency
# --------------------------------------------------------------------------- #


def test_consistency_flags_contradictory_numbers():
    artifact = (
        "Our uptime was 99.9%. Later in the doc, uptime was 95.0%. "
        "The team is proud of the result."
    )
    f = assure.check_internal_consistency(artifact)
    assert f.status == "FLAG"
    assert f.items


def test_consistency_clean_negative():
    artifact = "Uptime was 99.9%. Latency was 12 ms. Throughput was 5000 requests."
    f = assure.check_internal_consistency(artifact)
    assert f.status == "PASS"


# --------------------------------------------------------------------------- #
# Report assembly + disclaimer
# --------------------------------------------------------------------------- #


def test_report_contains_mandatory_disclaimer(tmp_path):
    art = tmp_path / "art.md"
    art.write_text("A clean artifact with nothing to flag.\n")
    result = assure.run_checks(str(art), [], do_stamp=False)
    md = assure.render_markdown(result)
    assert "NOT a certification, attestation of compliance, legal opinion" in md
    assert "## Disclaimer" in md
    assert result["artifact_sha256"] in md


def test_report_has_findings_table(tmp_path):
    art = tmp_path / "art.md"
    art.write_text("Clean artifact.\n")
    result = assure.run_checks(str(art), [], do_stamp=False)
    md = assure.render_markdown(result)
    assert "| Check | Result | Detail |" in md
    for check in ["Provenance", "Source-grounding", "Secret / PII scan", "Internal consistency"]:
        assert check in md


# --------------------------------------------------------------------------- #
# End-to-end CLI
# --------------------------------------------------------------------------- #


def test_cli_clean_artifact_exit_zero(tmp_path):
    art = tmp_path / "clean.md"
    art.write_text("Nothing suspicious here. Uptime was 99.9%.\n")
    out = tmp_path / "report.md"
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "assure.py"), str(art), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    assert "AI-Output Assurance Report" in out.read_text()


def test_cli_flagged_artifact_exit_one(tmp_path):
    art = tmp_path / "dirty.md"
    art.write_text("token ghp_" + "a" * 36 + "\nuptime 99.9%. uptime 80.0%.\n")
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "assure.py"), str(art), "--json"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stderr
    # JSON tail must be present and report flags
    payload = proc.stdout[proc.stdout.index("{") :]
    data = json.loads(payload)
    assert data["flag_count"] >= 1


def test_cli_missing_artifact_exit_two(tmp_path):
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "assure.py"), str(tmp_path / "nope.md")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


def test_grounding_span_never_leaks_full_secret(tmp_path):
    """GOLDEN RATCHET (2026-06-14): a secret inside an UNSUPPORTED grounding span
    must be redacted in the report - the grounding section must not echo a full secret."""
    import assure as A
    leak = "ghp_" + "Z" * 34 + "12"
    art = tmp_path / "a.md"
    art.write_text(f'The runbook says "deploy token {leak} to proceed here" now.\n')
    src = tmp_path / "s.md"
    src.write_text("Unrelated source content with no token.\n")
    f = A.check_source_grounding(art.read_text(), src.read_text())
    blob = f.detail + " " + " ".join(getattr(f, "items", []) or [])
    assert leak not in blob, "full secret leaked in grounding output"
    assert "ghp_" in blob and "..." in blob, "redacted form expected"


# --------------------------------------------------------------------------- #
# Reports never carry absolute paths; committed samples carry no secret literal
# --------------------------------------------------------------------------- #


def test_report_contains_no_absolute_path(tmp_path):
    art = tmp_path / "art.md"
    art.write_text("Clean artifact.\n")
    src = tmp_path / "src.md"
    src.write_text("Clean source.\n")
    result = assure.run_checks(str(art), [str(src)], do_stamp=False)
    md = assure.render_markdown(result)
    assert str(tmp_path) not in md
    assert str(tmp_path) not in json.dumps(result)
    assert "../" not in md
    assert "`art.md`" in md and "`src.md`" in md


def test_committed_sample_report_has_no_absolute_path():
    with open(os.path.join(ROOT, "samples", "sample-report.md")) as fh:
        text = fh.read()
    assert ROOT not in text
    import re

    assert not re.search(r"`(/|[A-Za-z]:[\\/])", text), "absolute path in committed report"


def test_committed_sample_report_matches_generator():
    proc = subprocess.run(
        [sys.executable, "assure.py", "samples/artifact.md", "--source", "samples/source.md"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 1, proc.stderr

    import re

    def body(t):  # mask the volatile timestamps
        return re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", "TS", t).splitlines()

    with open(os.path.join(ROOT, "samples", "sample-report.md")) as fh:
        assert body(fh.read()) == body(proc.stdout)


def test_committed_samples_hold_no_standard_secret_literal():
    import re

    standard = re.compile(r"ghp_[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|xox[bp]-")
    for name in ("artifact.md", "source.md", "sample-report.md"):
        with open(os.path.join(ROOT, "samples", name)) as fh:
            assert not standard.search(fh.read()), name


def test_sample_artifact_planted_token_is_still_detected():
    with open(os.path.join(ROOT, "samples", "artifact.md")) as fh:
        finding = assure.check_secrets_pii(fh.read())
    assert finding.status == "FLAG"
    assert any("Stripe secret key" in i for i in finding.items)
