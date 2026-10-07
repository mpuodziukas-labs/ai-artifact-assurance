#!/usr/bin/env python3
"""
assure.py - AI-Output Assurance

Takes an AI-generated artifact (text / markdown / code) plus optional source
files and produces a timestamped EVIDENCE REPORT in Markdown.

This tool produces EVIDENCE, not attestation. It runs four deterministic
checks and emits a findings report a human auditor can rely on. It does NOT
certify, attest, or render any opinion. See the disclaimer in every report.

Usage:
    python3 assure.py ARTIFACT [--source SRC ...] [--out REPORT.md]
                       [--stamp] [--json]

Exit codes:
    0  report generated, no FLAGs
    1  report generated, one or more FLAGs raised
    2  usage / IO error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single line in the findings table."""
    check: str
    status: str  # "PASS" or "FLAG"
    detail: str
    items: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Provenance
# ---------------------------------------------------------------------------


def sha256_file(path: str) -> str:
    """Deterministic SHA-256 of a file's bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def display_path(path: str) -> str:
    """Path as shown in reports: relative to the working directory; a file outside
    the working directory is shown by base name only. Never absolute."""
    rel = os.path.relpath(path).replace(os.sep, "/")
    return os.path.basename(path) if rel.startswith("..") else rel


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp, second precision, explicit Z."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


_ABS_PATH_RE = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][^\s\\/:'\"]+)+[\\/]([^\s\\/:'\"]+)")


def _strip_paths(text: str) -> str:
    """Reduce every multi-segment path in tool output to its base name, so a
    wrapped command's error text cannot put a directory layout in the report."""
    return _ABS_PATH_RE.sub(lambda m: m.group(1), text)


def opentimestamps_stamp(path: str) -> tuple[bool, str]:
    """
    Attempt an OpenTimestamps stamp of the artifact. Returns (ok, detail).
    Never raises; if `ots` is missing or fails, returns (False, reason).
    """
    if shutil.which("ots") is None:
        return False, "ots binary not available; provenance stamp skipped"
    try:
        proc = subprocess.run(
            ["ots", "stamp", path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:  # pragma: no cover
        return False, f"ots stamp failed: {_strip_paths(str(exc))}"
    ots_path = path + ".ots"
    if proc.returncode == 0 and os.path.exists(ots_path):
        return True, f"OpenTimestamps proof written to {os.path.basename(ots_path)}"
    err = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = _strip_paths(err[-1]) if err else f"ots exit {proc.returncode}"
    return False, f"ots stamp not completed: {reason}"


# ---------------------------------------------------------------------------
# 2. Source-grounding
# ---------------------------------------------------------------------------

# A "claim span" we attempt to verify against sources:
#  - quoted spans:  "..."  or  '...'  (>= 8 chars inside the quotes)
#  - sentences that assert a number (e.g. "revenue grew 42%")
_QUOTE_RE = re.compile(
    r'"([^"\n]{8,})"'
    r"|\u201c([^\u201d\n]{8,})\u201d"
    r"|\u201e([^\u201c\u201d\n]{8,})[\u201c\u201d]"
    r"|\u00ab([^\u00bb\n]{8,})\u00bb"
    r"|\u300c([^\u300d\n]{8,})\u300d"
    # single quotes must not be apostrophes: not inside a word on either side
    r"|(?<![A-Za-z0-9])'([^'\n]{8,}?)'(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])\u2018([^\u2019\n]{8,}?)\u2019(?![A-Za-z0-9])"
)
# A sentence terminator is . ! or ? that is NOT between two digits (so "95.0"
# and "5,000.50" stay intact) and is followed by whitespace/end.
_SENT_SPLIT_RE = re.compile(r"(?<!\d)[.!?]+(?:\s+|$)|\n+")
_WORD_RE = re.compile(r"[A-Za-z0-9]+")
_HAS_DIGIT_RE = re.compile(r"\d")


# Default-ignorable code points that are not category Cf: combining grapheme
# joiner, Mongolian free variation selectors, variation selectors, Hangul fillers.
_IGNORABLE = (
    {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0}
    | set(range(0x180B, 0x180E)) | {0x180F}
    | set(range(0xFE00, 0xFE10))
    | set(range(0xE0100, 0xE01F0))
)
_MD_ESCAPE_RE = re.compile(r"\\([!-/:-@\[-`{-~])")


def _canon(text: str) -> str:
    """NFKC-normalize, drop invisible format / control / default-ignorable
    characters, then strip Markdown backslash escapes, so a zero-width space,
    a joiner, a fullwidth letter or `ghp\\_` cannot split a pattern."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(
        ch for ch in text
        if ord(ch) not in _IGNORABLE
        and (ch in "\n\t\r" or unicodedata.category(ch) not in ("Cf", "Cc"))
    )
    return _MD_ESCAPE_RE.sub(r"\1", text)


_CLIP = 200


def _clip(text: str) -> str:
    return text if len(text) <= _CLIP else text[:_CLIP] + "..."


def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace for substring containment checks."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _token_set(text: str) -> set[str]:
    return set(w.lower() for w in _WORD_RE.findall(text))


# A number is (sign, digits, scale): "-12%" and "12%" differ, "$5M" and "$5B" differ,
# "5M" and "5 million" are equal.
_NUM_RE = re.compile(
    r"(?:(?<![\w.])([-\u2212])(?=\d))?"
    r"(\d[\d,]*(?:\.\d+)?)"
    r"(?:(%)|\s?(percent|thousand|million|billion)\b|(bn|k|m|b)\b)?",
    re.IGNORECASE,
)
_SCALES = {"%": "%", "percent": "%", "k": "K", "thousand": "K", "m": "M", "million": "M",
           "b": "B", "bn": "B", "billion": "B"}
_DIRECTION_RE = re.compile(
    r"\b(?:rose|rise|rises|rising|fell|fall|falls|falling|increased|increase|increases|"
    r"decreased|decrease|decreases|grew|grow|grows|dropped|drop|drops|declined|decline|declines)\b",
    re.IGNORECASE,
)
_NEG_RE = re.compile(r"\b(?:not|no|never|none|cannot|neither|nor|without)\b|n['\u2019]t\b", re.IGNORECASE)


def _numbers(text: str) -> set[tuple[str, str, str]]:
    out = set()
    for m in _NUM_RE.finditer(text):
        scale = (m.group(3) or m.group(4) or m.group(5) or "").lower()
        out.add(("-" if m.group(1) else "", m.group(2).replace(",", ""), _SCALES.get(scale, "")))
    return out


def _directions(text: str) -> set[str]:
    return {m.group(0).lower() for m in _DIRECTION_RE.finditer(text)}


def _negators(text: str) -> set[str]:
    return {m.group(0).lower() for m in _NEG_RE.finditer(text)}


def _supported(span: str, norm_sources: str, source_tokens: set[str],
               source_numbers: Optional[set] = None,
               source_negators: Optional[set[str]] = None) -> bool:
    """
    A span is 'supported' if its normalized form appears verbatim in any
    source, OR (for longer spans) >=85% of its content tokens appear in the
    union of source tokens. The verbatim path is exact and deterministic;
    the token path is a deliberately conservative fuzzy fallback.
    """
    nspan = _normalize(span)
    if not nspan:
        return True
    # A number or a negation the sources never use cannot be supported, however
    # many surrounding words match.
    if source_numbers is not None and not _numbers(span) <= source_numbers:
        return False
    if source_negators is not None and not _negators(span) <= source_negators:
        return False
    # A direction word (rose/fell/...) the sources never use cannot be supported:
    # the overlap fallback must not let "fell" ride on a source that says "rose".
    if source_numbers is not None and not _directions(span) <= source_tokens:
        return False
    if nspan in norm_sources:
        return True
    toks = [w.lower() for w in _WORD_RE.findall(span)]
    if not toks:
        return True
    hits = sum(1 for t in toks if t in source_tokens)
    return (hits / len(toks)) >= 0.85


def _qtext(m: "re.Match") -> str:
    return next(g for g in m.groups() if g).strip()


def extract_claim_spans(artifact_text: str) -> list[str]:
    """Pull quoted spans and numeric-bearing sentences as verifiable claims."""
    artifact_text = _canon(artifact_text)
    spans: list[str] = []
    for m in _QUOTE_RE.finditer(artifact_text):
        spans.append(_qtext(m))
    # numeric-bearing sentences (decimals kept intact by _SENT_SPLIT_RE)
    for sentence in _SENT_SPLIT_RE.split(artifact_text):
        s = sentence.strip().strip("-\u2022* \t")
        if s and _HAS_DIGIT_RE.search(s):
            spans.append(s)
    # de-dupe, keep order
    seen: set[str] = set()
    out: list[str] = []
    for s in spans:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def check_source_grounding(artifact_text: str, sources_text: str) -> Finding:
    artifact_text = _canon(artifact_text)
    sources_text = _canon(sources_text)
    spans = extract_claim_spans(artifact_text)
    if not spans:
        return Finding(
            "Source-grounding",
            "PASS",
            "No quoted spans or numeric claims detected to ground.",
        )
    norm_sources = _normalize(sources_text)
    source_tokens = _token_set(sources_text)
    source_numbers = _numbers(sources_text)
    source_negators = _negators(sources_text)
    # Quoted spans are the strongest verifiable claims. Collect the ones that
    # are themselves supported so we don't double-penalize a sentence that
    # merely *wraps* a supported quote in unsupported framing ("The report
    # notes \"...\""). A sentence containing a supported quote is supported.
    supported_quotes = [
        _qtext(m)
        for m in _QUOTE_RE.finditer(artifact_text)
        if _supported(_qtext(m), norm_sources, source_tokens, source_numbers, source_negators)
    ]
    supported_quotes = [_normalize(q) for q in supported_quotes if q]

    def _is_supported(span: str) -> bool:
        if _supported(span, norm_sources, source_tokens, source_numbers, source_negators):
            return True
        # A supported quote clears only itself: whatever the sentence says outside
        # the quote must still carry no number, negator or direction the sources lack.
        nspan = _normalize(span)
        for q in supported_quotes:
            if q and q in nspan:
                rest = nspan.replace(q, " ")
                if (_numbers(rest) <= source_numbers and _negators(rest) <= source_negators
                        and _directions(rest) <= source_tokens):
                    return True
        return False

    unsupported = [s for s in spans if not _is_supported(s)]
    if unsupported:
        sample = [_clip(_scrub_secrets(s)) for s in unsupported[:10]]
        return Finding(
            "Source-grounding",
            "FLAG",
            f"{len(unsupported)} of {len(spans)} claim span(s) not found in / "
            f"supported by supplied sources.",
            items=sample,
        )
    return Finding(
        "Source-grounding",
        "PASS",
        f"All {len(spans)} claim span(s) supported by supplied sources.",
    )


# ---------------------------------------------------------------------------
# 3. Secret / PII scan
# ---------------------------------------------------------------------------

_B = r"(?<![A-Za-z0-9])"   # not inside a longer alphanumeric run (underscore is allowed)
_E = r"(?![A-Za-z0-9])"

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("GitHub token (ghp_)", re.compile(_B + r"ghp_[A-Za-z0-9]{20,}" + _E)),
    ("GitHub fine-grained PAT (github_pat_)", re.compile(_B + r"github_pat_[A-Za-z0-9_]{20,}" + _E)),
    ("OpenAI/Anthropic-style key (sk-)", re.compile(_B + r"sk-[A-Za-z0-9_-]{16,}" + _E)),
    ("Stripe secret key (sk_live / sk_test)", re.compile(_B + r"sk_(?:live|test)_[A-Za-z0-9]{16,}" + _E)),
    ("AWS access key ID (AKIA / ASIA)", re.compile(_B + r"(?:AKIA|ASIA)[0-9A-Z]{16}" + _E)),
    ("Slack token (xox)", re.compile(_B + r"xox[abprs]-[A-Za-z0-9-]{10,}" + _E)),
    ("Google API key (AIza)", re.compile(_B + r"AIza[0-9A-Za-z_-]{35}" + _E)),
    ("JSON Web Token (eyJ)", re.compile(_B + r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
]

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("US SSN", re.compile(r"(?<!\d)\d{3}([-. ])\d{2}\1\d{4}(?!\d)")),
    ("Credit card number (Luhn-valid)", re.compile(r"(?<!\d)(?:\d[ .-]?){12,18}\d(?!\d)")),
    ("US phone number", re.compile(r"\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b")),
]


def _luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VALIDATORS = {"Credit card number (Luhn-valid)": _luhn_ok}


def _pattern_hits(label: str, pat: re.Pattern, text: str):
    ok = _VALIDATORS.get(label)
    for m in pat.finditer(text):
        if ok is None or ok(m.group(0)):
            yield m


def _redact(value: str) -> str:
    """Show only enough to identify the hit; never echo a full secret."""
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:6] + "..." + value[-2:]


def _scrub_secrets(text: str) -> str:
    """Replace any secret/PII match in free text with its redacted form.
    Applied to EVERY artifact span echoed into the report so no section
    (incl. source-grounding samples) can leak a full secret. Defense-in-depth."""
    text = _canon(text)
    for label, pat in _SECRET_PATTERNS + _PII_PATTERNS:
        ok = _VALIDATORS.get(label)
        text = pat.sub(
            lambda m, ok=ok: _redact(m.group(0)) if (ok is None or ok(m.group(0))) else m.group(0),
            text,
        )
    return text


def check_secrets_pii(artifact_text: str) -> Finding:
    hits: list[str] = []
    artifact_text = _canon(artifact_text)
    for label, pat in _SECRET_PATTERNS + _PII_PATTERNS:
        for m in _pattern_hits(label, pat, artifact_text):
            hits.append(f"{label}: {_redact(m.group(0))}")
    if hits:
        # de-dupe while preserving order
        seen: set[str] = set()
        uniq = [h for h in hits if not (h in seen or seen.add(h))]
        return Finding(
            "Secret / PII scan",
            "FLAG",
            f"{len(uniq)} potential secret/PII pattern(s) detected (redacted).",
            items=uniq[:20],
        )
    return Finding(
        "Secret / PII scan",
        "PASS",
        "No known secret or PII patterns detected.",
    )


# ---------------------------------------------------------------------------
# 4. Internal consistency
# ---------------------------------------------------------------------------

# Grab "<label> ... <number>" pairs, e.g. "uptime of 99.9%" or
# "the latency was 12 ms". We bucket by a normalized metric label and flag
# when the same label is asserted with conflicting values.
# A bare "<word> <number>" ("Step 1", "Figure 2") is a counter, not a metric, so a
# match needs a connector word (was, is, of, =, :) or a unit.
_METRIC_RE = re.compile(
    r"([A-Za-z][A-Za-z ]{2,40}?)\s*(was|is|of|=|:|reached|hit|at)?\s*"
    r"\$?(\d[\d,]*(?:\.\d+)?)\s*(%|(?:percent|ms|gb|mb|s|x|k|m|b)\b)?",
    re.IGNORECASE,
)

_STOP_LABEL = re.compile(r"\b(the|a|an|and|or|of|to|in|on|for|with|by|at|is|was)\b\s*$",
                         re.IGNORECASE)
# Leading filler / possessives so "our uptime" and "uptime" collapse to one key.
_LEAD_FILLER = re.compile(
    r"^\s*(the|a|an|our|their|its|his|her|my|your|this|that|later in the doc,?|"
    r"overall|total|average|mean|median)\s+",
    re.IGNORECASE,
)


# Like _SENT_SPLIT_RE but also splits after a digit ("... in 2023. Revenue ...").
_CLAUSE_SPLIT_RE = re.compile(r"[.!?]+(?:\s+|$)|\n+")
_PERIOD_RE = re.compile(
    r"\b(?:(?:19|20)\d{2}|Q[1-4]|FY\d{2,4}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*)\b",
    re.IGNORECASE,
)


def _period(sentence: str, value_span: tuple[int, int]) -> str:
    """Years, quarters and months named in the same sentence, excluding the value
    itself, so a time series ("10 in 2023", "12 in 2024") is not a conflict."""
    found = sorted({m.group(0).lower() for m in _PERIOD_RE.finditer(sentence)
                    if m.end() <= value_span[0] or m.start() >= value_span[1]})
    return " ".join(found)


def _metric_key(label: str, unit: str) -> str:
    label = label.strip().lower()
    # strip leading filler repeatedly (e.g. "the average ...")
    prev = None
    while prev != label:
        prev = label
        label = _LEAD_FILLER.sub("", label).strip()
    label = _STOP_LABEL.sub("", label).strip()
    label = re.sub(r"\s+", " ", label)
    return f"{label}|{(unit or '').lower()}"


def extract_metrics(text: str) -> dict[str, set[str]]:
    metrics: dict[str, set[str]] = {}
    text = _canon(text)
    pos = 0
    for sentence in _CLAUSE_SPLIT_RE.split(text):
        start = text.find(sentence, pos)
        pos = start + len(sentence)
        for m in _METRIC_RE.finditer(sentence):
            label, connector, value, unit = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            if not connector and not unit:
                continue
            key = _metric_key(label, unit)
            bare_label = key.split("|", 1)[0]
            if len(bare_label) < 3:
                continue
            period = _period(sentence, m.span(3))
            norm_val = value.replace(",", "")
            metrics.setdefault(f"{key}|{period}" if period else key, set()).add(norm_val)
    return metrics


def check_internal_consistency(artifact_text: str) -> Finding:
    metrics = extract_metrics(artifact_text)
    conflicts: list[str] = []
    for key, values in metrics.items():
        if len(values) > 1:
            label, unit, *period = key.split("|")
            unit_s = f" {unit}" if unit else ""
            period_s = f" ({period[0]})" if period else ""
            vals = ", ".join(sorted(values))
            conflicts.append(f'"{label.strip()}"{period_s} asserted as: {vals}{unit_s}')
    if conflicts:
        return Finding(
            "Internal consistency",
            "FLAG",
            f"{len(conflicts)} metric(s) asserted with conflicting values.",
            items=conflicts[:20],
        )
    return Finding(
        "Internal consistency",
        "PASS",
        "No conflicting numeric assertions detected for any single metric.",
    )


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

DISCLAIMER = (
    "This report presents EVIDENCE and findings on the supplied artifact at a "
    "point in time. It is NOT a certification, attestation of compliance, legal "
    "opinion, or guarantee. The reader or their auditor renders any opinion."
)


def run_checks(
    artifact_path: str,
    source_paths: list[str],
    do_stamp: bool,
) -> dict:
    with open(artifact_path, "rb") as fh:
        artifact_bytes = fh.read()
    artifact_text = artifact_bytes.decode("utf-8", errors="replace")

    sources_text = ""
    loaded_sources: list[str] = []
    for sp in source_paths:
        with open(sp, "rb") as fh:  # an unreadable source is an error, never a silent skip
            sources_text += fh.read().decode("utf-8", errors="replace") + "\n"
        loaded_sources.append(sp)

    artifact_hash = sha256_bytes(artifact_bytes)
    timestamp = utc_now_iso()

    stamp_ok, stamp_detail = (False, "Provenance stamp not requested (--stamp to enable).")
    if do_stamp:
        stamp_ok, stamp_detail = opentimestamps_stamp(artifact_path)

    findings: list[Finding] = []

    # 1. Provenance - always PASS (it records evidence; it can't "fail")
    prov_detail = (
        f"SHA-256 recorded; report timestamped {timestamp}. "
        + (stamp_detail if do_stamp else "OpenTimestamps stamp not requested.")
    )
    findings.append(Finding("Provenance", "PASS", prov_detail))

    # 2. Source-grounding
    if loaded_sources:
        findings.append(check_source_grounding(artifact_text, sources_text))
    else:
        findings.append(
            Finding(
                "Source-grounding",
                "PASS",
                "No sources supplied; grounding not evaluated (provide --source to enable).",
            )
        )

    # 3. Secret / PII
    findings.append(check_secrets_pii(artifact_text))

    # An empty or control-only artifact is no evidence of a clean output.
    if not _canon(artifact_text).strip():
        findings.append(Finding(
            "Artifact content", "FLAG",
            "Artifact is empty (no printable content after normalization); nothing was assured.",
        ))

    # 4. Internal consistency
    findings.append(check_internal_consistency(artifact_text))

    overall_flags = [f for f in findings if f.status == "FLAG"]

    return {
        "artifact_path": display_path(artifact_path),
        "artifact_name": os.path.basename(artifact_path),
        "artifact_sha256": artifact_hash,
        "artifact_bytes": len(artifact_bytes),
        "timestamp_utc": timestamp,
        "sources": [display_path(s) for s in loaded_sources],
        "stamp_requested": do_stamp,
        "stamp_ok": stamp_ok,
        "stamp_detail": stamp_detail,
        "findings": [asdict(f) for f in findings],
        "flag_count": len(overall_flags),
        "tool_version": "1.0.0",
    }


def render_markdown(result: dict) -> str:
    lines: list[str] = []
    a = lines.append

    a("# AI-Output Assurance Report")
    a("")
    a(f"**Generated (UTC):** {result['timestamp_utc']}  ")
    a(f"**Tool:** assure.py v{result['tool_version']}")
    a("")
    a("## Artifact under examination")
    a("")
    a(f"- **File:** `{result['artifact_name']}`")
    a(f"- **Path:** `{result['artifact_path']}`")
    a(f"- **Size:** {result['artifact_bytes']} bytes")
    a(f"- **SHA-256:** `{result['artifact_sha256']}`")
    if result["sources"]:
        a(f"- **Sources supplied:** {len(result['sources'])}")
        for s in result["sources"]:
            a(f"  - `{s}`")
    else:
        a("- **Sources supplied:** none")
    a(f"- **Tamper-evident stamp:** {result['stamp_detail']}")
    a("")

    a("## Findings")
    a("")
    a("| Check | Result | Detail |")
    a("| --- | --- | --- |")
    for f in result["findings"]:
        detail = f["detail"].replace("|", "\\|")
        a(f"| {f['check']} | **{f['status']}** | {detail} |")
    a("")

    # Detailed items for any check that produced them
    detail_blocks = [f for f in result["findings"] if f.get("items")]
    if detail_blocks:
        a("### Flagged items (detail)")
        a("")
        for f in detail_blocks:
            a(f"**{f['check']}** ({f['status']}):")
            a("")
            for item in f["items"]:
                a(f"- {item}")
            a("")

    a("## Evidence summary")
    a("")
    total = len(result["findings"])
    flags = result["flag_count"]
    passes = total - flags
    a(f"- Checks run: **{total}**")
    a(f"- PASS: **{passes}**")
    a(f"- FLAG: **{flags}**")
    a("")
    if flags == 0:
        a(
            "No FLAGs were raised by the automated checks on this artifact at the "
            "time recorded above. This is an evidentiary observation, not an opinion "
            "of correctness or compliance."
        )
    else:
        a(
            f"{flags} check(s) raised one or more FLAGs requiring human review. "
            "FLAGs are findings for an auditor to evaluate; they are not "
            "determinations."
        )
    a("")

    a("## Disclaimer")
    a("")
    a("> " + DISCLAIMER)
    a("")
    a("---")
    a(
        f"_Report SHA-256 of artifact: `{result['artifact_sha256']}`; "
        f"generated by assure.py v{result['tool_version']}._"
    )
    a("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assure.py",
        description="Produce an EVIDENCE report on an AI-generated artifact.",
    )
    p.add_argument("artifact", help="Path to the AI-generated artifact (text/markdown/code).")
    p.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="SRC",
        help="Source file the artifact should be grounded against (repeatable).",
    )
    p.add_argument("--out", metavar="REPORT.md", help="Write the Markdown report to this path.")
    p.add_argument(
        "--stamp",
        action="store_true",
        help="Attempt an OpenTimestamps proof of the artifact (requires `ots`).",
    )
    p.add_argument("--json", action="store_true", help="Also emit the raw result as JSON to stdout.")
    return p


def _same_file(a: str, b: str) -> bool:
    """True if a and b are the same file, through symlinks or hard links."""
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
    except OSError:
        pass
    return os.path.realpath(a) == os.path.realpath(b)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.artifact):
        print(f"error: artifact not found: {args.artifact}", file=sys.stderr)
        return 2

    if args.out:
        for other in [args.artifact, *args.source]:
            if _same_file(args.out, other):
                print(f"error: --out would overwrite an input file ({os.path.basename(other)})",
                      file=sys.stderr)
                return 2

    try:
        with open(args.artifact, "rb") as fh:
            art_bytes = fh.read()
        for sp in args.source:
            with open(sp, "rb") as fh:
                same_bytes = fh.read() == art_bytes
            if same_bytes or _same_file(sp, args.artifact):
                print("error: --source is the artifact itself; it grounds nothing",
                      file=sys.stderr)
                return 2
    except OSError as exc:
        name = os.path.basename(exc.filename) if exc.filename else "input"
        print(f"error: could not read {name}: {exc.strerror or 'I/O error'}", file=sys.stderr)
        return 2

    try:
        result = run_checks(args.artifact, args.source, args.stamp)
    except OSError as exc:
        name = os.path.basename(exc.filename) if exc.filename else "input"
        print(f"error: could not read {name}: {exc.strerror or 'I/O error'}", file=sys.stderr)
        return 2
    report_md = render_markdown(result)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(report_md)
            print(f"report written to {args.out}", file=sys.stderr)
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 2
    elif args.json:
        sys.stderr.write(report_md)  # stdout carries only the JSON
    else:
        sys.stdout.write(report_md)

    if args.json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")

    return 1 if result["flag_count"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
