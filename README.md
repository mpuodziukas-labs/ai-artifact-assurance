# ai-artifact-assurance

Proves: a deterministic CLI turns an AI-generated draft plus its source files into a hashed evidence report, and its tests have teeth. Verify in 60s: `python3 assure.py samples/artifact.md --source samples/source.md; echo "exit code: $?"`

A small, deterministic, standard-library Python CLI. Input is an artifact (text, markdown or code) and optional source files. Output is a timestamped **evidence report** in Markdown.

> **Evidence, not attestation.** The tool gathers and presents findings on an artifact at a point in time. It does not certify it, attest to it, or give an opinion on correctness or compliance. Every report ends with that disclaimer.

## Business problem

AI-generated drafts can reach a customer or a payment run with a leaked credential, a number nobody can trace to a source, or two figures that contradict each other. This tool flags those before the draft ships and records what was checked, with a hash.

## Run it in 60 seconds

```bash
python3 assure.py samples/artifact.md --source samples/source.md
echo "exit code: $?"
```

The sample artifact is built to raise FLAGs, so the exit code is `1`. The printed report contains these lines (the timestamp and hash lines are the only ones that vary or are long):

```
| Source-grounding | **FLAG** | 3 of 6 claim span(s) not found in / supported by supplied sources. |
| Secret / PII scan | **FLAG** | 2 potential secret/PII pattern(s) detected (redacted). |
| Internal consistency | **FLAG** | 1 metric(s) asserted with conflicting values. |
- Checks run: **4**
- PASS: **1**
- FLAG: **3**
```

The committed copy of the full report is `samples/sample-report.md`. A test regenerates it and compares it, with timestamps masked.

Tests and mutation check (pytest is the only dependency):

```bash
pip install -r requirements.txt
python3 -m pytest -q
python3 mutants.py
```

`mutants.py` breaks `assure.py` in 7 known ways, on a temporary copy, and requires the test suite to fail each time. It exits 0 only if the control run passes and all 7 mutants are killed.

## Interface

```
python3 assure.py ARTIFACT [--source SRC ...] [--out REPORT.md] [--stamp] [--json]
```

Exit codes: `0` = report generated, no FLAGs; `1` = report generated, one or more FLAGs; `2` = usage or IO error. An empty artifact (or one that is only control characters) is a FLAG, exit `1`. With `--json`, stdout holds only the JSON and the Markdown report goes to stderr (or to `--out`). Exit 2 covers a missing or unreadable artifact or source, a `--source` that is the artifact (same file or same bytes), and an `--out` path that is the same file as the artifact or a source. No report is written in those cases.

Report format: artifact name, path, size, SHA-256 and UTC timestamp; a findings table (check, PASS or FLAG, detail); a flagged-items appendix; an evidence summary; the disclaimer.

## What it checks

1. **Provenance.** SHA-256 of the artifact and an ISO-8601 UTC timestamp. With `--stamp` and the optional `ots` binary it also writes an OpenTimestamps proof (only a hash leaves the machine).
2. **Source-grounding.** With `--source` files, it extracts quoted spans and sentences containing a number, then checks each against the sources. A span with a number, negation word or direction word (rose, fell) that no source carries is flagged even when the surrounding words match. Unsupported spans are shown clipped to 200 characters.
3. **Secret / PII scan.** Regex scan for leaked credentials (nine secret shapes) and obvious PII (four PII shapes). Text is NFKC-normalized, Markdown backslash escapes are stripped and invisible characters are removed before matching. Hits are redacted in the report, so the tool never echoes a full secret.
4. **Internal consistency.** Flags the same metric asserted with conflicting values, by simple, explainable heuristics. A named year, quarter or month separates metrics.

## Honesty Statement

- Every file under `samples/` is synthetic and was written for this repository. The organization in them is invented. Nothing here is production output or real data.
- The access token in `samples/artifact.md` is a made-up string planted so the secret scan has something to catch. It is not a credential for anything.
- The email address in the sample uses the reserved example.com domain.
- The tests run offline. The optional `--stamp` path (which needs the external `ots` tool and network access) is not exercised by the test suite.
- The sample report shows real behavior, including the consistency finding on two availability figures that carry the same label.

## Limitations

- Grounding is lexical (verbatim containment, then an 85% token-overlap fallback). It does not understand meaning, so it can miss paraphrased support (a false FLAG) and will not catch a claim that is grounded in the wrong source.
- Consistency matching keys on the words just before a number. A conflict phrased with different surrounding words is not detected, and unrelated sentences that share a label can be paired by mistake.
- Secret and PII detection is a fixed list of regular expressions (nine secret shapes, four PII shapes). Anything outside those shapes passes. Encoded secrets (base64 and similar) are not decoded, spelled-out emails such as `alice [at] example [dot] com` are not matched, and a random 13 to 19 digit number passes the Luhn check about one time in ten.
- Grounding compares numbers (with sign and scale: `-12%` is not `12%`, `$5M` is not `$5B`), negation words and direction words against the whole source set, not against the matching sentence. A number that appears anywhere in a source supports a span that uses it elsewhere, and a swapped subject with the same words is not detected.
- Only quoted spans and sentences containing a digit are checked. A false statement with no quote and no number is never examined.
- Runtime grows linearly with input size, about 2 to 3 seconds per 400 KB in the consistency check on plain prose. Measure it on your machine: `python3 -c "import time,assure;s=time.time();assure.extract_metrics('word '*80000);print(round(time.time()-s,1),'s')"`.
- Report paths are shown relative to the directory you run the tool from.
- Absence of a FLAG is not proof of absence. A human reviewer renders any opinion.

## Tests

Each check has a planted positive (must FLAG) and a clean negative (must PASS), plus hash determinism and end-to-end CLI runs. `tests/test_hostile.py` and `tests/test_redteam.py` hold adversarial cases: evasion by invisible or look-alike characters, secret shapes, changed numbers and negation in quoted claims, false positives (order ids, step numbers), exit codes, absolute paths in output, and a check that the shape counts in this README equal the counts in the code. Tests marked strict-xfail document known gaps.

## License

MIT. See [LICENSE](LICENSE).
