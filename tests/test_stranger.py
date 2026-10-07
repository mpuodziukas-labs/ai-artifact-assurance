import subprocess, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {"LICENSE", "build_corpus.py", "tests/test_stranger.py"}
DASHES = ("\u2014", "\u2013")


def test_no_em_or_en_dash_in_tracked_text():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    bad = []
    for f in files:
        if f in SKIP or f.startswith("corpus/"):
            continue
        text = (ROOT / f).read_text(encoding="utf-8", errors="ignore")
        if any(d in text for d in DASHES):
            bad.append(f)
    assert not bad, bad


def test_readme_slowness_claim_has_a_command():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "extract_metrics" in text, "the per-400-KB timing needs a command that produces it"
    import re, sys, time
    sys.path.insert(0, str(ROOT))
    import assure
    s = time.time()
    assure.extract_metrics("word " * 80000)
    assert time.time() - s < 15
