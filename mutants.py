#!/usr/bin/env python3
"""Mutation check: break assure.py in known ways and require the test suite to fail.

  python3 mutants.py

Exit 0 = the unmodified code passes AND every mutant is killed (tests fail).
Exit 1 = a mutant survived or the control run failed.
Works on a temporary copy; the real files are never edited.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))

# (name, exact text in assure.py, replacement). Each old text must occur once.
MUTANTS = [
    ("hash drops last byte", "h.update(chunk)", "h.update(chunk[:-1])"),
    ("secret regex too strict", 'ghp_[A-Za-z0-9]{20,}', 'ghp_[A-Za-z0-9]{200,}'),
    ("luhn check always true", "return total % 10 == 0", "return True"),
    ("negation word list loses 'never'", "(?:not|no|never|none", "(?:not|no|none"),
    ("grounding fallback threshold lowered", ">= 0.85", ">= 0.10"),
    ("exit code ignores flags", 'return 1 if result["flag_count"] > 0 else 0', "return 0"),
    ("disclaimer removed", "NOT a certification, attestation of compliance", "is a document, with compliance"),
]


def run_tests(cwd):
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
        cwd=cwd, capture_output=True, text=True, timeout=300,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )
    return r.returncode


def fresh_copy():
    d = os.path.join(tempfile.mkdtemp(prefix="mut-"), "repo")
    shutil.copytree(ROOT, d, ignore=shutil.ignore_patterns("__pycache__", ".git", ".pytest_cache"))
    return d


def main():
    d = fresh_copy()
    try:
        if run_tests(d) != 0:
            print("control run FAILED: unmodified code must pass the tests")
            return 1
        survived = 0
        for name, old, new in MUTANTS:
            src = open(os.path.join(d, "assure.py"), encoding="utf-8").read()
            if src.count(old) != 1:
                print(f"BAD MUTANT {name}: pattern occurs {src.count(old)} times")
                return 1
            with open(os.path.join(d, "assure.py"), "w", encoding="utf-8") as fh:
                fh.write(src.replace(old, new))
            killed = run_tests(d) != 0
            print(f"{'killed  ' if killed else 'SURVIVED'} {name}")
            survived += 0 if killed else 1
            with open(os.path.join(d, "assure.py"), "w", encoding="utf-8") as fh:
                fh.write(src)
        print(f"mutants killed: {len(MUTANTS) - survived}/{len(MUTANTS)}")
        return 1 if survived else 0
    finally:
        shutil.rmtree(os.path.dirname(d), ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
