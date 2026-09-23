#!/usr/bin/env python3
"""Reference runner (Python / rfc8785).

Validates every vector in the a2a-jcs-v01 corpus against rfc8785 and
prints the result record the design doc specifies: corpus digest, spec
commit, per-vector pass/fail, coverage count. Run this against ANY other
RFC 8785 implementation by swapping the `canonicalize` function --
that substitution is the entire point of a runner separate from the
generator.
"""

from __future__ import annotations

import json
import sys

from pathlib import Path

import rfc8785


HERE = Path(__file__).resolve().parent
DEFAULT_VROOT = HERE
SPEC_COMMIT_PINNED = (
    "19598c4"  # a2a-protocol.org/A2A commit this corpus's clauses were read from
)


def canonicalize(obj: object) -> bytes | None:
    """Canonicalize obj with rfc8785, or None if it refuses the input."""
    try:
        return rfc8785.dumps(obj)
    except (ValueError, TypeError):
        return None


def signing_bytes(card: dict) -> bytes | None:
    """The bytes a card signature covers: drop `signatures` (rule 3), then RFC 8785.

    Swap this function for another implementation's signing path to test that
    path. The rule-3 vectors in both directions go through it, so an
    implementation that keeps `signatures` through canonicalization fails them.
    """
    return canonicalize({k: val for k, val in card.items() if k != "signatures"})


def check_vector(v: dict) -> tuple[bool, str]:
    """Check one vector record against this runner's oracle."""
    if v["disposition"] == "MUST-ACCEPT":
        obj = v["input"]
        rule3 = v["clause"] == "a2a-spec-8.4.1-rule-3"
        out = signing_bytes(obj) if rule3 else canonicalize(obj)
        if out is None:
            return False, "canonicalization raised, expected success"
        want = bytes.fromhex(v["expected"]["canonical_utf8_hex"])
        if out != want:
            return False, f"byte mismatch: got {out!r} want {want!r}"
        return True, "ok"
    # MUST-REJECT
    if v["clause"] == "a2a-spec-8.4.1-rule-3":
        # The input is presented AS a card's canonical signing bytes. A verifier
        # recomputes the signing bytes from the parsed card and refuses when they
        # differ. That comparison runs the implementation under test; a check on
        # the fixture alone would pass whatever the implementation does.
        raw = v["input_raw"].encode("utf-8")
        out = signing_bytes(json.loads(raw))
        if out is None:
            return False, "signing path raised on well-formed input"
        if out != raw:
            return True, "correctly refused: not this card's signing bytes"
        return False, "accepted claimed-canonical bytes that still carry 'signatures'"
    try:
        obj = json.loads(v["input_raw"])
    except json.JSONDecodeError:
        return True, "correctly refused (parse-level)"
    out = canonicalize(obj)
    if out is None:
        return True, "correctly refused (canonicalization-level)"
    return False, f"accepted input that should have been refused, produced {out!r}"


def main() -> int:
    """Run every vector in DEFAULT_VROOT (or sys.argv[1]) and print the result record."""
    vroot = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_VROOT
    manifest = json.loads((vroot / "MANIFEST.json").read_text())
    results = []
    for entry in manifest["vectors"]:
        v = json.loads((vroot / entry["path"]).read_text())
        ok, detail = check_vector(v)
        results.append({"id": v["id"], "pass": ok, "detail": detail})

    passed = sum(1 for r in results if r["pass"])
    record = {
        "runner": "python/rfc8785",
        "corpusDigest": manifest["corpusDigest"],
        "specCommit": SPEC_COMMIT_PINNED,
        "coverage": {
            "total": len(results),
            "passed": passed,
            "failed": len(results) - passed,
        },
        "results": results,
    }
    print(json.dumps(record, indent=2))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
