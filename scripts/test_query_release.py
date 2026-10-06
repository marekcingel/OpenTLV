# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Candidate-gate regressions: provenance, hashes, parity and platform evidence."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from check_query_release import CHECKS, FACADES, evidence_errors


class ReleaseGate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "results.json"
        self.artifact.write_text('{"passed": true}\n')
        record = {"status": "passed", "artifact": "results.json",
                  "sha256": hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
                  "surface": "idiomatic", "capabilities": ["tlv_query_compile", "child"],
                  "pointer_bits": [32, 64]}
        self.evidence = {"commit": "candidate", "phases": {}, "facades": {}, "checks": {}}
        for category, names in (("phases", [f"F{n}" for n in range(1, 6)]),
                                ("facades", FACADES), ("checks", CHECKS)):
            self.evidence[category] = {name: copy.deepcopy(record) for name in names}

    def errors(self):
        return evidence_errors(self.evidence, self.root, "candidate", {"tlv_query_compile"}, ["child"])

    def test_complete_candidate(self):
        self.assertEqual(self.errors(), [])

    def test_wrong_commit_and_missing_or_failed_phase(self):
        self.evidence["commit"] = "old"
        self.assertTrue(self.errors())
        self.evidence["commit"] = "candidate"
        self.evidence["phases"]["F4"]["status"] = "failed"
        self.assertIn("missing passing candidate evidence: phases/F4", self.errors())

    def test_modified_and_missing_artifact(self):
        self.artifact.write_text("changed")
        self.assertTrue(any("changed" in error for error in self.errors()))
        self.artifact.unlink()
        self.assertTrue(any("missing or changed" in error for error in self.errors()))

    def test_paths_must_stay_inside_evidence_directory(self):
        for artifact in (str(self.artifact.resolve()), "../results.json"):
            self.evidence["phases"]["F5"]["artifact"] = artifact
            self.assertIn("artifact escapes evidence directory: phases/F5", self.errors())

    def test_raw_ffi_and_missing_capabilities(self):
        self.evidence["facades"]["Rust"]["surface"] = "ffi"
        self.evidence["facades"]["Lua"]["capabilities"] = []
        self.assertIn("raw FFI is insufficient: Rust", self.errors())
        self.assertIn("incomplete capabilities: facades/Lua", self.errors())

    def test_benchmarks_are_optional_and_advisory(self):
        self.assertNotIn("benchmarks", CHECKS)
        self.assertEqual(self.errors(), [])
        for record in (None, {"status": "failed"},
                       {"status": "passed", "baseline_accepted": False}):
            with self.subTest(record=record):
                self.evidence["checks"]["benchmarks"] = record
                self.assertEqual(self.errors(), [])

    def test_single_architecture_cannot_release(self):
        self.evidence["checks"]["ABI-32-64"]["pointer_bits"] = [64]
        self.assertTrue(any("32-bit" in error for error in self.errors()))

    def test_malformed_records_fail_closed(self):
        for value in (None, [], "passed"):
            self.evidence["facades"]["Go"] = value
            self.assertIn("missing passing candidate evidence: facades/Go", self.errors())
        self.evidence["checks"] = None
        self.assertTrue(self.errors())

    def test_malformed_architecture_evidence_fail_closed(self):
        for value in (None, 32, "32,64", [[32], 64], [32.0, 64], [True, 64]):
            with self.subTest(value=value):
                self.evidence["checks"]["ABI-32-64"]["pointer_bits"] = value
                self.assertIn("both 32-bit and 64-bit evidence required: ABI-32-64",
                              self.errors())


if __name__ == "__main__":
    unittest.main()
