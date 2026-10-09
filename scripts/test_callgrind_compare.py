#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Regression checks for comparable workload selection and build isolation."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import callgrind_compare as comparison


class ComparisonTests(unittest.TestCase):
    def result(self, **changes):
        value = {"workload": "reader", "iterations": 100, "elapsed_ns": 1234,
                 "checksum": 42, "input_bytes": 4608, "input_id": "fixed-v1"}
        value.update(changes)
        return value

    def test_rejects_different_inputs_or_results(self):
        baseline = self.result()
        for change in ({"input_id": "v2"}, {"input_bytes": 100}, {"checksum": 43},
                       {"iterations": 99}, {"workload": "writer"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.require_equivalent(baseline, self.result(**change))

    def test_instrumented_and_native_runs_can_have_different_iteration_counts(self):
        comparison.require_equivalent(self.result(), self.result(iterations=1000, checksum=420),
                                      include_checksum=False)
        with self.assertRaises(ValueError):
            comparison.require_equivalent(self.result(), self.result(input_id="changed"),
                                          include_checksum=False)
        with self.assertRaises(ValueError):
            comparison.require_equivalent(self.result(), self.result(iterations=1000, checksum=421),
                                          include_checksum=False)

    def test_invalid_or_missing_measurements_are_not_clean_results(self):
        for change in ({"iterations": 101}, {"elapsed_ns": 0}, {"elapsed_ns": True},
                       {"elapsed_ns": "123"}, {"input_bytes": -1}, {"checksum": None},
                       {"input_id": ""}, {"workload": "query"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.validate_result(json.dumps(self.result(**change)), "reader", 100)
        self.assertEqual(comparison.validate_result(json.dumps(self.result()), "reader", 100), self.result())
        # Definition-check-only workloads read no input.
        self.assertEqual(comparison.validate_result(json.dumps(self.result(input_bytes=0)), "reader", 100),
                         self.result(input_bytes=0))
        with self.assertRaisesRegex(ValueError, "JSON result object"):
            comparison.validate_result("[]", "reader", 100)

    def test_configs_are_optimized_and_separate(self):
        commands = {mode: comparison.configure_command(Path("harness"), Path("library"),
                                                        Path(mode), mode, "/usr/bin/gcc")
                    for mode in ("callgrind", "native")}
        self.assertIn("-DCMAKE_BUILD_TYPE=RelWithDebInfo", commands["callgrind"])
        self.assertIn("-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O2 -g -DNDEBUG", commands["callgrind"])
        self.assertIn("-DOPENTLV_CALLGRIND_INSTRUMENTATION=ON", commands["callgrind"])
        self.assertIn("-DCMAKE_BUILD_TYPE=Release", commands["native"])
        self.assertIn("-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG", commands["native"])
        self.assertIn("-DOPENTLV_CALLGRIND_INSTRUMENTATION=OFF", commands["native"])
        for command in commands.values():
            self.assertIn("-DCMAKE_C_FLAGS=", command)
            self.assertIn("-DCMAKE_EXE_LINKER_FLAGS=", command)

    def test_failed_command_keeps_diagnostics(self):
        failed = mock.Mock(returncode=2, stdout="stdout detail", stderr="compiler rejected input")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "command.log"
            with mock.patch.object(comparison.subprocess, "run", return_value=failed):
                with self.assertRaisesRegex(RuntimeError, "compiler rejected input"):
                    comparison.run(["compiler", "argument with spaces"], log)
            self.assertIn("stdout detail", log.read_text())
            self.assertIn("compiler rejected input", log.read_text())

    def test_source_changes_change_provenance_even_with_same_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "file.c").write_text("first", encoding="utf-8")
            def git(command):
                option = command[3:]
                if option == ["rev-parse", "--show-toplevel"]:
                    return str(root)
                if option == ["rev-parse", "HEAD"]:
                    return "a" * 40
                if option[0] == "status":
                    return " M file.c\n"
                return "file.c\0"
            with mock.patch.object(comparison, "run", side_effect=git):
                before = comparison.source_metadata(root)
                (root / "file.c").write_text("second", encoding="utf-8")
                after = comparison.source_metadata(root)
            self.assertEqual(before["sha"], after["sha"])
            self.assertNotEqual(before["tree_sha256"], after["tree_sha256"])
            self.assertTrue(before["dirty"])

    def test_timeout_is_reported_as_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "timeout.log"
            with mock.patch.object(comparison.subprocess, "run", side_effect=
                                   comparison.subprocess.TimeoutExpired("workload", 1,
                                                                        output=b"partial output",
                                                                        stderr="error detail")):
                with self.assertRaisesRegex(RuntimeError, "exceeded 1s"):
                    comparison.run(["workload"], log=log, timeout=1)
            self.assertIn("partial output", log.read_text())
            self.assertIn("error detail", log.read_text())

    def test_threshold_rejects_non_finite_values(self):
        for value in ("nan", "inf", "-1"):
            with self.subTest(value=value), self.assertRaises(comparison.argparse.ArgumentTypeError):
                comparison.nonnegative_float(value)


if __name__ == "__main__":
    unittest.main()
