# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Regressions for child-report failure propagation in the CTest launcher."""

import contextlib
import importlib.util
import io
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "memcheck", Path(__file__).resolve().parents[1] / "scripts" / "memcheck.py")
MEMCHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEMCHECK)


class MemcheckLauncherTest(unittest.TestCase):
    def run_launcher(self, reports, returncode=0, stale=False, started=()):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "MemoryChecker.1.log"
            if stale:
                old = Path(directory) / "MemoryChecker.1.old"
                old.mkdir()
                (old / "100.log").write_text("==100== ERROR SUMMARY: 0 errors from 0 contexts\n")

            def child(command):
                self.assertEqual(command[0], "valgrind")
                self.assertEqual(command[-2:], ["test-harness", "argument with spaces"])
                self.assertIn("--trace-children=yes", command)
                pattern = next(option.split("=", 1)[1] for option in command
                               if option.startswith("--log-file="))
                for pid, contents in reports.items():
                    Path(pattern.replace("%p", str(pid))).write_text(contents)
                for pid in started:
                    Path(pattern.replace("%p", str(pid))).with_suffix(".started").touch()
                return subprocess.CompletedProcess(command, returncode)

            with patch.object(MEMCHECK.subprocess, "run", side_effect=child), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = MEMCHECK.run([
                    "valgrind", f"--log-file={output}", "--trace-children=yes",
                    "test-harness", "argument with spaces"])
            return status, output.read_text()

    def test_clean_parent_and_children_are_aggregated(self):
        status, output = self.run_launcher({
            100: "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
            101: "==101== ERROR SUMMARY: 0 errors from 0 contexts\n",
        })
        self.assertEqual(status, 0)
        self.assertIn("==100==", output)
        self.assertIn("==101==", output)

    def test_expected_child_failure_cannot_hide_memcheck_errors(self):
        status, output = self.run_launcher({
            100: "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
            101: "==101== ERROR SUMMARY: 1 errors from 1 contexts\n",
        }, returncode=0)
        self.assertEqual(status, MEMCHECK.ERROR_EXIT)
        self.assertIn("101.log: Memcheck reported errors", output)

    def test_truncated_child_report_fails(self):
        status, output = self.run_launcher({
            100: "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
            101: "==101== Memcheck, a memory error detector\n",
        })
        self.assertEqual(status, MEMCHECK.ERROR_EXIT)
        self.assertIn("missing ERROR SUMMARY", output)

    def test_missing_reports_fail_even_with_old_successful_reports(self):
        status, output = self.run_launcher({}, stale=True)
        self.assertEqual(status, MEMCHECK.ERROR_EXIT)
        self.assertIn("no reports", output)

    def test_clean_sibling_cannot_hide_failure_to_start_valgrind(self):
        status, output = self.run_launcher({
            100: "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }, started=(100, 101))
        self.assertEqual(status, MEMCHECK.ERROR_EXIT)
        self.assertIn("101.log: missing report for a started native command", output)

    def test_ordinary_test_failure_is_preserved(self):
        status, _ = self.run_launcher({
            100: "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
        }, returncode=7)
        self.assertEqual(status, 7)

    def test_every_summary_in_one_process_log_is_checked(self):
        status, _ = self.run_launcher({
            100: "==100== ERROR SUMMARY: 1,000 errors from 1 contexts\n"
                 "==100== ERROR SUMMARY: 0 errors from 0 contexts\n",
        })
        self.assertEqual(status, MEMCHECK.ERROR_EXIT)

    def test_python_harness_wraps_all_native_executables_with_safe_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            native = "/native binaries/it'works $(literal)"
            command = [sys.executable, "harness.py", "--native", native,
                       "--cli", "/cli tool", "--checker", "/checker tool"]
            valgrind = ["/valgrind tool", "--trace-children=yes", "--log-file=/reports/%p.log"]
            actual = MEMCHECK.test_command(command, valgrind, reports)
            self.assertEqual(actual[:2], command[:2])
            for index in (3, 5, 7):
                wrapper = Path(actual[index])
                lines = wrapper.read_text().splitlines()
                self.assertEqual(lines[0], "#!/bin/sh")
                self.assertEqual(lines[1], ": > " + shlex.quote(str(reports)) + '/"$$.started" || exit 99')
                self.assertEqual(shlex.split(lines[2]), ["exec", *valgrind, command[index], "$@"])
                self.assertNotEqual(actual[index], command[index])

    def test_python_harness_without_native_executable_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no supported"):
                MEMCHECK.test_command([sys.executable, "harness.py"], ["valgrind"], Path(directory))


if __name__ == "__main__":
    unittest.main()
