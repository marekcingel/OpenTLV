#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Exercise reproduction identity, corpus validation and failure evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from corpus import commit_seed, enumerate_cases, parser, preserve_failure, run


class CorpusContract(unittest.TestCase):
    def test_runner_captures_checker_failure_and_clears_it_on_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "generator.h"
            header.write_text("#define TLV_GENERATOR_VERSION 7\n")
            args = parser().parse_args([
                "--cli", "generator", "--checker", "checker", "--format", "fixed",
                "--commit", "abc", "--seed", "0", "--count", "1",
                "--root", str(root / "data"), "--failures", str(root / "failures"),
                "--generator-header", str(header)])

            def generator(command, **kwargs):
                (args.root / "000000.bin").write_bytes(b"\x01\x00")
                return subprocess.CompletedProcess(command, 0, "", "")

            def checker(command, **kwargs):
                Path(command[3]).write_bytes(b"\x01\x01\xff")
                return subprocess.CompletedProcess(command, 1, "", "injected mismatch")

            with patch("corpus.subprocess.run", side_effect=lambda command, **kw: (
                    generator(command, **kw) if command[0] == "generator" else checker(command, **kw))):
                self.assertEqual(run(args), 1)
            evidence = json.loads((args.failures / "000000" / "metadata.json").read_text())
            self.assertEqual(evidence["seed"], "0")
            self.assertEqual(evidence["generator"]["version"], 7)
            self.assertIn("injected mismatch", evidence["failure"])

            def passing_checker(command, **kwargs):
                Path(command[3]).write_bytes(Path(command[2]).read_bytes())
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("corpus.subprocess.run", side_effect=lambda command, **kw: (
                    generator(command, **kw) if command[0] == "generator"
                    else passing_checker(command, **kw))):
                self.assertEqual(run(args), 0)
            self.assertFalse((args.failures / "000000").exists())

    def test_seed_mapping(self):
        self.assertEqual(commit_seed("abc"), 13436514500253700074)
        self.assertEqual(commit_seed("ABC"), commit_seed("abc"))
        self.assertNotEqual(commit_seed("abc"), commit_seed("abd"))

    def test_missing_extra_and_empty_cases_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                enumerate_cases(root, 1)
            (root / "000000.bin").write_bytes(b"\x01\x00")
            self.assertEqual(enumerate_cases(root, 1), [root / "000000.bin"])
            (root / "000001.bin").write_bytes(b"")
            with self.assertRaises(ValueError):
                enumerate_cases(root, 2)
            with self.assertRaises(ValueError):
                enumerate_cases(root, 1)

    def test_failure_preserves_exact_bytes_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = root / "000731.bin"
            output = root / "output.tmp"
            case.write_bytes(b"\x04\x01\xff")
            output.write_bytes(b"\x04\x00")
            metadata = {"seed": "42", "format": "ber", "commit": "abc",
                        "generator": {"version": 1}, "options": {"max_depth": 4}}
            preserve_failure(root / "failures", case, metadata, "mismatch", output)
            saved = root / "failures" / "000731"
            self.assertEqual((saved / "input.bin").read_bytes(), case.read_bytes())
            self.assertEqual((saved / "output.bin").read_bytes(), output.read_bytes())
            evidence = json.loads((saved / "metadata.json").read_text())
            self.assertEqual(evidence["case"], 731)
            for key, value in metadata.items():
                self.assertEqual(evidence[key], value)


if __name__ == "__main__":
    unittest.main()
