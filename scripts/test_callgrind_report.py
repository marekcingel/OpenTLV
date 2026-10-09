#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Callgrind format and informational comparison regressions."""

from pathlib import Path
import tempfile
import unittest

from callgrind_report import ProfileError, compare_workload, parse_profile, render_markdown


# Format examples cover name and subposition compression, call edges, event
# ordering, omitted trailing zero counters, and a summary above attributed cost.
PROFILE = """# callgrind format
version: 1
creator: callgrind-3.22.0
pid: 123
cmd: ./benchmark reader 100
part: 1
positions: instr line
events: Dr Ir Dw
summary: 8 850 5

ob=(1) /build/candidate/benchmark
fl=(1) driver.c
fn=(1) main
0x8000 16 2 20 1
cfn=(2) func1
calls=1 0x8010 50
* * 5 400 2
cfi=(2) library.c
cfn=(3) func2
calls=3 0x8020 20
* * 7 400 2

fn=(2)
0x8010 51 3 100
cfl=(2)
cfn=(3)
calls=2 0x8020 20
* * 7 300 2

fl=(2)
fn=(3)
0x8020 20 0 400
+4 +1 0 200
-4 -1 0 100
totals: 5 820 1
"""


def profile(instructions, functions=None):
    return {"instructions": instructions,
            "functions": functions if functions is not None else {"work": instructions}}


class ProfileTest(unittest.TestCase):
    def parse(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "callgrind.out"
            path.write_text(content, encoding="utf-8")
            return parse_profile(path)

    def test_compressed_names_positions_and_call_costs(self):
        result = self.parse(PROFILE)
        self.assertEqual(result["instructions"], 850)
        self.assertEqual(result["self_instructions"], 820)
        self.assertEqual(result["unattributed_instructions"], 30)
        self.assertEqual(result["functions"], {"main": 20, "func1": 100, "func2": 700})

    def test_optional_summary_and_default_line_positions(self):
        result = self.parse("events: Ir\nfl=x.c\nfn=work\n10 42\ntotals: 42\n")
        self.assertEqual(result["instructions"], 42)
        self.assertEqual(result["unattributed_instructions"], 0)

    def test_same_symbol_in_multiple_files_and_inline_sources(self):
        result = self.parse("events: Ir\nfl=a.c\nfn=work\n1 2\nfi=inlined.h\n2 3\n"
                            "fl=b.c\nfn=work\n1 5\ntotals: 10\n")
        self.assertEqual(result["functions"], {"work": 10})

    def test_event_order_can_put_ir_last_and_missing_cost_is_zero(self):
        result = self.parse("events: Dr Ir\nsummary: 4 5\nfn=work\n1 4\n2 0 5\ntotals: 4 5\n")
        self.assertEqual(result["instructions"], 5)
        self.assertEqual(result["functions"], {"work": 5})

    def test_header_summary_may_precede_events(self):
        result = self.parse("summary: 5\nevents: Ir\nfn=work\n1 5\ntotals: 5\n")
        self.assertEqual(result["instructions"], 5)

    def test_hex_counters_and_zero_cost_rows(self):
        result = self.parse("events: Ir\nfn=work\n1 0xa\n2\ntotals: 0xa\n")
        self.assertEqual(result["instructions"], 10)

    def test_jumps_do_not_consume_following_self_cost(self):
        result = self.parse("events: Ir\nfn=work\n1 2\njump=2 10\njcnd=4 2 20\n2 3\ntotals: 5\n")
        self.assertEqual(result["instructions"], 5)

    def test_rejects_truncation_and_missing_footer(self):
        for content in (PROFILE.rstrip(), PROFILE.rsplit("totals:", 1)[0],
                        "events: Ir\nsummary: 5\nfn=work\n1 5\n"):
            with self.subTest(content=content[-60:]), self.assertRaises(ProfileError):
                self.parse(content)

    def test_rejects_inconsistent_totals_and_summary(self):
        for content in (PROFILE.replace("totals: 5 820 1", "totals: 5 821 1"),
                        PROFILE.replace("summary: 8 850 5", "summary: 8 819 5"),
                        PROFILE.replace("totals: 5 820 1", "totals: 6 820 1")):
            with self.subTest(content=content[-60:]), self.assertRaises(ProfileError):
                self.parse(content)

    def test_rejects_unsupported_event_layout_and_multipart(self):
        for content in (PROFILE.replace("events: Dr Ir Dw", "events: Dr Dw"),
                        PROFILE.replace("events: Dr Ir Dw", "events: Ir Ir Dw"),
                        PROFILE + "part: 2\nevents: Ir\ntotals: 0\n",
                        PROFILE.replace("positions: instr line", "positions: line instr"),
                        PROFILE.replace("events: Dr Ir Dw", "events: Dr Ir Dw\nevents: Ir")):
            with self.subTest(content=content[-60:]), self.assertRaises(ProfileError):
                self.parse(content)

    def test_rejects_undefined_or_conflicting_name_aliases(self):
        for content in (PROFILE.replace("\nfn=(3)", "\nfn=(99)"),
                        PROFILE.replace("\nfn=(3)", "\nfn=(3) other"),
                        PROFILE.replace("\nfn=(3)", "\nfn=(3")):
            with self.subTest(content=content[-100:]), self.assertRaises(ProfileError):
                self.parse(content)

    def test_rejects_invalid_counters_positions_and_incomplete_calls(self):
        for content in (PROFILE.replace("+4 +1 0 200", "+4 +1 0 -200"),
                        PROFILE.replace("+4 +1 0 200", "+4 nope 0 200"),
                        PROFILE.replace("+4 +1 0 200", "+4 +1 0 200 0 0"),
                        PROFILE.replace("fn=(2)\n0x8010", "calls=1 0x8010 20\nfn=(2)\n0x8010"),
                        "events: Ir\nfn=work\ncalls=1 20\n",
                        "events: Ir\n1 5\ntotals: 5\n"):
            with self.subTest(content=content[-100:]), self.assertRaises(ProfileError):
                self.parse(content)


class ComparisonTest(unittest.TestCase):
    def compare(self, baseline=100, candidate=110, before=(100, 100, 100),
                after=(100, 100, 100), **options):
        return compare_workload("Reader", profile(baseline), profile(candidate), before, after, **options)

    def test_instruction_warning_does_not_claim_native_slowdown(self):
        result = self.compare()
        self.assertTrue(result["instructions"]["warning"])
        self.assertEqual(result["instructions"]["delta"], 10)
        self.assertEqual(result["instructions"]["percent"], 10)
        self.assertEqual(result["native"]["signal"], "no_material_change")
        self.assertIn("slowdown is not established", result["assessment"])

    def test_both_thresholds_must_be_exceeded(self):
        self.assertFalse(self.compare(candidate=105)["instructions"]["warning"])
        self.assertFalse(self.compare(threshold_instructions=10)["instructions"]["warning"])
        self.assertTrue(self.compare(threshold_percent=9, threshold_instructions=9)["instructions"]["warning"])
        self.assertFalse(self.compare(candidate=80)["instructions"]["warning"])

    def test_zero_baseline_has_no_invented_percent(self):
        result = self.compare(baseline=0, candidate=10)
        self.assertIsNone(result["instructions"]["percent"])
        self.assertTrue(result["instructions"]["warning"])
        same = self.compare(baseline=0, candidate=0)
        self.assertEqual(same["instructions"]["percent"], 0)
        self.assertFalse(same["instructions"]["warning"])

    def test_native_medians_retain_samples_and_flag_noise(self):
        result = self.compare(before=(98, 100, 102), after=(110, 112, 114))
        self.assertEqual(result["native"]["baseline_median_ns"], 100)
        self.assertEqual(result["native"]["candidate_median_ns"], 112)
        self.assertEqual(result["native"]["delta_ns"], 12)
        self.assertEqual(result["native"]["baseline_cv_percent"], 2)
        self.assertEqual(result["native"]["signal"], "higher_time")
        self.assertEqual(result["native"]["baseline_ns"], [98, 100, 102])
        self.assertIn("before calling this a regression", result["assessment"])
        noisy = self.compare(after=(90, 100, 1000))
        self.assertEqual(noisy["native"]["candidate_median_ns"], 100)
        self.assertEqual(noisy["native"]["signal"], "noisy")
        self.assertEqual(self.compare(after=(90, 90, 90))["native"]["signal"], "lower_time")

    def test_all_function_differences_include_added_removed_and_unchanged(self):
        result = compare_workload("Reader", profile(120, {"removed": 10, "stable": 10, "up": 100}),
                                  profile(150, {"added": 20, "stable": 10, "up": 120}),
                                  [100] * 3, [100] * 3)
        functions = result["functions"]
        self.assertEqual([item["name"] for item in functions], ["added", "up", "removed", "stable"])
        self.assertIsNone(functions[0]["percent"])
        self.assertEqual(functions[2]["percent"], -100)
        self.assertEqual(functions[3]["delta"], 0)

    def test_invalid_thresholds_and_native_samples_fail(self):
        for options in ({"threshold_percent": -1}, {"threshold_percent": float("nan")},
                        {"threshold_instructions": float("inf")}, {"native_threshold_percent": True},
                        {"before": (1, 2)}, {"after": (1, 2, 3, 4)}, {"before": (0, 1, 2)},
                        {"before": (1, 1, float("inf"))}, {"candidate": -1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.compare(**options)

    def test_markdown_contains_provenance_deltas_native_and_function_report(self):
        comparison = self.compare(baseline=0, candidate=10)
        comparison["functions"][0]["name"] = "f<T|U>`()"
        report = render_markdown({"baseline_sha": "abc123", "candidate_sha": "def456",
                                  "metadata": {"iterations": 100, "compiler": "GCC 13"},
                                  "workloads": [comparison]}, top_functions=1)
        for expected in ("abc123", "def456", "GCC 13", "informational", "n/a (zero baseline)",
                         "Native Release", "+10", "3 samples per revision", "f&lt;T&#124;U&gt;&#96;()",
                         "more than 5%", "self Ir", "does not establish statistical confidence"):
            self.assertIn(expected, report)

    def test_dirty_snapshot_and_normalized_timings_are_visible_without_manifest_spam(self):
        metadata = {"native_iterations": 10,
                    "sources": {"baseline": {"sha": "abc", "dirty": False, "tree_sha256": "aabb"},
                                "candidate": {"sha": "def", "dirty": True, "tree_sha256": "ccdd",
                                              "files": {"unneeded-manifest-entry": "123"}}}}
        report = render_markdown({"baseline_sha": "abc", "candidate_sha": "def", "metadata": metadata,
                                  "workloads": [self.compare()]})
        self.assertIn("Candidate contains uncommitted source changes", report)
        self.assertIn("ccdd", report)
        self.assertIn("10.00 ns/iteration baseline", report)
        self.assertNotIn("unneeded-manifest-entry", report)

    def test_native_throughput_uses_native_iteration_count_and_input_bytes(self):
        workload = self.compare(before=(1e9, 1e9, 1e9), after=(2e9, 2e9, 2e9))
        workload["input_bytes"] = 1024 * 1024
        report = render_markdown({"baseline_sha": "abc", "candidate_sha": "def",
                                  "metadata": {"native_iterations": 10, "iterations": 2},
                                  "workloads": [workload]})
        self.assertIn("100,000,000.00 ns/iteration baseline", report)
        self.assertIn("200,000,000.00 ns/iteration candidate", report)
        self.assertIn("10.00 MiB/s baseline, 5.00 MiB/s candidate", report)

    def test_definition_check_share_relates_complete_and_check_only_workloads(self):
        check = compare_workload("schema_check", profile(300), profile(100), [100] * 3, [100] * 3)
        complete = compare_workload("schema_validate", profile(400), profile(200), [100] * 3, [100] * 3)
        complete["definition_check"] = "schema_check"
        check["input_bytes"] = 0
        report = render_markdown({"baseline_sha": "abc", "candidate_sha": "def",
                                  "metadata": {"native_iterations": 10, "iterations": 100},
                                  "workloads": [check, complete]})
        self.assertIn("| schema_validate | schema_check | 3 | 1 | 75.0% | 50.0% |", report)
        self.assertNotIn("MiB/s", report)
        plain = render_markdown({"baseline_sha": "abc", "candidate_sha": "def", "metadata": {},
                                 "workloads": [check]})
        self.assertNotIn("definition-check share", plain)


if __name__ == "__main__":
    unittest.main()
