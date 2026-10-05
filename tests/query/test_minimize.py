# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Shrinking preserves native-failure predicates and independent identities."""
import unittest
from minimize import minimize, query_candidates
from reference import select


class MinimizeTest(unittest.TestCase):
    def test_subtree_offsets_and_predicates_are_recomputed(self):
        case = {"wire": "70075001005a0201025001ff", "query": "//5A[@len > 0]"}
        reduced, attempts = minimize(case, lambda candidate, expected: bool(expected))
        self.assertEqual(reduced["wire"], "70025a00")
        self.assertEqual(reduced["query"], "//5A")
        self.assertEqual(reduced["matches"], [2])
        self.assertEqual(select(reduced["query"], bytes.fromhex(reduced["wire"])), [2])
        self.assertGreater(attempts, 0)

    def test_budget_and_rejected_candidates(self):
        case = {"wire": "5a020102500100", "query": "//5A"}
        reduced, attempts = minimize(case, lambda candidate, expected: False, budget=1)
        self.assertEqual(reduced, case)
        self.assertEqual(attempts, 1)

    def test_quoted_brackets_and_nested_predicates(self):
        candidates = list(query_candidates("//5A[contains(value(), '[x]')][50[1]]"))
        self.assertEqual(len(candidates), 3)
        self.assertIn("//5A[50[1]]", candidates)
        self.assertIn("//5A[contains(value(), '[x]')][50]", candidates)


if __name__ == "__main__":
    unittest.main()
