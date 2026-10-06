# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import unittest
from query_benchmark_budget import compare


class Budget(unittest.TestCase):
    def test_invalid_measurements_cannot_pass(self):
        stable = ({"query_platform": "test"}, {"query_compile": 100}, {"query_compile": .01})
        for value in (float("nan"), float("inf"), -1, 0):
            bad = ({"query_platform": "test"}, {"query_compile": value}, {"query_compile": .01})
            self.assertEqual(compare(stable, bad)[0]["status"], "invalid")
            self.assertEqual(compare(bad, stable)[0]["status"], "invalid")
        for value in (float("nan"), float("inf"), -1):
            bad = ({"query_platform": "test"}, {"query_compile": 100}, {"query_compile": value})
            self.assertEqual(compare(stable, bad)[0]["status"], "invalid")

    def test_platform_and_noise_are_not_success(self):
        stable = ({"query_platform": "test"}, {"query_compile": 100}, {"query_compile": .01})
        for other, expected in [(({}, {"query_compile": 100}, {}), "platform-unverified"),
                                (({"query_platform": "test"}, {"query_compile": 200},
                                  {"query_compile": .5}), "noisy")]:
            self.assertEqual(compare(stable, other)[0]["status"], expected)

    def test_stable_regression_and_missing_case(self):
        old = ({"query_platform": "test"}, {"query_compile": 100, "query_load": 1},
               {"query_compile": .01})
        new = ({"query_platform": "test"}, {"query_compile": 126}, {"query_compile": .01})
        self.assertEqual([row["status"] for row in compare(old, new)], ["regression", "missing"])


if __name__ == "__main__":
    unittest.main()
