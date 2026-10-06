# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import unittest
from adversarial_campaign import minimize


class Minimize(unittest.TestCase):
    def test_retains_ordered_failure_and_removes_noise(self):
        def fails(seq):
            return 'E' in seq and 'V' in seq[seq.index('E') + 1:]
        minimal = minimize('BFXRNEBPFVXXRS', fails)
        self.assertEqual(minimal, 'EV')

    def test_stops_at_one_minimal_sequence(self):
        self.assertEqual(minimize('R', lambda seq: seq == 'R'), 'R')


if __name__ == '__main__':
    unittest.main()
