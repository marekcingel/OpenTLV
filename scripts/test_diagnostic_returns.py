#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import unittest
from check_diagnostic_returns import violations


class DiagnosticReturns(unittest.TestCase):
    def check(self, body):
        return violations('tlv_result_t f(tlv_query_diagnostic_t* d) {\n' + body + '\n}')

    def test_detects_direct_error_and_resumable_status(self):
        for code in ('TLV_ERR_NULL_ARG', 'TLV_ERR_OVERFLOW', 'TLV_NEED_MORE_DATA'):
            self.assertEqual(self.check(f'query_diag_init(d); if (bad) return {code};')[0][2], code)

    def test_preflight_and_other_functions_are_excluded(self):
        self.assertFalse(self.check('if (overlap) return TLV_ERR_INVALID_ARG; query_diag_init(d); return TLV_OK;'))
        self.assertFalse(violations('void init(void) { query_diag_init(d); } int f(void) { return TLV_ERR_NULL_ARG; }'))

    def test_comments_strings_and_local_diagnostics_are_excluded(self):
        self.assertFalse(self.check('/* query_diag_init(d); */ return TLV_ERR_NULL_ARG;'))
        self.assertFalse(self.check('const char* s = "query_diag_init(d);"; return TLV_ERR_NULL_ARG;'))
        self.assertFalse(self.check('query_diag_init(local); return TLV_ERR_NULL_ARG;'))

    def test_nested_initialization_and_memset_are_detected(self):
        for init in ('if (d) tlv_reader_diagnostic_init(d);', 'memset(d, 0, sizeof *d);',
                     'tlv_diagnostic_init(&d->diagnostic, TLV_OK, 0);'):
            self.assertTrue(self.check(init + ' return TLV_ERR_VISITOR;'))

    def test_populated_return_requires_local_reason(self):
        self.assertFalse(self.check('query_diag_init(d); d->kind = TLV_QUERY_ERROR_EVENTS;\n'
                                    '/* diagnostic-return: category set above. */\nreturn TLV_ERR_INVALID_ARG;'))
        self.assertTrue(self.check('query_diag_init(d); /* diagnostic-return: */ return TLV_ERR_INVALID_ARG;'))

    def test_string_cannot_suppress_a_return(self):
        self.assertTrue(self.check('query_diag_init(d); const char* s = "diagnostic-return: populated";'
                                   'return TLV_ERR_INVALID_ARG;'))

    def test_helper_and_propagated_results_are_outside_lexical_guard(self):
        self.assertFalse(self.check('query_diag_init(d); return query_error(d, TLV_ERR_INVALID_ARG, 1, 0, 0, 0);'))
        self.assertFalse(self.check('query_diag_init(d); return rc;'))


if __name__ == '__main__':
    unittest.main()
