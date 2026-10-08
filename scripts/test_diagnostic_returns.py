#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
import unittest
from check_diagnostic_returns import lifecycle_violations, violations


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


class LifecycleReturns(unittest.TestCase):
    def check(self, body):
        return lifecycle_violations('tlv_result_t f(exec_t* e) {\n' + body + '\n}')

    def test_direct_returns_without_diagnostics(self):
        for member in ('busy', 'finished', 'invalid', 'query_callbacks'):
            for access in ('e->', 'state.'):
                self.assertEqual(self.check(f'if ({access}{member}) return TLV_ERR_INVALID_ARG;'),
                                 [(2, 'f', member)])

    def test_query_error_and_multiline_compound_condition(self):
        self.assertEqual(self.check('if (e &&\n (e->busy || e->invalid || overlap(e))) {\n'
                                    '  query_diag_init(d);\n'
                                    '  return query_error(d, TLV_ERR_INVALID_ARG, EVENTS, 0, 0, "fresh");\n'
                                    '}'), [(5, 'f', 'busy')])
        self.assertTrue(self.check('if (!e->finished && ready(e))\n return TLV_ERR_INVALID_ARG;'))

    def test_comments_strings_and_unrelated_identifiers(self):
        self.assertFalse(self.check('/* if (e->busy) return TLV_ERR_INVALID_ARG; */\n'
                                    'const char* s = "if (e->invalid) return TLV_ERR_INVALID_ARG;";\n'
                                    'if (invalid || finished || busy || query_callbacks) return TLV_ERR_INVALID_ARG;\n'
                                    'if (e->invalid_argument || e->finished_count) return TLV_ERR_INVALID_ARG;\n'
                                    'if (bad /* e->busy */) return TLV_ERR_INVALID_ARG;'))

    def test_correct_state_and_propagated_errors(self):
        self.assertFalse(self.check('if (e->busy) return TLV_ERR_INVALID_STATE;\n'
                                    'if (e->invalid) return query_error(d, TLV_ERR_INVALID_STATE, STATE);\n'
                                    'if (e->finished) return rc;'))

    def test_sibling_nested_and_else_argument_checks(self):
        self.assertFalse(self.check('if (e->busy) return TLV_ERR_INVALID_STATE;\n'
                                    'if (overlap) return TLV_ERR_INVALID_ARG;\n'
                                    'if (e->finished) { if (overlap) return TLV_ERR_INVALID_ARG; }\n'
                                    'if (e->invalid) return TLV_ERR_INVALID_STATE;\n'
                                    'else return TLV_ERR_INVALID_ARG;\n'
                                    'if (e->busy) { if (valid) return TLV_OK; else return TLV_ERR_INVALID_ARG; }'))
        self.assertTrue(self.check('if (valid) { if (e->busy) return TLV_ERR_INVALID_ARG; }'))
        self.assertTrue(self.check('if (valid) return TLV_OK; else if (e->busy) return TLV_ERR_INVALID_ARG;'))
        self.assertTrue(self.check('if (e->busy) { if (ready) return TLV_OK; return TLV_ERR_INVALID_ARG; }'))

    def test_diagnostic_comment_cannot_suppress_lifecycle_mapping(self):
        self.assertTrue(self.check('if (e->invalid) {\n'
                                   '/* diagnostic-return: keep original diagnostic. */\n'
                                   'return TLV_ERR_INVALID_ARG;\n}'))

    def test_function_names_and_line_numbers(self):
        self.assertEqual(lifecycle_violations('int ok(void) { return TLV_OK; }\n'
                                              'int rejected(exec_t* e) {\n'
                                              '  if (e->busy) return TLV_ERR_INVALID_ARG;\n}'),
                         [(3, 'rejected', 'busy')])


if __name__ == '__main__':
    unittest.main()
