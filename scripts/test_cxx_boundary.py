#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Regression cases for the public C++ consumer architecture gate."""
import json
from pathlib import Path
import tempfile
import unittest
from check_cxx_boundary import audit, consumers, load_baseline, violations


class BoundaryTests(unittest.TestCase):
    def symbols(self, source):
        return [item["symbol"] for item in violations("consumer.cpp", source)]

    def test_comments_and_strings_do_not_create_dependencies(self):
        self.assertEqual([], self.symbols('''// #include <tlv/error.h>
/* tlv_reader_next(); TLV_OK; */
const char* text = R"note(tlv::native and TLV_OK)note";
const char* quoted = "tlv_reader_t";
'''))

    def test_direct_and_internal_headers_are_rejected(self):
        self.assertEqual(["tlv/reader/reader.h", "tlv++/native.hpp", "tlv++/detail/visitor.hpp"],
                         self.symbols('''#include <tlv/reader/reader.h>
#include "tlv++/native.hpp"
#include <tlv++/detail/visitor.hpp>
#include <tlv/config.h>
'''))

    def test_include_text_inside_raw_strings_is_not_a_header(self):
        self.assertEqual(["tlv/error.h"], self.symbols('''const char* sample = R"sample(
#include "tlv/reader/reader.h"
)sample";
const char* comment_text = "/*";
#include "tlv/error.h"
'''))

    def test_native_tokens_and_spaced_namespaces_are_rejected(self):
        self.assertEqual(["tlv_reader_t", "tlv_reader_next", "TLV_OK", "tlv::native", "tlv::detail"],
                         self.symbols("tlv_reader_t r; tlv_reader_next(); TLV_OK; tlv :: native; tlv::detail;"))

    def test_native_members_have_distinct_normalized_symbols(self):
        self.assertEqual(["tlv::native::handle", "tlv::native::descriptor", "tlv::detail::access::get"],
                         self.symbols("tlv :: native :: handle(x); tlv::native::descriptor(x); tlv::detail::access::get(x);"))

    def test_lines_survive_multiline_comments(self):
        found = list(violations("consumer.cpp", "/*\ncomment\n*/\nTLV_OK;"))
        self.assertEqual(4, found[0]["line"])


class BaselineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.relative = "tests/interop.cpp"

    def source(self, text, relative=None):
        path = self.root / (relative or self.relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def baseline(self, **symbols):
        return {self.relative: {"reason": "Canonical C/C++ parity test.", "symbols": symbols}}

    def test_existing_interop_passes_only_at_its_exact_budget(self):
        self.source('#include <tlv++/tlv.hpp>\nTLV_OK; TLV_OK;')
        self.assertEqual([], audit(self.root, self.baseline(TLV_OK=2)))

    def test_existing_symbol_cannot_gain_an_occurrence(self):
        self.source('#include <tlv++/tlv.hpp>\nTLV_OK; TLV_OK;')
        failures = audit(self.root, self.baseline(TLV_OK=1))
        self.assertEqual(["TLV_OK"], [item["symbol"] for item in failures])
        self.assertIn("allows 1 occurrences", failures[0]["message"])

    def test_new_symbol_in_interop_file_is_not_exempt(self):
        self.source('#include <tlv++/tlv.hpp>\nTLV_OK; tlv_reader_next();')
        failures = audit(self.root, self.baseline(TLV_OK=1))
        self.assertEqual(["tlv_reader_next"], [item["symbol"] for item in failures])

    def test_swapping_native_members_does_not_reuse_a_namespace_budget(self):
        self.source('#include <tlv++/tlv.hpp>\ntlv::native::descriptor(x);')
        failures = audit(self.root, self.baseline(**{"tlv::native::handle": 1}))
        self.assertEqual(["tlv::native::descriptor", "tlv::native::handle"],
                         [item["symbol"] for item in failures])

    def test_new_native_headers_in_interop_files_are_rejected(self):
        self.source('#include <tlv++/tlv.hpp>\n#include <tlv/error.h>\nTLV_OK;')
        failures = audit(self.root, self.baseline(TLV_OK=1))
        self.assertEqual(["tlv/error.h"], [item["symbol"] for item in failures])

    def test_reduced_and_removed_symbols_make_budgets_stale(self):
        self.source('#include <tlv++/tlv.hpp>\nTLV_OK;')
        failures = audit(self.root, self.baseline(TLV_OK=2, TLV_ERR_LIMIT=1))
        self.assertEqual(["baseline", "baseline"], [item["kind"] for item in failures])
        self.assertEqual(["TLV_OK", "TLV_ERR_LIMIT"], [item["symbol"] for item in failures])

    def test_missing_or_no_longer_facade_consumer_has_stale_baseline(self):
        for source in (None, '#include <tlv/error.h>\nTLV_OK;',
                       '// #include <tlv++/tlv.hpp>\nTLV_OK;'):
            with self.subTest(source=source):
                if source is not None:
                    self.source(source)
                failures = audit(self.root, self.baseline(TLV_OK=1))
                self.assertEqual(["<file>"], [item["symbol"] for item in failures])
                self.assertEqual("baseline", failures[0]["kind"])

    def test_additional_cpp_extensions_are_scanned_in_all_consumer_roots(self):
        paths = []
        for folder in ("examples/tlv++", "tools/cli", "tests"):
            for extension in (".cc", ".cxx", ".inl"):
                relative = f"{folder}/consumer{extension}"
                self.source('#include <tlv++/tlv.hpp>\ntlv_reader_t reader;', relative)
                paths.append(relative)
        self.assertEqual(sorted(paths), sorted(path for path, _ in consumers(self.root)))
        self.assertEqual(sorted(paths), sorted(item["path"] for item in audit(self.root, {})))

    def test_pure_c_harness_and_commented_facade_includes_stay_outside_scope(self):
        self.source('#include <tlv/reader/reader.h>\ntlv_reader_t r;')
        self.source('// #include <tlv++/tlv.hpp>\ntlv_reader_t r;', 'tests/comments.cxx')
        self.assertEqual([], audit(self.root, {}))

    def test_baseline_requires_exact_symbols_positive_counts_and_reasons(self):
        path = self.root / "baseline.json"
        valid = self.baseline(TLV_OK=1)
        path.write_text(json.dumps({"version": 1, "files": valid}), encoding="utf-8")
        self.assertEqual(valid, load_baseline(path))
        invalid = [self.baseline(TLV_OK=0), self.baseline(TLV_OK=True),
                   self.baseline(**{"TLV_*": 1}), self.baseline(**{"tlv/*": 1}),
                   self.baseline(**{"tlv::native::*": 1}),
                   {"tests/*.cpp": valid[self.relative]},
                   {self.relative: {"reason": "", "symbols": {"TLV_OK": 1}}}]
        for baseline in invalid:
            with self.subTest(baseline=baseline):
                path.write_text(json.dumps({"version": 1, "files": baseline}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_baseline(path)


if __name__ == "__main__":
    unittest.main()
