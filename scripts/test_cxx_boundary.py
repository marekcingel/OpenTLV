#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Regression cases for the public C++ consumer architecture gate."""
import unittest
from check_cxx_boundary import violations


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
        self.assertEqual(["tlv_reader_t", "tlv_reader_next", "TLV_OK", "tlv :: native", "tlv::detail"],
                         self.symbols("tlv_reader_t r; tlv_reader_next(); TLV_OK; tlv :: native; tlv::detail;"))

    def test_lines_survive_multiline_comments(self):
        found = list(violations("consumer.cpp", "/*\ncomment\n*/\nTLV_OK;"))
        self.assertEqual(4, found[0]["line"])


if __name__ == "__main__":
    unittest.main()
