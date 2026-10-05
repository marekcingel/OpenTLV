# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel
"""Regression tests for transitive allocation and recursion detection."""
import unittest
from check_query_contracts import violations
from check_query_objects import object_graph


class Contracts(unittest.TestCase):
    def test_hidden_allocation(self):
        errors, _ = violations({"query": {"helper"}, "helper": {"malloc"}}, {"query"})
        self.assertIn("query -> helper -> malloc", errors[0])

    def test_mutual_recursion(self):
        errors, _ = violations({"query": {"a"}, "a": {"b"}, "b": {"a"}}, {"query"})
        self.assertIn("recursive dependency", errors[0])

    def test_document_allocator_outside_boundary(self):
        errors, reached = violations({"query": {"node_tag"}, "document_new": {"malloc"}},
                                     {"query"})
        self.assertEqual(errors, [])
        self.assertNotIn("malloc", reached)

    def test_object_relocations_follow_transitive_allocator(self):
        graph = object_graph("""compiler.c.o: file format elf64-x86-64
00000000 <tlv_query_compile>:
  10: call 20 <hidden>
00000020 <hidden>:
  24: e8 00 00 00 00 call 29 <hidden+0x9>
  28: R_X86_64_PLT32 malloc-0x4
document.c.o: file format elf64-x86-64
00000000 <hidden>:
  10: R_X86_64_PLT32 calloc-0x4
""")
        errors, reached = violations(graph, {"compiler.c.o::tlv_query_compile"})
        self.assertIn("compiler.c.o::hidden -> malloc", errors[0])
        self.assertNotIn("calloc", reached)

    def test_object_external_helper_and_recursion(self):
        graph = object_graph("""query.c.o: file format elf64-x86-64
00000000 <tlv_query_next>:
  08: e8 00 00 00 00 call d <tlv_query_next+0xd>
  10: R_X86_64_PLT32 helper-0x4
other.c.o: file format elf64-x86-64
00000000 <helper>:
  08: e8 00 00 00 00 call d <helper+0xd>
  10: R_X86_64_PLT32 tlv_query_next-0x4
""")
        errors, _ = violations(graph, {"query.c.o::tlv_query_next"})
        self.assertIn("recursive dependency", errors[0])


if __name__ == "__main__":
    unittest.main()
