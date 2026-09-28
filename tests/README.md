# Test layout

`unit/` contains component contract tests; `integration/` contains tests
that compose components. Both trees follow the library's module paths:

- Core contracts such as `format`, `tag` and `value` stay at the root.
- Generic codecs live in `codec/`, with separate files for fundamental
  values and IPv4.
- Generic formats live in `formats/`. Fixed-format examples using DHCP-like
  bytes belong here when they do not use the DHCP builtin.
- Protocol tests live in `builtins/<protocol>/`, including C++ wrapper tests.
- Reader, writer, schema, query and document tests use their module folders.

Keep cross-layer integration cases together when their purpose is composition.
Split component-specific cases by the source module they exercise.
C and C++ test sources are registered explicitly in `c_tests.cmake` and
`cxx_tests.cmake`; update both paths and optional-component filters when
moving files. Keep existing test names and assertions during file-only moves.
