# C fuzz harnesses and seed corpus

See [local builds, execution, and reproduction](../../docs/fuzzing.md).
All harnesses are C99 and exercise only the C library.

Checked-in seed files use the `.bin` extension to identify binary test inputs.

`corpus/read`, `corpus/walk_tree`, and `corpus/der` contain raw TLV bytes, with no
selector prefix. Every enabled format receives the same input. A seed may be
valid for one format and invalid for another. Walker and DER limits are also
derived from input bytes without removing them from the parsed input.

Seed names describe framing cases: empty input/value, primitive values,
concatenated elements, truncated tag/length/value, invalid/overflowing lengths,
high-number tags, nested containers, BER indefinite framing and EOC errors,
noncanonical DER framing, and depth-limit boundaries. The raw formats use
`0x20` as a test-only constructed bit in the walker.

`corpus/roundtrip` uses a different layout: byte 0 modulo
`(TLV_TAG_MAX_SIZE + 1)` gives the candidate tag size, clamped to the remaining
input size; subsequent bytes hold that tag, followed by its value. Empty input
produces an empty candidate tag/value. Every input is also tested as a value
with the valid primitive tag `04`, ensuring successful writes are exercised.
Long-value seeds cover 127/128 and 255/256 length transitions.

Only seed inputs belong in these corpus directories. Store documentation here,
and write mutation discoveries and crash artifacts under the build directory.
