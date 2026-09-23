# C examples

- **Start here:** [`quick_start.c`](quick_start.c) -- the smallest possible round
  trip: write one element, read it back.

## Use cases

The same document is parsed, built, addressed and checked here as in
[`examples/tlv++`](../../tlv++/src/), [`bindings/rust/opentlv/examples`](../../../bindings/rust/opentlv/examples/)
and [`bindings/wasm/examples`](../../../bindings/wasm/examples/), so the same
operation can be compared across languages.

- [`parse.c`](parse.c) -- read a nested BER-TLV document.
- [`write.c`](write.c) -- build that same document from its parts.
- [`query.c`](query.c) -- address one field directly by path.
- [`validate.c`](validate.c) -- check the document's structure without decoding it.

## API tour

One topic per file: sequential I/O, explicit copies, schema validation while
walking, codecs and endian conversion, and a fully custom format.

- [`sequential_io.c`](sequential_io.c) -- a sequential writer and reader,
  `tlv_writer_copy_view`/`tlv_writer_copy_encoded`.
- [`copies.c`](copies.c) -- the explicit `tlv_copy_value`/`tlv_copy_encoded`/`tlv_copy_view`
  helpers.
- [`schema_walk_and_scan.c`](schema_walk_and_scan.c) -- schema validation inside a
  `tlv_walk()` callback, and recovering candidates with `tlv_scan()`.
- [`codecs_and_endian.c`](codecs_and_endian.c) -- an application value codec, and
  the standalone endian helpers.
- [`custom_format.c`](custom_format.c) -- defining your own reader/writer format.

## Builtins

Examples specific to one wire format or profile.

- [`builtins/asn1/ber.c`](builtins/asn1/ber.c) -- BER: multi-byte tags and
  long-form lengths.
- [`builtins/asn1/cer.c`](builtins/asn1/cer.c) -- CER: indefinite-length framing
  and segmented strings.
- [`builtins/emv/tag_decoding.c`](builtins/emv/tag_decoding.c) -- decoding a full
  EMV record with the built-in dictionary.
