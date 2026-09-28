# Application-defined format example

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Header | `tlv/format.h`, `tlv/layout.h` |
| Setup | `tlv_format_init` or `tlv_fields_format_init` |
| CMake option | None; generic callbacks are always available |
| Link target | `tlv` |

## Scope and limits

The application supplies its descriptors, callbacks, and optional context.
Callbacks define valid tags and lengths, obey buffer bounds, and support writer
size queries. For a fixed-width tag and length, use the built-in
[configurable fixed-width format](../fixed/configurable.md) instead of custom
callbacks; write custom callbacks for anything with a different shape, such as
a variable-length or protocol-specific length field.
See [format context ownership and lifetime](../../guides/memory.md#format-context-ownership-and-lifetime).

For packed or otherwise transformed identifiers, set
`result->source.tag_binding = TLV_TAG_BINDING_FORMAT` in the decoder and return
semantic Tag bytes from immutable format-supplied storage. The default binding
requires a direct input slice. The optional source Tag range describes the wire
byte envelope, which may overlap Length; it does not hold the transformed bytes.
Storage must outlive all retained results and must not be reused as scratch.
See the [identifier contract](../../concepts/format-contract.md#decoded-identifier-consistency)
for validation, copying and lifetime rules. These semantics require a complete
Format callback; sequential `tlv_field_layout_t` helpers still describe byte
fields rather than packed bits.

## C usage

Use the complete custom-format implementation in the
[C example](../../../examples/tlv/src/custom_format.c), which includes callback
implementations, descriptor initialization, writing, and reading.
The [generic contract](../README.md#generic-interface) documents each callback.

## Byte example

Custom callbacks are implemented infrastructure, not one additional standardized
wire format. The bundled C example supplies a one-byte tag and a fixed two-byte
little-endian length:

```text
01 01 00 AA
Element (4 bytes)
|-- Tag:    01
|-- Length: 01 00 (little-endian) = 1 value byte
`-- Value:  AA
```

See the custom-format implementation in the
[C example](../../../examples/tlv/src/custom_format.c) and the
[callback contracts](../README.md#generic-interface). This particular shape -
a fixed-width tag and length - could also be built with the
[configurable fixed-width format](../fixed/configurable.md)
(`tag_size = 1, length_size = 2, order = TLV_BYTE_ORDER_LITTLE_ENDIAN`); the
example keeps hand-written callbacks to demonstrate the generic mechanism.
