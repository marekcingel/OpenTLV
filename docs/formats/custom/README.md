# Application-defined format example

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Header | `tlv/format.h` |
| Reader setup | `tlv_reader_format_init` |
| Writer setup | `tlv_writer_format_init` |
| CMake option | None; generic callbacks are always available |
| Link target | `tlv` |

## Scope and limits

The application supplies its descriptors, callbacks, and optional context.
Callbacks define valid tags and lengths, obey buffer bounds, and support writer
size queries. For a fixed-width tag and length, use the built-in
[configurable fixed-width format](../fixed/configurable.md) instead of custom
callbacks; write custom callbacks for anything with a different shape, such as
a variable-length or protocol-specific length field.
See [shared memory ownership rules](../../guides/memory.md).

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
