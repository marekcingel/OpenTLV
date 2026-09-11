# Application-defined format example

[Format documentation](../README.md)


## API and build

| Setting | Value |
| --- | --- |
| Header | `tlv/formats/format.h` |
| Reader setup | `tlv_reader_format_init` |
| Writer setup | `tlv_writer_format_init` |
| CMake option | None; generic callbacks are always available |
| Link target | `tlv` |

## Scope and limits

The application supplies its descriptors, callbacks, and optional context.
Callbacks define valid tags and lengths, obey buffer bounds, and support writer
size queries. There is no built-in configurable fixed-width descriptor.
See [shared memory ownership rules](../../memory.md).

## C usage

Use the complete custom-format implementation in the
[C example](../../../examples/tlv/src/basic_usage.c), which includes callback
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
[C example](../../../examples/tlv/src/basic_usage.c) and the
[callback contracts](../README.md#generic-interface). No built-in configurable
fixed-width descriptor is implied by this example.
