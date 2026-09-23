# Fixed 1-byte TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/builtins/fixed/fixed_1byte.h` |
| Reader descriptor | `tlv_reader_format_fixed_1byte` |
| Writer descriptor | `tlv_writer_format_fixed_1byte` |
| CMake option (default ON) | `OPENTLV_FORMAT_FIXED_1BYTE` |
| Link target | `tlv` |

## Scope and limits

One tag byte and one unsigned length byte; at most 255 value bytes. Values are opaque.

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed view.

## Minimal C usage

This complete example writes and reads one opaque byte. Exit code zero means success.

```c
#include "tlv/builtins/fixed/fixed_1byte.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = TLV_TAG(0x04);
    const uint8_t value[] = {0x2A};
    uint8_t output[8];
    size_t written = 0, consumed = 0;
    tlv_view_t view;
    if (tlv_write(output, sizeof(output), &tlv_writer_format_fixed_1byte,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(output, written, &tlv_reader_format_fixed_1byte,
                 &view, &consumed) != TLV_OK)
        return 1;
    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x04 && view.value.length == 1 &&
           view.value.data[0] == 0x2A ? 0 : 1;
}
```

Use `tlv_reader_format_fixed_1byte` and `tlv_writer_format_fixed_1byte` for a one-byte tag, a one-byte unsigned length,
and exactly that many value bytes. For example, `01 03 AA BB CC` encodes tag
`01` and the three-byte value `AA BB CC`. All tag bytes are valid, including
`00` and `FF`; lengths range from 0 to 255, with no BER-style prefixes.

```c
tlv_reader_t reader;
tlv_reader_init(&reader, data, size, &tlv_reader_format_fixed_1byte);
tlv_writer_t writer;
tlv_writer_init(&writer, buffer, capacity, &tlv_writer_format_fixed_1byte);
```

Writing a tag whose size is not 1 returns `TLV_ERR_INVALID_TAG_SIZE`; a value
longer than 255 bytes returns `TLV_ERR_INVALID_LENGTH`. Missing length or
value bytes return `TLV_ERR_BUFFER_TOO_SHORT`. An empty input is the end of
the stream (`TLV_ERR_END_OF_BUFFER`). Multiple records may be concatenated.

## Layout and typical use

```text
+--------+--------+-------------------------+
| Tag    | Length | Value                   |
| 1 byte | 1 byte | Length bytes (0-255)    |
+--------+--------+-------------------------+
```

The header is always two bytes, and the length counts the value only. There are no
long forms and no special length values, so `80` is an ordinary length. Use it for
small internal records and device protocol fields where every value fits in 255
bytes. For a different tag width, length width or byte order use the
[configurable fixed-width TLV](configurable.md).

## Byte example

One tag byte and one unsigned length byte, up to 255 value bytes.

```text
02 02 10 20
Element (4 bytes)
|-- Tag:    02
|-- Length: 02 = 2 value bytes
`-- Value:  10 20
```

For 128 value bytes, the header is `02 80`, followed by all 128 payload
bytes: `80` is an ordinary length here, not a BER indefinite-length marker.
Use `tlv_reader_format_fixed_1byte` / `tlv_writer_format_fixed_1byte`.
[Fixed format](README.md)
