# Default TLV

[Format documentation](../README.md)

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/formats/default/default.h` |
| Reader descriptor | `tlv_reader_format_default` |
| Writer descriptor | `tlv_writer_format_default` |
| CMake option (default ON) | `OPENTLV_FORMAT_DEFAULT` |
| Link target | `tlv` |

## Scope and limits

One raw tag byte; definite BER-style lengths up to 65,535 bytes. Values are opaque.

See [shared memory ownership rules](../../memory.md) before retaining a parsed view.

## Minimal C usage

This complete example writes and reads one opaque byte. Exit code zero means success.

```c
#include "tlv/formats/default/default.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

int main(void) {
    const tlv_tag_t tag = {{0x04}, 1};
    const uint8_t value[] = {0x2A};
    uint8_t output[8];
    size_t written = 0, consumed = 0;
    tlv_view_t view;
    if (tlv_write(output, sizeof(output), &tlv_writer_format_default,
                  tag, value, sizeof(value), &written) != TLV_OK)
        return 1;
    if (tlv_read(output, written, &tlv_reader_format_default,
                 &view, &consumed) != TLV_OK)
        return 1;
    return consumed == written && view.tag.size == 1 &&
           view.tag.data[0] == 0x04 && view.value.length == 1 &&
           view.value.data[0] == 0x2A ? 0 : 1;
}
```



## Byte example

One raw tag byte and a definite BER-style length, up to 65,535 value bytes.
The tag has no built-in constructed-bit interpretation.

```text
01 03 AA BB CC
Element (5 bytes)
|-- Tag:    01
|-- Length: 03 = 3 value bytes
`-- Value:  AA BB CC
```

For 128 value bytes, the header is `01 81 80`, followed by all 128 payload
bytes. This format supports BER-style lengths, not multi-byte BER tags.
Use `tlv_reader_format_default` / `tlv_writer_format_default`.
[Format contract](../README.md#generic-interface)

