# Configurable fixed-width TLV

[Format documentation](../README.md)

A fixed-width TLV format: a tag width, a length width (1 to 8 bytes) and a
length byte order, chosen independently instead of hardcoded. A one-byte tag
and a one-byte length is `tag_size = 1, length_size = 1, order =
TLV_BYTE_ORDER_BIG_ENDIAN` (or `fixed_format<1, 1,
TLV_BYTE_ORDER_BIG_ENDIAN>`); define your own file-scope constant for a
configuration your application reuses.

Two equivalent APIs share this wire layout:

- **C**, `tlv_fixed_config_t`: chosen at runtime, checked when the format is initialized.
- **C++**, `tlv::fixed_format<TagWidth, LengthWidth, Order>`: chosen at compile time, checked with `static_assert`.

## API and build

| Setting | C | C++ |
| --- | --- | --- |
| Header | `tlv/builtins/fixed/fixed.h` | `tlv++/builtins/fixed/fixed_format.hpp` (also usable without the rest of `tlv++`) |
| Configuration | `tlv_fixed_config_t{tag_size, length_size, order}` | `tlv::fixed_format<TagWidth, LengthWidth, Order>` |
| Reader descriptor | `tlv_fixed_reader_format_init(&format, &config)` | `fixed_format<...>::reader()` returns `const tlv_reader_format_t&` |
| Writer descriptor | `tlv_fixed_writer_format_init(&format, &config)` | `fixed_format<...>::writer()` returns `const tlv_writer_format_t&` |
| CMake option (default ON) | `OPENTLV_FORMAT_FIXED` | none (C++ header) |
| Link target | `tlv` | `tlv++` |

The C++ descriptors have static storage and a `NULL` context, so they never
need lifetime management. The C descriptors store the address of `config` as
their context: `config` must outlive every reader or writer built from it.
Both work with the reader, writer, walker, schemas and the C API. Neither
performs allocation.

## Supported parameters

| Parameter | C field | C++ template parameter | Supported values |
| --- | --- | --- | --- |
| Tag width | `tag_size` | `TagWidth` | 1 or more bytes |
| Length width | `length_size` | `LengthWidth` | 1 to 8 bytes |
| Length byte order | `order` | `Order` | `TLV_BYTE_ORDER_BIG_ENDIAN`, `TLV_BYTE_ORDER_LITTLE_ENDIAN` |

An out-of-range C++ template argument fails to compile with a `static_assert`
message; an invalid C `tlv_fixed_config_t` is rejected at init time (see
[Errors](#errors)).

## Wire layout

Each element is `tag_size`/`TagWidth` tag bytes, `length_size`/`LengthWidth`
length bytes and then that many value bytes.

- Tags are raw bytes and are never reordered; the byte order applies only to the length field.
- The length counts the value only, not the header.
- Every tag byte value is valid. Values are opaque and read in place from the input.

```text
tag_size = 2, length_size = 2, order = TLV_BYTE_ORDER_LITTLE_ENDIAN

12 34 03 00 AA BB CC
Element (7 bytes)
|-- Tag:    12 34
|-- Length: 03 00 = 3 value bytes (little-endian)
`-- Value:  AA BB CC
```

## Errors

| Situation | Result |
| --- | --- |
| `config` (C) is `NULL`, `tag_size` is 0, or `length_size` is 0 or greater than 8 | `TLV_ERR_INVALID_ARG` (init only) |
| `order` (C) is neither big- nor little-endian | `TLV_ERR_INVALID_BYTE_ORDER` (init only) |
| Input has fewer bytes than the tag, length or value needs | `TLV_ERR_BUFFER_TOO_SHORT` |
| Output capacity is smaller than the element | `TLV_ERR_BUFFER_TOO_SHORT` |
| Written tag size differs from the configured tag width | `TLV_ERR_INVALID_TAG_SIZE` |
| Value longer than the largest length the length width can hold | `TLV_ERR_INVALID_LENGTH` |
| Decoded length does not fit in `size_t` (for example an 8-byte length on a 32-bit target) | `TLV_ERR_INVALID_LENGTH` |

## Example (C)

<!-- example: examples/tlv/src/builtins/fixed/fixed_format.c -->
```c
/*
 * Defines a fixed-width TLV format at runtime: two tag bytes and a one-byte
 * length, then writes and reads one element. See tlv/builtins/fixed/fixed.h.
 */
#include <stdio.h>
#include "tlv/builtins/fixed/fixed.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void) {
    const tlv_fixed_config_t config = {
        .tag_size = 2, .length_size = 1, .order = TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from it. */
    tlv_reader_format_t reader_format;
    tlv_writer_format_t writer_format;
    CHECK(tlv_fixed_reader_format_init(&reader_format, &config));
    CHECK(tlv_fixed_writer_format_init(&writer_format, &config));

    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t       encoded[16];
    size_t        written = 0, consumed = 0;
    tlv_view_t    view;

    CHECK(tlv_write(encoded, sizeof(encoded), &writer_format, (TLV_TAG(0x12, 0x34)), value,
                    sizeof(value), &written));
    /* Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte. */
    CHECK(tlv_read(encoded, written, &reader_format, &view, &consumed));

    return consumed == written && view.tag.size == 2 && view.value.length == sizeof(value) ? 0 : 1;
}
```

## Example (C++)

<!-- example: examples/tlv++/src/builtins/fixed/fixed_format.cpp -->
```cpp
// Defines a fixed-width TLV format at compile time: two tag bytes and a
// two-byte little-endian length, then writes and reads one element.
#include <array>
#include <cstddef>
#include <iostream>

#include "tlv++/builtins/fixed/fixed_format.hpp"
#include "tlv++/tlv.hpp"

using format = tlv::fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>;

int main() {
    std::array<tlv::byte, 16> buf{};
    tlv::writer               writer(buf.data(), buf.size(), format::writer());

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto written = writer.write(TLV_TAG(0x12, 0x34), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 00 AA BB CC. The tag is kept as is; only the length is little-endian.
    tlv::reader reader(tlv::bytes(buf.data(), writer.size()), format::reader());
    auto        entry = reader.next();
    if (!entry) {
        std::cerr << "read error: " << entry.error().message << "\n";
        return 1;
    }
    std::cout << "wrote " << writer.size() << " bytes, read a " << entry->value.size()
              << "-byte value\n";
    return entry->value.size() == value.size() ? 0 : 1;
}
```

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed view.
