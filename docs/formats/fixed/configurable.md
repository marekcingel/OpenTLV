# Configurable fixed-width TLV

[Format documentation](../README.md)

A fixed-width TLV format: a tag width, a length width (1 to 8 bytes) and a
length byte order, chosen independently instead of hardcoded. A one-byte tag
and a one-byte length is `tag_size = 1, length_size = 1, order =
TLV_BYTE_ORDER_BIG_ENDIAN` (or `fixed_format<1, 1,
TLV_BYTE_ORDER_BIG_ENDIAN>`); define your own file-scope constant for a
configuration your application reuses.

Two APIs share this wire layout, and the C++ one is a thin compile-time
wrapper that delegates every read and write to the C one:

- **C**, `tlv_fixed_format_t`: chosen at runtime, checked when the format is initialized.
- **C++**, `tlv::fixed_format<TagWidth, LengthWidth, Order>`: chosen at compile time, checked with
  `static_assert`, and built from `tlv_fixed_format_init()` internally.

## API and build

| Setting | C | C++ |
| --- | --- | --- |
| Header | `tlv/formats/fixed.h` | `tlv++/formats/fixed_format.hpp` |
| Configuration | `tlv_fixed_format_t{tag_size, length_size, order}` | `tlv::fixed_format<TagWidth, LengthWidth, Order>` |
| Descriptor | `tlv_fixed_format_init(&format, &config)` | `fixed_format<...>::format()` returns `const tlv_format_t&` |
| CMake option (default ON) | `OPENTLV_FORMAT_FIXED` | `OPENTLV_FORMAT_FIXED` |
| Link target | `tlv` | `tlv++` |

Both descriptors have static storage duration, so neither needs lifetime
management from the caller: the C++ descriptor's context is a static
`tlv_fixed_format_t` built from `TagWidth`, `LengthWidth` and `Order`, and the
C descriptor's context is the caller-owned `config` passed to
`tlv_fixed_format_init()`, which must outlive every reader or writer built
from it. See [format context ownership and
lifetime](../../guides/memory.md#format-context-ownership-and-lifetime) for
the general contract this follows, including copying, sharing and moving.
Both work with the reader, writer, walker, schemas and the C API. Neither
performs allocation.

## Supported parameters

| Parameter | C field | C++ template parameter | Supported values |
| --- | --- | --- | --- |
| Tag width | `tag_size` | `TagWidth` | 1 or more bytes |
| Length width | `length_size` | `LengthWidth` | 1 to 8 bytes |
| Length byte order | `order` | `Order` | `TLV_BYTE_ORDER_BIG_ENDIAN`, `TLV_BYTE_ORDER_LITTLE_ENDIAN` |

An out-of-range C++ template argument fails to compile with a `static_assert`
message; an invalid C `tlv_fixed_format_t` is rejected at init time (see
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

<!-- example: examples/tlv/src/formats/fixed_format.c -->
```c
/*
 * Defines a fixed-width TLV format at runtime: two tag bytes and a one-byte
 * length, then writes and reads one element. See tlv/formats/fixed.h.
 */
#include <stdio.h>
#include "tlv/formats/fixed.h"
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
    const tlv_fixed_format_t config = {
        .tag_size = 2, .length_size = 1, .order = TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from it. */
    tlv_format_t format;
    CHECK(tlv_fixed_format_init(&format, &config));

    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t       encoded[16];
    size_t        written = 0, consumed = 0;
    tlv_view_t    view;

    CHECK(tlv_write(encoded, sizeof(encoded), &format, (TLV_TAG(0x12, 0x34)), value, sizeof(value),
                    &written));
    /* Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte. */
    CHECK(tlv_read(encoded, written, &format, &view, &consumed));

    return consumed == written && view.tag.size == 2 && view.value.length == sizeof(value) ? 0 : 1;
}
```

## Example (C++)

<!-- example: examples/tlv++/src/formats/fixed_format.cpp -->
```cpp
// Defines a fixed-width TLV format at compile time: two tag bytes and a
// two-byte little-endian length, then writes and reads one element.
#include <array>
#include <cstddef>
#include <iostream>

#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/tlv.hpp"

using format = tlv::fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>;

int main() {
    std::array<tlv::byte, 16> buf{};
    tlv::writer               writer(buf.data(), buf.size(), format::format());

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto written = writer.write(TLV_TAG(0x12, 0x34), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 00 AA BB CC. The tag is kept as is; only the length is little-endian.
    tlv::reader reader(tlv::bytes(buf.data(), writer.size()), format::format());
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

## Example (C++, runtime-configurable)

Use the raw C `tlv_fixed_format_t`/`tlv_fixed_format_init()` directly when the
tag width, length width or byte order are not known at compile time — no
`tlv++` wrapper is needed, since `tlv::writer`/`tlv::reader` already accept a
plain `const tlv_format_t&`:

<!-- example: examples/tlv++/src/formats/fixed_format_runtime.cpp -->
```cpp
// Defines a fixed-width TLV format at runtime from tlv++: two tag bytes and a
// one-byte length, using the raw C tlv_fixed_format_t/tlv_fixed_format_init
// directly (no tlv++ wrapper is needed: tlv::writer/tlv::reader already take
// a plain `const tlv_format_t&`). See tlv/formats/fixed.h and
// docs/guides/memory.md#format-context-ownership-and-lifetime for why config
// must outlive every reader and writer built from it.
#include <array>
#include <iostream>

#include "tlv/formats/fixed.h"
#include "tlv++/tlv.hpp"

int main() {
    const tlv_fixed_format_t config = {/* tag_size */ 2, /* length_size */ 1,
                                       TLV_BYTE_ORDER_BIG_ENDIAN};
    /* config must outlive every reader and writer built from format. */
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;

    std::array<tlv::byte, 16> buf{};
    tlv::writer               writer(buf.data(), buf.size(), format);

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto written = writer.write(TLV_TAG(0x12, 0x34), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte.
    tlv::reader reader(tlv::bytes(buf.data(), writer.size()), format);
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
