# Configurable fixed-width TLV (C++)

[Format documentation](../README.md)

`tlv::fixed_format` is a C++11 template that generates fixed-width formats at
compile time from a tag width, a length width and a length byte order. It
generalizes [Fixed 1-byte TLV](README.md): `fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>`
encodes the same bytes.

## API and build

| Setting | Value |
| --- | --- |
| Header | `tlv++/builtins/fixed/fixed_format.hpp` (also usable without the rest of `tlv++`) |
| Template | `tlv::fixed_format<TagWidth, LengthWidth, Order>` |
| Reader descriptor | `fixed_format<...>::reader()` returns `const tlv_reader_format_t&` |
| Writer descriptor | `fixed_format<...>::writer()` returns `const tlv_writer_format_t&` |
| Link target | `tlv++` |

The descriptors have static storage and a `NULL` context, so they never need
lifetime management. They work with `tlv::reader`, `tlv::writer`, the walker,
schemas and the C API. The format needs no CMake option and performs no allocation.

## Supported parameters

| Parameter | Supported values |
| --- | --- |
| `TagWidth` | 1 or more bytes |
| `LengthWidth` | 1 to 8 bytes |
| `Order` | `TLV_BYTE_ORDER_BIG_ENDIAN`, `TLV_BYTE_ORDER_LITTLE_ENDIAN` |

Any other value fails to compile with a `static_assert` message.

## Wire layout

Each element is `TagWidth` tag bytes, `LengthWidth` length bytes and then that
many value bytes.

- Tags are raw bytes and are never reordered; `Order` applies only to the length field.
- The length counts the value only, not the header.
- Every tag byte value is valid. Values are opaque and read in place from the input.

```text
fixed_format<2, 2, TLV_BYTE_ORDER_LITTLE_ENDIAN>

12 34 03 00 AA BB CC
Element (7 bytes)
|-- Tag:    12 34
|-- Length: 03 00 = 3 value bytes (little-endian)
`-- Value:  AA BB CC
```

## Errors

Errors match the built-in fixed format.

| Situation | Result |
| --- | --- |
| Input has fewer bytes than the tag, length or value needs | `TLV_ERR_BUFFER_TOO_SHORT` |
| Output capacity is smaller than the element | `TLV_ERR_BUFFER_TOO_SHORT` |
| Written tag size differs from `TagWidth` | `TLV_ERR_INVALID_TAG_SIZE` |
| Value longer than `max_length` (the largest value `LengthWidth` bytes hold) | `TLV_ERR_INVALID_LENGTH` |
| Decoded length does not fit in `size_t` (for example an 8-byte length on a 32-bit target) | `TLV_ERR_INVALID_LENGTH` |

## Example

<!-- example: examples/tlv++/src/fixed_format.cpp -->
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
