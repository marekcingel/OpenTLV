# Configurable fixed-width TLV

[Format documentation](../README.md)

A fixed-width TLV format: a tag width, a length width (1 to 8 bytes), a length
byte order, a field order and a length scope, chosen independently instead of
hardcoded. A one-byte tag and a one-byte length is `identifier.size = 1, length.size
= 1, length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN` (or `fixed_format<1, 1,
TLV_BYTE_ORDER_BIG_ENDIAN>`), with `element_order` and `length_scope` defaulted
to the conventional TLV/value-only shape; define your own file-scope constant
for a configuration your application reuses.

[Bluetooth LTV](../bluetooth/README.md) is this format preset to
`{{1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_LTV,
TLV_LENGTH_SCOPE_TAG_AND_VALUE}`.

Two APIs share this wire representation, and the C++ one is a thin compile-time
wrapper that delegates every read and write to the C one:

- **C**, `tlv_fixed_format_t`: chosen at runtime, checked when the format is initialized.
- **C++**, `tlv::fixed_format<TagWidth, LengthWidth, Order>`: chosen at compile time, checked with
  `static_assert`, and built from `tlv_fixed_format_init()` internally.

## API and build

| Setting | C | C++ |
| --- | --- | --- |
| Header | `tlv/formats/fixed.h` | `tlv++/formats/fixed_format.hpp` |
| Configuration | `tlv_fixed_format_t{{tag_size}, {length_size, length_order}, element_order, length_scope}` | `tlv::fixed_format<TagWidth, LengthWidth, Order>` (TLV element order, value-only length scope) |
| Descriptor | `tlv_fixed_format_init(&format, &config)` | `fixed_format<...>::format()` returns `const tlv_format_t&` |
| Availability | Always built | Always available with the C++ wrapper |
| Link target | `tlv` | `tlv++` |

Both descriptors have static storage duration, so neither needs lifetime
management from the caller: the C++ descriptor's context is a static
`tlv_fixed_format_t` built from `TagWidth`, `LengthWidth` and `Order`, and the
C descriptor's context is the caller-owned `config` passed to
`tlv_fixed_format_init()`, which must outlive every reader or writer built
from it. See [format context ownership and
lifetime](../../guides/memory.md#format-context-ownership-and-lifetime) for
the general contract this follows, including copying, sharing and moving.
Both work with the reader, writer, visitor, schemas and the C API. Neither
performs allocation.

## Standalone Field Encoding

Use `tlv/field/fixed.h` when only an individual Identifier or Length field is
needed. Its allocation-free primitives are available without Format headers,
Reader, Writer or optional builtin protocols:

| Configuration | Operations | Representation |
| --- | --- | --- |
| `tlv_fixed_identifier_t` | `tlv_fixed_identifier_read()`, `tlv_fixed_identifier_write()` | `size` raw identifier bytes; the configured width must be nonzero. |
| `tlv_fixed_length_t` | `tlv_fixed_length_read()`, `tlv_fixed_length_write()` | `size` count bytes, from 1 through 8, with explicit `byte_order`; counts use `tlv_size_t`. |

Identifier reading borrows the exact input bytes; writing requires an identifier
of the configured width and preserves its bytes. There is no numeric tag
conversion or byte-order normalization. Length operations accept explicit big
or little endian and reject counts that exceed the configured width, without
narrowing the logical count to `size_t`. Both write operations support width
measurement with NULL output and zero capacity.

Argument and configuration errors preserve outputs. Incomplete Identifier or
Length input reports the available prefix through `consumed` while leaving the
decoded identifier or count unchanged. Failed writes
preserve `written` and destination bytes. Identifier copying requires
nonoverlapping source and destination; no overlap guarantee is added.

These operations do not select field order, apply length scope or describe
complete elements. The binary composition callbacks adapt them to those rules;
the Escaped format reuses the same fixed identifier operations.
`tlv_binary_composition_t` embeds `tlv_fixed_identifier_t identifier` and
`tlv_fixed_length_t length`, alongside `element_order` and `length_scope`.
`tlv_fixed_format_t` remains the fixed-format name for this composition.
`tlv_escaped_format_t` embeds the same identifier configuration with an escaped
length configuration and uses the same ordering/scope member names.

Field primitives define the shared validation contract: required pointers,
configuration, field constraints, then buffer capacity. Format adapters forward
to this contract without compatibility pre-checks. Sizing validates the actual
byte order. See the [migration notes](../../concepts/format-contract.md#migration)
for source and diagnostic changes.

## Supported parameters

| Parameter | C field | C++ template parameter | Supported values |
| --- | --- | --- | --- |
| Tag width | `identifier.size` | `TagWidth` | 1 or more bytes |
| Length width | `length.size` | `LengthWidth` | 1 to 8 bytes |
| Length byte order | `length.byte_order` | `Order` | `TLV_BYTE_ORDER_BIG_ENDIAN`, `TLV_BYTE_ORDER_LITTLE_ENDIAN` |
| Element order | `element_order` | not configurable (always `TLV_ELEMENT_ORDER_TLV`) | `TLV_ELEMENT_ORDER_TLV` (tag, length, value), `TLV_ELEMENT_ORDER_LTV` (length, tag, value) |
| Length scope | `length_scope` | not configurable (always `TLV_LENGTH_SCOPE_VALUE`) | `TLV_LENGTH_SCOPE_VALUE` (counts only the value), `TLV_LENGTH_SCOPE_TAG_AND_VALUE` (counts the tag and the value) |

An out-of-range C++ template argument fails to compile with a `static_assert`
message; an invalid C `tlv_fixed_format_t` is rejected at init time (see
[Errors](#errors)).

<!-- markdownlint-disable-next-line MD033 -->
<a id="wire-layout"></a>

## Wire representation

Each element is `identifier.size`/`TagWidth` tag bytes and `length.size`/`LengthWidth`
length bytes, in the order `element_order` selects, followed by the value bytes.

- Tags are raw bytes and are never reordered; the byte order applies only to the length field.
- `TLV_LENGTH_SCOPE_VALUE` (the default, and the only scope the C++ template
  supports) has the length count the value only, not the header:
  `encoded_length = value_size`.
- `TLV_LENGTH_SCOPE_TAG_AND_VALUE` has the length also count the tag:
  `encoded_length = tag_size + value_size`. Reading rejects an encoded length
  smaller than `identifier.size` with `TLV_ERR_INVALID_LENGTH`, since it leaves no
  room for the tag.
- Every tag byte value is valid. Values are opaque and read in place from the input.

```text
identifier.size = 2, length.size = 2, length.byte_order = TLV_BYTE_ORDER_LITTLE_ENDIAN
element_order = TLV_ELEMENT_ORDER_TLV, length_scope = TLV_LENGTH_SCOPE_VALUE

12 34 03 00 AA BB CC
Element (7 bytes)
|-- Tag:    12 34
|-- Length: 03 00 = 3 value bytes (little-endian)
`-- Value:  AA BB CC
```

```text
identifier.size = 1, length.size = 1, length.byte_order = TLV_BYTE_ORDER_BIG_ENDIAN
element_order = TLV_ELEMENT_ORDER_LTV, length_scope = TLV_LENGTH_SCOPE_TAG_AND_VALUE
(this is the Bluetooth LTV preset; see ../bluetooth/README.md)

03 09 48 69
Element (4 bytes)
|-- Length: 03 = 1 tag byte + 2 value bytes
|-- Tag:    09
`-- Value:  48 69
```

## Errors

| Situation | Result |
| --- | --- |
| `config` (C) is `NULL`, `identifier.size` is 0, `length.size` is 0 or greater than 8, or `element_order`/`length_scope` is not one of its enumerators | `TLV_ERR_INVALID_ARG` (init only) |
| `length.byte_order` (C) is neither big- nor little-endian | `TLV_ERR_INVALID_BYTE_ORDER` (init only) |
| Input has fewer bytes than the tag, length or value needs | `TLV_ERR_BUFFER_TOO_SHORT` |
| Output capacity is smaller than the element | `TLV_ERR_BUFFER_TOO_SHORT` |
| Written tag size differs from the configured tag width | `TLV_ERR_INVALID_TAG_SIZE` |
| Value longer than the largest length the length width can hold (minus `identifier.size` under `TLV_LENGTH_SCOPE_TAG_AND_VALUE`) | `TLV_ERR_INVALID_LENGTH` |
| Decoded length does not fit in `size_t` (for example an 8-byte length on a 32-bit target), or is smaller than `identifier.size` under `TLV_LENGTH_SCOPE_TAG_AND_VALUE` | `TLV_ERR_INVALID_LENGTH` |

## Example (C)

<!-- example: examples/tlv/src/formats/fixed_format.c -->
```c
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

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
    const tlv_fixed_format_t config = {.identifier = {2}, .length = {1, TLV_BYTE_ORDER_BIG_ENDIAN}};
    /* config must outlive every reader and writer built from it. */
    tlv_format_t format;
    CHECK(tlv_fixed_format_init(&format, &config));

    const uint8_t value[] = {0xAA, 0xBB, 0xCC};
    uint8_t       encoded[16];
    size_t        written = 0, consumed = 0;
    tlv_element_t element;

    CHECK(tlv_write(encoded, sizeof(encoded), &format, (TLV_TAG(0x12, 0x34)), value, sizeof(value),
                    &written));
    /* Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte. */
    CHECK(tlv_read(encoded, written, &format, &element, &consumed));

    return consumed == written && element.tag.size == 2 && element.value.size == sizeof(value) ? 0
                                                                                               : 1;
}
```

## Example (C++)

<!-- example: examples/tlv++/src/formats/fixed_format.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

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
    tlv::writer<format>       writer(buf.data(), buf.size());

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto                           written = writer.write<0x12, 0x34>(value);
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 00 AA BB CC. The tag is kept as is; only the length is little-endian.
    tlv::reader<format> reader(tlv::bytes(buf.data(), writer.size()));
    size_t              count = 0;
    try {
        for (auto element : reader) {
            if (element.value().size() != value.size()) return 1;
            std::cout << "wrote " << writer.size() << " bytes, read a " << element.value().size()
                      << "-byte value\n";
            ++count;
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << "read error: " << failure.what() << "\n";
        return 1;
    }
    return count == 1 ? 0 : 1;
}
```

## Example (C++, runtime-configurable)

Use the raw C `tlv_fixed_format_t`/`tlv_fixed_format_init()` directly when the
tag width, length width or byte order are not known at compile time — no
`tlv++` wrapper is needed, since `tlv::writer<>`/`tlv::reader<>` already accept a
plain `const tlv_format_t&`:

<!-- example: examples/tlv++/src/formats/fixed_format_runtime.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Defines a fixed-width TLV format at runtime from tlv++: two tag bytes and a
// one-byte length, using the raw C tlv_fixed_format_t/tlv_fixed_format_init
// through the explicit tlv::native interoperability boundary. See tlv/formats/fixed.h and
// docs/guides/memory.md#format-context-ownership-and-lifetime for why config
// must outlive every reader and writer built from it.
#include <array>
#include <iostream>

#include "tlv/formats/fixed.h"
#include "tlv++/tlv.hpp"
#include "tlv++/native.hpp"

int main() {
    const tlv_fixed_format_t config = {{/* tag_size */ 2},
                                       {/* length_size */ 1, TLV_BYTE_ORDER_BIG_ENDIAN},
                                       TLV_ELEMENT_ORDER_TLV,
                                       TLV_LENGTH_SCOPE_VALUE};
    /* config must outlive every reader and writer built from format. */
    tlv_format_t format;
    if (tlv_fixed_format_init(&format, &config) != TLV_OK) return 1;
    const auto format_view = tlv::native::borrow_format(format);

    std::array<tlv::byte, 16> buf{};
    tlv::writer<>             writer(buf.data(), buf.size(), format_view);

    const std::array<tlv::byte, 3> value = {tlv::byte(0xAA), tlv::byte(0xBB), tlv::byte(0xCC)};
    auto                           written =
        writer.write(tlv::tag_bytes<0x12, 0x34>(), tlv::bytes(value.data(), value.size()));
    if (!written) {
        std::cerr << "write error: " << written.error().message << "\n";
        return 1;
    }

    // Wire bytes: 12 34 03 AA BB CC. The tag is kept as is; the length is one byte.
    size_t count = 0;
    try {
        for (auto element : tlv::parse(tlv::bytes(buf.data(), writer.size()), format_view)) {
            if (element.value().size() != value.size()) return 1;
            std::cout << "wrote " << writer.size() << " bytes, read a " << element.value().size()
                      << "-byte value\n";
            ++count;
        }
    } catch (const tlv::parse_error& failure) {
        std::cerr << "read error: " << failure.what() << "\n";
        return 1;
    }
    return count == 1 ? 0 : 1;
}
```

See [shared memory ownership rules](../../guides/memory.md) before retaining a parsed element.
