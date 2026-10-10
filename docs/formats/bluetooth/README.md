# Bluetooth LTV

[Format documentation](../README.md)

Bluetooth advertising data, scan-response data and Generic Access Profile (GAP)
data are a sequence of **Length | Type | Value** structures. OpenTLV reads and
writes them through the same generic reader and writer as every other format;
only the format descriptor differs.

See the [field ordering and length scope contract](../../concepts/format-contract.md#field-ordering-and-length-scope)
for equivalent TLV/LTV examples, source ranges and explicit byte preservation.

## API and build

| Setting | Value |
| --- | --- |
| Format header | `tlv/builtins/bluetooth/bluetooth_ltv.h` |
| Descriptor | `tlv_format_bluetooth_ltv` |
| CMake option (default ON) | `OPENTLV_BLUETOOTH` |
| `otlv` format name | `bluetooth-ltv` |
| Link target | `tlv` |

`OPENTLV_BLUETOOTH` controls the entire Bluetooth extension: LTV format,
Advertising Data containers, definitions, schemas and codecs. Setting it to
`OFF` omits all Bluetooth implementations. Headers remain installed, as for
other optional components. This replaces `OPENTLV_FORMAT_BLUETOOTH_LTV`;
update existing CMake invocations and presets to use the new option.
The runtime feature query is `tlv_config_bluetooth()` from `tlv/config.h`;
it reports availability of the entire extension. The wire descriptor remains
`tlv_format_bluetooth_ltv` and the CLI format name remains `bluetooth-ltv`.

Bluetooth LTV is a preset of the [configurable Fixed format](../fixed/configurable.md):
`{{1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_LTV,
TLV_LENGTH_SCOPE_TAG_AND_VALUE}`. `tlv_format_bluetooth_ltv` exists so callers
do not have to spell that configuration out themselves; there is no
Bluetooth-specific parser or writer underneath it.

## Advertising Data Type definitions

Include `tlv/builtins/bluetooth/ad_types.h` to resolve AD type names with
`tlv_definition_find(&tlv_bluetooth_ad_types, &element.tag)`. The result is a
borrowed `const tlv_definition_t*`: `tag` preserves the one-byte identifier and
`name` provides its official Bluetooth SIG name. For `02 01 06`, lookup resolves
`01` to `Flags`; the value remains the borrowed byte `06`.

The initial registry covers `01` through `0A`, `16`, `20`, `21`, and `FF`, using
the [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/).
It is not exhaustive. Lookup returns `NULL` for an unlisted type such as `FE`;
that does not prevent the format from reading or writing the element.

The registry uses the generic `tlv_definition_t` and
`tlv_definition_registry_t` model from `tlv/definition.h`. Applications can
provide their own immutable tables and use the same lookup, which compares tag
size and bytes, returns the first match, and never allocates. Definition
metadata does not impose schema constraints or interpret values. The Bluetooth
registry requires `OPENTLV_BLUETOOTH=ON`; the generic Definition API is always available.

## Basic Advertising Data value codecs

Include `tlv/builtins/bluetooth/ad_codec.h` and call the generic
`tlv_codec_decode()` / `tlv_codec_encode()` functions on an element's value.
The codecs are allocation-free and require `OPENTLV_BLUETOOTH=ON`. They do not select or invoke a format,
schema or registry.

| AD type | Codec | C representation |
| --- | --- | --- |
| Flags (`01`) | `tlv_bluetooth_ad_codec_flags` | Borrowed `tlv_value_t` |
| Shortened / Complete Local Name (`08`, `09`) | `tlv_bluetooth_ad_codec_local_name` | Borrowed UTF-8 `tlv_value_t` |
| Tx Power Level (`0A`) | `tlv_bluetooth_ad_codec_tx_power` | `int8_t`, in dBm |

Flags preserve all bytes, including unknown bits and extension octets.
Use `tlv_bluetooth_ad_flags_test()` with `TLV_BLUETOOTH_AD_FLAG_LE_LIMITED_DISCOVERABLE`,
`TLV_BLUETOOTH_AD_FLAG_LE_GENERAL_DISCOVERABLE`,
`TLV_BLUETOOTH_AD_FLAG_BR_EDR_NOT_SUPPORTED` or
`TLV_BLUETOOTH_AD_FLAG_SIMULTANEOUS_LE_BR_EDR_CONTROLLER` to test defined bits.
Bit 4 is previously used; it has no current named meaning here. Empty Flags
mean all bits clear, while an absent Flags structure conveys no such value.
Trailing all-zero octets are rejected; omit them when encoding.

The Name codec accepts valid UTF-8 independently of field length. AD Schema
enforces the 0 through 248-byte field limit. They are byte spans, not
NUL-terminated C strings: embedded U+0000 is retained, and no terminator is
appended. Keep the AD Type to distinguish shortened and complete names.
Tx Power accepts exactly one octet in the range -127 through +127 dBm;
`FC` decodes to `-4`, while `80` (-128) is invalid.
These rules follow [Bluetooth CSS, Part A, sections 1.2, 1.3 and 1.5](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v14/out/en/core-supplementary-features/data-types-specification.html)
and the [GAP Device Name representation](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/generic-access-profile.html).

For the example `02 01 06 02 0A FC 07 09 53 65 6E 73 6F 72`, decode the three
values as Flags `06`, Tx Power `-4 dBm` and Complete Local Name `Sensor`.
After reading the Tx Power element, for example:

```c
#include "tlv/builtins/bluetooth/ad_codec.h"

/* element is the AD Type 0x0A element returned by the reader. */
size_t length;
int8_t dbm;
if (tlv_size_to_native(element.value.size, &length) == TLV_OK) {
    tlv_result_t result = tlv_codec_decode(
        &tlv_bluetooth_ad_codec_tx_power, element.value.data, length,
        &dbm, sizeof(dbm), NULL);
    /* On success dbm is -4; otherwise tlv_strerror(result) describes the error. */
    (void)result;
}
```

Decoding never changes `element.value`; even a rejected semantic value remains
available as raw bytes. Borrowed Flags and name results require the input to
remain alive and immutable. Encode takes the same C representation and supports
`NULL, 0` size queries; a `tlv_value_t` input must have a valid native size and
borrowed pointer. Accepted bytes round-trip exactly.

Malformed values (including invalid UTF-8, non-minimal Flags and invalid Tx
Power) report `TLV_ERR_INVALID_VALUE`. Missing pointers report
`TLV_ERR_NULL_ARG`, and insufficient output capacity reports
`TLV_ERR_BUFFER_TOO_SHORT`. `tlv_strerror()` provides readable
diagnostics; these are distinct from framing and schema errors. Applications
can retain the parsed tag and source offset alongside a codec error.

UUID lists, Service Data and Manufacturer Specific Data use the separate
codecs described below.

## Advertising Data schema

Include `tlv/builtins/bluetooth/ad_schema.h` and pass
`&tlv_bluetooth_ad_schema` to `tlv_schema_validate()` with
`&tlv_format_bluetooth_ltv`. The immutable schema requires `OPENTLV_BLUETOOTH=ON`; it has no dependency on codecs or the registry.

| AD types | Value-length constraint | Occurrences per AD block |
| --- | --- | --- |
| Flags (`01`) | Any, including empty | At most one |
| Shortened / Complete Local Name (`08`, `09`) | 0 through 248 bytes | At most one across both types |
| Tx Power (`0A`) | Exactly 1 byte | Unrestricted |
| Service UUID lists (`02`–`07`) | Multiple of 2, 4 or 16 bytes; empty allowed | At most one list per width, across complete and incomplete variants |
| Service Data (`16`, `20`, `21`) | At least 2, 4 or 16 bytes | Unrestricted |
| Manufacturer Specific Data (`FF`) | At least 2 bytes | Unrestricted |

These rules follow [Bluetooth CSS v12, Part A](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html),
Table 1.1 and sections 1.1–1.5 and 1.11. All fields are optional in this
context-free schema. Unknown types are accepted. Conditional requirements
based on connectability and relationships between separate AD/SRD blocks
require additional context and are not checked.

`02 0A FC` passes; `03 0A FC FD` parses successfully but fails schema
validation with `TLV_ERR_INVALID_LENGTH`. Likewise, `04 03 0F 18 00`
fails because three value bytes cannot form a 16-bit UUID list.
`tlv_schema_validate_all_diag()` report these
as length issues; the detailed diagnostic includes `length_multiple`.

This schema checks lengths and occurrences only. It does not check UTF-8,
flag-bit contents, numeric ranges, assigned UUIDs/company identifiers or
service/manufacturer payloads. The format still enforces the 254-byte value
limit. Pass only significant AD structures; use the container helper below
to validate padding and obtain the significant prefix first.

## Advertising Data containers and padding

Include `tlv/builtins/bluetooth/ad_data.h` and call
`tlv_bluetooth_ad_data_validate(data, size, &significant_size, &diagnostic)`
before processing a padded Advertising Data buffer. This helper is available
with `OPENTLV_BLUETOOTH=ON` and uses the generic reader with the
strict Bluetooth LTV format. It allocates nothing and leaves the input unchanged.

For `02 01 06 00 00 00`, validation succeeds with `significant_size = 3`.
Pass the original `data` pointer and that size to the generic reader, visitor
or schema validator. The remaining bytes are padding; source offsets still
refer to the original buffer. Subsequent parsing performs a second pass.

A zero byte starts padding only at a structure boundary, and every remaining
byte must be zero. Zeros inside declared values are preserved. Empty input
(including `NULL, 0`) and all-zero input succeed with a zero significant size.
Unknown AD types and empty values are accepted; schema and value-codec checks
remain separate.

A nonzero byte after padding starts returns `TLV_ERR_INVALID_VALUE`, with
`diagnostic.diagnostic.location` identifying the first offending INPUT byte. Truncated structures
retain the generic reader error and failing-field offset, even when their
available value bytes end in zeros. `significant_size` is required and remains
unchanged on failure. `diagnostic` is optional and unchanged on success; argument errors have
UNKNOWN location. Output storage must not overlap the input or each
other. Never strip trailing zeros by scanning backward: they may belong to
the final value.

<!-- markdownlint-disable-next-line MD033 -->
<a id="wire-layout-and-logical-model"></a>

## Wire representation and logical model

On the wire the length comes first:

```text
[Length][Type][Value]
   1 B    1 B   Length - 1 bytes
```

OpenTLV always presents an element as the logical triple **Type (tag), Length,
Value**, whatever the wire order. For Bluetooth LTV:

| Logical field | Where it comes from |
| --- | --- |
| Tag | The one-byte type, exposed as a tag of size 1 (`element.tag.data[0]`) |
| Length | The number of value bytes, which is the wire length byte minus 1 |
| Value | The bytes after the type, borrowed from the input (`element.value`) |

The wire order is a property of the format descriptor, not of the data model.
Nothing in OpenTLV requires a format to put the tag first, and Bluetooth LTV is
the built-in example of a format that does not.

## Length semantics

The Bluetooth length byte counts the **type byte plus the value bytes**. It does
not count itself. This differs from the length in conventional TLV, which counts
only the value.

| Wire length byte | Structure size | Value bytes |
| --- | --- | --- |
| `00` | rejected | none (see [malformed input](#malformed-input)) |
| `01` | 2 bytes | 0 |
| `03` | 4 bytes | 2 |
| `FF` | 256 bytes | 254 (the maximum) |

A structure is `length + 1` bytes and carries at most 254 value bytes. The
logical length reported by OpenTLV is the value length, so a wire length of `03`
is reported as a value of 2 bytes.

## Differences from conventional TLV

| | Conventional TLV (for example [Fixed](../fixed/configurable.md)) | Bluetooth LTV |
| --- | --- | --- |
| Wire order | Tag, length, value | Length, type, value |
| Length counts | Value bytes only | Type byte and value bytes |
| Tag size | Format specific, may be multi-byte | Always 1 byte |
| Maximum value | Format specific | 254 bytes |
| Zero length | Empty value | Invalid |
| Constructed types | Depends on the format | None |
| Canonical operations | `decode`, `measure`, `encode` | `decode`, `measure`, `encode` |

## Parsing

Select the format by passing `tlv_format_bluetooth_ltv` to
`tlv_reader_init`, then call `tlv_reader_next` until it stops returning
`TLV_OK`. Each `tlv_element_t` gives the type in `element.tag` and the value in
`element.value`.

```c
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#include "tlv/size.h"
#include "tlv/reader/reader.h"

#include <stdio.h>

int main(void) {
    /* Flags (01) = 06, then Complete Local Name (09) = "Hi". */
    const uint8_t advertising[] = {0x02, 0x01, 0x06, 0x03, 0x09, 'H', 'i'};
    tlv_reader_t reader;
    tlv_element_t element;
    tlv_result_t rc;

    if (tlv_reader_init(&reader, advertising, sizeof(advertising),
                        &tlv_format_bluetooth_ltv) != TLV_OK)
        return 1;

    while ((rc = tlv_reader_next(&reader, &element)) == TLV_OK) {
        size_t length;
        if (tlv_size_to_native(element.value.size, &length) != TLV_OK) return 1;
        printf("type 0x%02X, %u value byte(s)\n", (unsigned)element.tag.data[0],
               (unsigned)length);
        /* element.value.data[0 .. length) holds the value. */
    }
    /* rc is not TLV_OK here; at_end distinguishes a clean finish from an error. */
    return tlv_reader_at_end(&reader) ? 0 : 1;
}
```

This prints:

```text
type 0x01, 1 value byte(s)
type 0x09, 2 value byte(s)
```

The value is not interpreted. Decoding it (flags bits, UTF-8 names, UUID lists,
manufacturer data) is up to the caller, keyed on the type. The views borrow the
input buffer; see the [shared memory ownership rules](../../guides/memory.md)
before retaining one.

The reader is also usable through the visitor, schemas and the `otlv`
CLI:

```text
$ otlv dump --format bluetooth-ltv --hex "02 01 06 03 09 48 69"
offset=0 tag=01 length=1 value=06
offset=3 tag=09 length=2 value=4869
```

## UUID values and lists

Include `tlv/builtins/bluetooth/uuid.h` for reusable value codecs. UUID16/32
names are source aliases of `tlv_codec_uint16_le` / `tlv_codec_uint32_le`. They interpret
Bluetooth little-endian byte order independently of the AD Type and format.

| UUID width | Value codec | C representation | List codec | AD Types |
| --- | --- | --- | --- | --- |
| 16 bits | `tlv_bluetooth_codec_uuid16` | `uint16_t` | `tlv_bluetooth_codec_uuid16_list` | `0x02`, `0x03` |
| 32 bits | `tlv_bluetooth_codec_uuid32` | `uint32_t` | `tlv_bluetooth_codec_uuid32_list` | `0x04`, `0x05` |
| 128 bits | `tlv_bluetooth_codec_uuid128` | `tlv_bluetooth_uuid128_t` | `tlv_bluetooth_codec_uuid128_list` | `0x06`, `0x07` |

The 128-bit representation contains 16 bytes in canonical printed UUID order
(most significant byte first). Its codec reverses the entire wire sequence;
it does not use the mixed-endian layout of a Windows GUID. Value codecs consume
exactly one UUID and can also decode a UUID prefix isolated from Service Data.
They do not validate assigned numbers or expand short UUIDs to the Bluetooth base UUID.

List codecs return `tlv_bluetooth_uuid_list_t`, borrowing the complete raw value
without allocation. Length must be a multiple of 2, 4 or 16 respectively; empty
lists are accepted. Keep the source alive and immutable while using the view.
The AD Type retains the complete/incomplete distinction; codec selection is
the caller's responsibility.

For `05 03 0F 18 0A 18`, the reader returns AD Type `0x03` and raw value
`0F 18 0A 18`. Decode and iterate that value as follows:

```c
#include <tlv/builtins/bluetooth/uuid.h>

int decode_service_uuids(void) {
    const uint8_t raw[] = {0x0F, 0x18, 0x0A, 0x18};
    tlv_bluetooth_uuid_list_t list;
    size_t count;
    if (tlv_codec_decode(&tlv_bluetooth_codec_uuid16_list, raw, sizeof(raw),
                         &list, sizeof(list), NULL) != TLV_OK) return 1;
    if (tlv_size_to_native(list.raw.size / list.uuid_size, &count) != TLV_OK) return 1;
    for (size_t i = 0; i < count; ++i) {
        uint16_t uuid;
        if (tlv_bluetooth_uuid_list_at(&list, i, &uuid, sizeof(uuid)) != TLV_OK)
            return 1;
        /* uuid is 0x180F, then 0x180A. list.raw still points to raw. */
    }
    return 0;
}
```

Encoding a list validates the view and copies its original wire bytes exactly.
To create new list bytes, encode individual UUID values into caller-owned storage.
All these codecs require `OPENTLV_BLUETOOTH=ON`.
Byte-order interpretation stays in Codec; Element continues to expose opaque bytes.

## Service Data

Include `tlv/builtins/bluetooth/service_data.h` to decode a service UUID prefix
and an opaque service-specific payload.

| AD Type | Codec | C representation |
| --- | --- | --- |
| `0x16` | `tlv_bluetooth_codec_service_data16` | `tlv_bluetooth_service_data16_t` |
| `0x20` | `tlv_bluetooth_codec_service_data32` | `tlv_bluetooth_service_data32_t` |
| `0x21` | `tlv_bluetooth_codec_service_data128` | `tlv_bluetooth_service_data128_t` |

Each representation exposes `uuid`, a borrowed `payload` span and the complete
borrowed `raw` value. The UUID uses the same representation and byte order as
the UUID value codecs above. Keep the source storage alive and immutable while
using either span. A missing or incomplete UUID is rejected; an empty payload
is valid.

For `05 16 0F 18 64 01`, the reader returns AD Type `0x16` and value
`0F 18 64 01`. Its Service Data codec exposes UUID `0x180F`, payload
`64 01` and raw value `0F 18 64 01`. It does not interpret those payload
bytes as Battery Service fields.

Encoding uses `uuid` and `payload`, regenerating the UUID prefix through the
UUID codec and copying the payload unchanged. The informational `raw` span
is ignored, so caller-constructed objects can leave it empty. Both directions
are allocation-free. These codecs require `OPENTLV_BLUETOOTH=ON` and do not
impose the AD framing size limit.

## Manufacturer Specific Data and Company Identifiers

Include `tlv/builtins/bluetooth/manufacturer_data.h` and use
`tlv_bluetooth_codec_manufacturer_data` for AD Type `0xFF`.
Its `tlv_bluetooth_manufacturer_data_t` representation contains:

- `company_id`: the numeric 16-bit Company Identifier, decoded little-endian;
- `payload`: a borrowed span after the two identifier bytes;
- `raw`: the complete borrowed value, including the identifier.

For `1A FF 4C 00 02 15 ...`, the codec exposes `company_id == 0x004C`
and payload `02 15 ...`. It does not interpret the payload as iBeacon or
any other vendor protocol. Such interpretation belongs in optional extensions.
Keep source storage alive and immutable while using either span. Values shorter
than two bytes are rejected; an empty payload and unknown identifiers are valid.
Encoding uses `company_id` and `payload`, ignores `raw`, and regenerates the
little-endian prefix. Both directions are allocation-free and available with
`OPENTLV_BLUETOOTH=ON`, without an AD framing size limit.

The independent `tlv/builtins/bluetooth/company_ids.h` header exposes
`tlv_bluetooth_company_ids`, a Definition registry for `tlv_definition_find()`.
Its keys are the two identifier octets, least-significant octet first: Apple's
key is `{0x4C, 0x00}`. A decoded value's first two `raw` bytes can be used
directly as a `tlv_tag_t` key. For a numeric identifier, explicitly construct
the two bytes; do not reinterpret its native memory representation.
The registry performs byte comparison only and has no dependency on the codec,
schema or format. A missing definition returns `NULL` and does not invalidate
the Company Identifier.

Initial coverage is `0x0000` (Ericsson), `0x0006` (Microsoft), `0x004C` (Apple),
`0x0059` (Nordic Semiconductor), `0x0075` (Samsung) and `0x00E0` (Google).
This is a non-exhaustive snapshot of the
[Bluetooth SIG Assigned Numbers HTML table](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/index-en.html)
(Company Identifiers table dated 2023-12-21). It is descriptive metadata,
not an automatically updated list or a vendor payload dispatcher.
The value structure follows
[Core Specification Supplement, Part A, section 1.4](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html).

## Encoding

Writing uses `tlv_format_bluetooth_ltv` with the same `tlv_write` and
`tlv_writer_write` calls as any other format. The writer emits the length byte
(`value length + 1`) followed by the type byte and the value.

| Condition | Result |
| --- | --- |
| Tag size is not 1 | `TLV_ERR_INVALID_TAG_SIZE` |
| Value longer than 254 bytes | `TLV_ERR_INVALID_LENGTH` |
| Output buffer too small | `TLV_ERR_BUFFER_TOO_SHORT` |

## Unknown types

The format never inspects the type value, so every type is structurally valid.
An unknown or vendor-specific type is returned like any other, and the reader
moves to the next structure using the length alone. Callers decide which types
they handle and ignore the rest.

## Malformed input

| Input | Result |
| --- | --- |
| No input left | `TLV_END`; `tlv_reader_at_end` reports a clean finish |
| Length byte `00` | `TLV_ERR_INVALID_LENGTH`: there is no type byte |
| Length larger than the remaining bytes | `TLV_ERR_TRUNCATED` |

A length byte of zero has no type byte to report. In Bluetooth data it also
starts the non-significant zero padding that may follow the last structure, so
a buffer with trailing zero padding stops with `TLV_ERR_INVALID_LENGTH` after the
last real structure. For padded buffers, use
`tlv_bluetooth_ad_data_validate()` to validate the container and obtain the
significant prefix before parsing it. Do not treat arbitrary parsing errors
as successful termination.

On error the reader position does not advance, so a truncated structure is
never returned partially.

## Limitations

- The type is exposed as a one-byte tag and the value is opaque; the AD Type
  registry and schema do not decode values.
- Values are limited to 254 bytes, and the tag is always one byte.
- There are no constructed types; nesting is left to the caller.
- Framing and optional schema validation do not implement a Bluetooth stack.

## Byte example

```text
03 09 48 69
Element (4 bytes)
|-- Length: 03 = type byte + 2 value bytes
|-- Type:   09 (Complete Local Name), exposed as the tag
`-- Value:  48 69 ("Hi")
```

## How it fits the format architecture

Bluetooth is a configuration of the public binary-field composition primitives
in `tlv/formats/compose.h`: one-byte Tag and Length, Length before Tag, Length
counting Tag and Value. It has no dependency on Fixed-private code or the Fixed build option.
Both formats expose the same canonical decode/measure/encode contract.

See [Format/Element contract](../../concepts/format-contract.md).
