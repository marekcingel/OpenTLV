# C++ built-in standards

The [current facade overview](cxx-native-boundary.md#public-facade) explains
generic consumers and interoperability; the
[implemented support inventory](../formats/support.md) separates framing,
definitions, Schema, Codec, validation, CLI and binding presets.

Generic C++ primitives remain directly under `tlv`: `reader`, `writer`,
`element_view`, `field`, `codec`, `document` and `query`. Public namespaces
describe standards and protocols, independently of header directory structure.
For example, `builtins/asn1/ber.hpp` exposes `tlv::ber::format`, without adding
`tlv::builtins` or nesting BER inside an ASN.1 namespace.

## Framing entry points

Every supported framing domain provides `format`, `parse(data)` and
`encode(output, callback)`, plus an encoding overload accepting an explicit
`writer_workspace` before the callback:

| Domain | Framing | CMake option | Header under `tlv++/builtins/` |
| --- | --- | --- | --- |
| `tlv::ber` | BER | `OPENTLV_FORMAT_BER` | `asn1/ber.hpp` |
| `tlv::der` | DER | `OPENTLV_FORMAT_DER` | `asn1/der.hpp` |
| `tlv::cer` | CER | `OPENTLV_FORMAT_CER` | `asn1/cer.hpp` |
| `tlv::emv` | EMV Contact Book 3 | `OPENTLV_EMV` | `emv/format.hpp` |
| `tlv::bluetooth` | Bluetooth Advertising Data LTV | `OPENTLV_BLUETOOTH` | `bluetooth/ltv.hpp` |
| `tlv::lldp` | LLDP information strings | `OPENTLV_LLDP` | `lldp/lldp.hpp` |
| `tlv::dhcp` | DHCPv4 options | `OPENTLV_DHCP` | `dhcp/dhcpv4.hpp` |
| `tlv::nfc` | NFC Type 2 data-area TLV | `OPENTLV_NFC` | `nfc/type2.hpp` |

These are conveniences over the same [generic Format contracts](cxx-formats.md)
available to user-defined Formats. For example:

```cpp
#include <tlv++/builtins/asn1/ber.hpp>

void inspect(tlv::bytes data) {
    for (auto element : tlv::ber::parse(data)) {
        auto value = element.value().as_bytes();
        (void)value;
    }

    tlv::reader<tlv::ber::format> reader(data);
    (void)reader;
}
```

`tlv::ber(data)` cannot coexist with the namespace `tlv::ber`; use
`tlv::ber::parse(data)`. Parsing is a borrowed, single-pass final-input range.
Input must outlive the range and retained Elements. Iteration raises
`parse_error` on a failure rather than treating it as end-of-input.

```cpp
#include <tlv++/builtins/asn1/der.hpp>

auto encode_answer(tlv::span<tlv::byte> output)
    -> tlv::expected<size_t, tlv::writer_failure> {
    return tlv::der::encode<32, 2>(output, [](tlv::writer_builder& writer) {
        const uint8_t content[] = {42};
        writer.write<0x02>(content);
    });
}
```

The bounded-workspace overload defaults to 1024 scratch bytes and
`TLV_TREE_DEFAULT_DEPTH` frames. `encode<32, 2>` selects 32 scratch bytes and
two frames; storage never grows automatically. The explicit-workspace overload
preserves caller-selected depth and element limits. Both propagate the generic
Writer's result, diagnostics and callback exception behavior. See
[Writer and scoped construction](../guides/writer.md).

Framing entry points do not add Schema, Value or container validation.
`tlv::dhcp::options_validate()` validates the options container separately;
`tlv::ber::write_indefinite()` wraps an encoded child sequence in explicit
indefinite framing. Existing flat native descriptor getters and low-level
helper names remain source-compatible.

`tlv::ber::indefinite_format` is the generic preset for explicit constructed
indefinite encoding. It rejects primitive writes. To measure a wrapped child
sequence, pass this preset and its semantic Element to `tlv::measure`; the
encoding helpers report insufficient capacity for an empty output buffer.

## Value codecs and fields

Include the domain's `codec.hpp` separately, or use `<tlv++/tlv.hpp>` to
aggregate all enabled domains. Framing headers do not require their codec
headers. All codecs support the generic `tlv::field` contract: `value_type`,
`decode(bytes)` and `encode(value, output, capacity)`. Passing `nullptr, 0`
to `encode` validates and measures the Value. Storage must not overlap input.
The original C codec errors and semantic restrictions are preserved.

| Namespace | Codec header under `tlv++/builtins/` | Coverage |
| --- | --- | --- |
| `tlv::asn1` | `asn1/codec.hpp` | All existing ASN.1 Value codecs and their primitive universal fields |
| `tlv::bluetooth` | `bluetooth/codec.hpp` | Flags, local name, Tx Power, UUID16/32/128, UUID lists, Service Data and Manufacturer Data |
| `tlv::lldp` | `lldp/codec.hpp` | Chassis/Port ID, TTL, text, capabilities, management address and organisation |
| `tlv::dhcp` | `dhcp/codec.hpp` | Message Type byte codec and option field |
| `tlv::emv` | `emv/codec.hpp` | Amount and every existing codec-bearing entry in the explicit builtin dictionaries |

NFC Type 2 currently defines framing, without a Value codec. Opaque NDEF bytes
remain opaque. Standard aliases of generic codecs reuse the generic C++ codec:
DHCP Message Type is `uint8_codec`, LLDP TTL is `uint16_be_codec`, and Bluetooth
UUID16/32 use little-endian integer codecs. Generic codecs stay under `tlv`.

ASN.1 codecs live once under `tlv::asn1`, with no repeated aliases under
BER, DER or CER. These formats share Value semantics while having separate
framing contracts. ASN.1 codecs enforce the existing canonical content rules
even on BER input: BOOLEAN accepts only `00` or `FF`, and INTEGER/ENUMERATED
require minimal signed encoding fitting `int64_t`. Larger integer content
can still be read as borrowed raw Value bytes. Primitive universal fields do
not assemble constructed or fragmented strings.

```cpp
#include <tlv++/builtins/asn1/der.hpp>
#include <tlv++/builtins/asn1/codec.hpp>

void decode_integers(tlv::bytes data) {
    for (auto element : tlv::der::parse(data)) {
        auto value = element.decode<tlv::asn1::integer_field>();
        if (value) {
            int64_t integer = *value;
            (void)integer;
        }
    }
}
```

Borrowed strings use `value_view`; ASN.1 BMP/UniversalString views count bytes,
including their two/four-byte wire units. BIT STRING, fractional time digits,
IRI labels, Bluetooth payloads/UUID lists and LLDP variable fields retain input
storage. Self-contained dates, numeric OID arcs, capability bitmaps and UUID128
are returned by value. Successful fixed-size and borrowed codec operations
allocate nothing. ASN.1 OID/IRI arc limits remain those of the C representations.

EMV numeric codecs use exact `uint64_t` values. `pan_codec` and other decimal
digit codecs return an owning `std::string`, may allocate while decoding,
and preserve leading zeroes. Codec names end in `_codec`, and corresponding
field names end in `_field`, such as `pan_field`,
`transaction_currency_code_field` and `transaction_date_field`.
Context-specific names carry a prefix such as `bht_biometric_type_field`;
they select that dictionary without falling back to the base context.
The selected descriptor is fixed independently of the input Element tag;
`element.decode<Field>()` performs the generic tag check before decoding.
Existing EMV dictionary codec constraints remain in force. Entries without a
codec do not acquire an invented semantic representation.

```cpp
#include <tlv++/builtins/emv/format.hpp>
#include <tlv++/builtins/emv/codec.hpp>

void write_pan(tlv::span<tlv::byte> output, const std::string& digits) {
    tlv::writer<tlv::emv::format> writer(output);
    tlv::byte scratch[10]{};
    auto result = writer.write<tlv::emv::pan_field>(digits, {scratch, sizeof(scratch)});
    (void)result;
}
```

Field aliases compose identifier, value type and codec; they are not registries
or Schemas. Structural occurrence, order and contextual constraints retain
their existing owners. Defining another field or selecting a codec for a custom
Format uses exactly the same generic APIs.
