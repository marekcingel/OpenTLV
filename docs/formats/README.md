# C library formats

Each page includes a byte example. Profile semantics are documented separately.
Concrete C implementations live under `tlv/builtins/<protocol>/` (grouped by
protocol) or, for protocol-agnostic mechanisms like the configurable fixed-width
format, `tlv/formats/`; see [architecture](../concepts/architecture.md#repository-layout).

Generic formats in `tlv/formats/` are part of the core and always available.
Built-ins in `tlv/builtins/<protocol>/` implement specific standards and are
optional. Both use the same Format, Reader and Writer contracts.

## Choose a format

### Generic core formats

| Need | Start with | Boundary |
| --- | --- | --- |
| Small internal records with fixed header sizes, or fixed tag/length widths chosen at runtime (C) or compile time (C++) | [Configurable fixed-width TLV](fixed/configurable.md) | Any tag width, length widths up to 8 bytes |
| Escaped variable identifiers and short/long length fields | [Configurable variable-width TLV](variable.md) | Generic framing; concrete validity and termination rules supplied separately |

### Built-in standards

| Need | Start with | Boundary |
| --- | --- | --- |
| DHCPv4 options with Pad and End | [DHCPv4 option framing](dhcp/README.md) | Individual options; caller handles termination and packet semantics |
| Bluetooth advertising data (length before type) | [Bluetooth LTV](bluetooth/README.md) | Values up to 254 bytes, no nesting |
| LLDP packed Type/Length headers | [LLDP TLV support](lldp/README.md) | Packed framing, base definitions, LLDPDU structural rules and value codecs |
| Multi-byte tags or constructed indefinite values | [BER-TLV](asn1/ber.md) | Payload semantics are separate |
| Canonical ASN.1 framing and nested checks | [DER](../profiles/der/README.md) | Structural validation, not full semantic DER |
| Canonical ASN.1 with indefinite-length framing and segmented strings | [CER](../profiles/cer/README.md) | Structural validation, not full semantic CER |
| EMV Contact Book 3 data objects | [BER plus EMV profile](../profiles/emv/README.md) | Dictionary/codecs, not a transaction engine |

For application-specific framing, use [custom callbacks](custom/README.md).
They are an extension mechanism, not a built-in standard or a supplied format.

## Compare formats

### Generic core formats

These reusable formats describe wire layouts without protocol policy. Fixed and
Variable are part of the core rather than optional standards packages.

| Format | Tag | Length field | Largest value | Field order on the wire | Nesting for the tree walker | Availability |
| --- | --- | --- | --- | --- | --- | --- |
| [Configurable fixed-width TLV](fixed/configurable.md#wire-layout) | 1 to 8 bytes | 1 to 8 bytes, big or little endian, counting the value alone or the tag and value | set by the length width | tag, length, value or length, tag, value | none (opaque values) | Always available (C and C++) |
| [Configurable variable-width TLV](variable.md) | inline or escaped continuation octets; configurable maximum width | short/long, big or little endian, counting value or tag and value | `tlv_size_t`, subject to configured count width and native buffer limits | tag, length, value or length, tag, value | supplied by concrete composition | Always available (C API) |

### Built-in standards

These formats implement a specific standard. Their packages may also provide
definitions, schemas, value codecs and container handling. Each format's page
explains its wire layout and supported scope.

| Format | Tag | Length field | Largest value | Field order on the wire | Nesting for the tree walker | Build option |
| --- | --- | --- | --- | --- | --- | --- |
| [DHCPv4 options](dhcp/README.md) | 1-byte code | 1 byte; absent for Pad/End | 255 bytes; 0 for Pad/End | code, length, value; code only for Pad/End | none | `OPENTLV_DHCP` |
| [Bluetooth LTV](bluetooth/README.md#wire-layout-and-logical-model) | 1-byte type | 1 byte, counting the type and the value | 254 bytes | length, type, value | none | `OPENTLV_BLUETOOTH` |
| [LLDP](lldp/README.md#wire-layout-and-logical-model) | 7-bit Type, canonical one-byte Tag | 9 bits, Value only | 511 bytes | packed Type/Length, Value | none | `OPENTLV_LLDP` |
| [BER-TLV](asn1/ber.md#layout-and-typical-use) | 1 to 8 bytes (multi-byte tags) | short, long, or indefinite for constructed values | up to `SIZE_MAX` | identifier, length, contents (and EOC) | `tlv_asn1_is_constructed` | `OPENTLV_FORMAT_BER` |
| [DER-TLV](asn1/der.md#layout-and-typical-use) | as BER | definite, shortest form only | definite lengths | identifier, length, contents | `tlv_asn1_is_constructed` | `OPENTLV_FORMAT_DER` |
| [CER-TLV](asn1/cer.md#layout-and-typical-use) | as BER | primitive: definite, shortest; constructed: indefinite | definite lengths for primitives | identifier, length, contents (and EOC) | `tlv_asn1_is_constructed` | `OPENTLV_FORMAT_CER` |

[Application-defined formats](custom/README.md) supply their own field layout,
limits and nesting predicate through the same generic callback contract.

Notes for choosing:

- Only BER, DER and CER carry a constructed bit, so only they nest by themselves.
  The other formats hold opaque values; nesting is then up to your predicate.
- DER and CER are BER with restrictions: they share the tag layout and differ in how
  lengths are chosen. Their generic readers check framing only; canonical values come from
  the profile functions.
- Bluetooth LTV is a preset of the configurable Fixed format that puts the length
  before the type and has the length count the type as well as the value; the
  Fixed format's `element_order` and `length_scope` make both properties
  available to any tag/length width, not just that one preset.
- Every format reads values in place and writes into caller-owned storage.
- To build only some of them, see [build only the components you need](../guides/select-components.md).

Formats that are not implemented yet are catalogued in
[format expansion candidates](format-roadmap.md).

All formats follow the [shared memory ownership rules](../guides/memory.md).

For canonical ASN.1 framing, nested validation, limits and error offsets, see
[ASN.1 DER-TLV](../profiles/der/README.md) and its sibling [ASN.1 CER-TLV](../profiles/cer/README.md).
`tlv_format_der` and `tlv_format_cer` also support the generic I/O below.

## Reading one element

Include `tlv/reader/reader.h` and call `tlv_read` to parse one element from the
beginning of a buffer:

```c
/* One tag byte and one length byte; config must outlive its readers. */
const tlv_fixed_format_t config = {
    .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
tlv_format_t format;
tlv_fixed_format_init(&format, &config);

tlv_element_t element;
size_t consumed;
tlv_result_t result = tlv_read(data, size, &format, &element, &consumed);
if (result == TLV_OK) {
    /* element.value borrows data; consumed also includes any framing trailer. */
}
```

Trailing bytes are ignored. The input must remain alive while using the element.
The reader allocates no memory, copies no value bytes, and does not decode
value semantics or validate a schema. Formats may inspect nested framing to
resolve an element boundary. Empty input (including NULL with size zero)
returns `TLV_ERR_END_OF_BUFFER`; missing tag, length, or value bytes return
`TLV_ERR_BUFFER_TOO_SHORT` with the supplied formats. Invalid arguments return
`TLV_ERR_NULL_ARG`. Both outputs are required and remain unchanged on failure.
Custom format callback errors propagate unchanged. The stateful
`tlv_reader_next` uses the same parser and advances by the consumed size.

## Walking multiple elements

Include `tlv/reader/walker.h` to visit concatenated elements with the generic reader:

```c
static tlv_visit_result_t count_element(const tlv_element_t* element, void* context) {
    size_t* count = (size_t*)context;
    (void)element;
    ++*count;
    return TLV_VISIT_CONTINUE;
}

/* Inside a function: format as constructed above. */
size_t count = 0;
tlv_result_t result = tlv_walk(data, size, &format, count_element, &count);
```

The visitor runs once per successfully parsed element, in buffer order.
Return `TLV_VISIT_CONTINUE` to advance, `TLV_VISIT_STOP` to finish successfully,
or `TLV_VISIT_ERROR` to return `TLV_ERR_VISITOR`. Unknown visitor results also
return `TLV_ERR_VISITOR`. Reader errors propagate unchanged. Stop and error
prevent parsing any further elements; earlier callback effects remain.

Empty input, including NULL with size zero, succeeds without calling the visitor.
The visitor and a format with both read callbacks are required even for empty
input; invalid arguments return `TLV_ERR_NULL_ARG`. The optional context may be
NULL. The element pointer lasts only for the callback; a copied element still borrows
the input value. Keep the input and format valid and unchanged during traversal.
The walker allocates no memory and never interprets or recurses into values,
even when they contain nested TLVs.

## Writing one element

Include `tlv/writer/writer.h`. Query the complete encoded size without providing value
bytes, then write into a caller-owned buffer:

```c
/* One tag byte and one length byte; config must outlive its writers. */
const tlv_fixed_format_t config = {
    .tag_size = 1, .length_size = 1, .length_order = TLV_BYTE_ORDER_BIG_ENDIAN};
tlv_format_t format;
tlv_fixed_format_init(&format, &config);

const tlv_tag_t tag = TLV_TAG(0x01);
const uint8_t value[] = {0xAA, 0xBB, 0xCC};
uint8_t buffer[5];
size_t required, written;
tlv_result_t result = tlv_encoded_size(tag, sizeof(value), &format, &required);
if (result == TLV_OK && required <= sizeof(buffer)) {
    result = tlv_write(buffer, sizeof(buffer), &format,
                       tag, value, sizeof(value), &written);
    /* On success: written == required; buffer contains 01 03 AA BB CC. */
}
```

Both APIs require `write_tag`, `write_length`, and `length_size`. The size query
validates the tag and length; a total that cannot fit in `size_t` returns
`TLV_ERR_INVALID_LENGTH`. Output size pointers are required and remain unchanged
on failure. Insufficient capacity returns `TLV_ERR_BUFFER_TOO_SHORT` before any
destination bytes are written. NULL output memory is valid only with zero
capacity, which reports insufficient capacity for an otherwise valid element.
An empty value may use NULL with length zero and still encodes tag and length.
Value bytes are copied verbatim without allocation or semantic interpretation.
The source value must not overlap the destination element. Callback errors
propagate and may leave partially encoded bytes. `tlv_writer_write` uses the
same encoder and advances its position only on success.

## Generic interface

`tlv_format_t` defines one canonical wire contract through `decode`, `measure`
and `encode`, plus an optional nesting predicate. Its context is borrowed,
caller-owned and immutable. Read-only descriptors provide `decode`; write-only
descriptors provide both `measure` and `encode`.

`tlv_format_decode()` produces `tlv_decoded_t`: a canonical identifier/value
`tlv_element_t` and separate `tlv_source_t` framing information. Header, Value
and Trailer partition the complete encoded range. Tag and Length field ranges
are optional. The core never assumes their order or interprets Length bytes.

`tlv_format_measure()` reports logical 64-bit Header, Value, Trailer and total
sizes. `tlv_format_encode()` regenerates framing from current semantic content.
A successful encoding must be accepted by the same format's decoder.
`tlv_encoded_size()` remains a convenience query for native-sized, content-
independent encodings; use `tlv_format_measure()` for logical sizes or formats
whose framing depends on value content.

Use `tlv_source_preserve()` for byte-identical reproduction. It compares the
current element with the immutable source content and rejects mutation instead
of silently reusing stale Length or Trailer bytes. Ordinary encoding does not
preserve BER nonminimal lengths or arbitrary header padding.

Field-based custom formats can compose `tlv_field_layout_t` from `tlv/layout.h`
and initialize a descriptor with `tlv_fields_format_init()`. Fixed TLV, Fixed
LTV and Bluetooth use the same public binary-field primitives. Formats with
other framing implement the same canonical operations directly.

See the [Format/Element contract](../concepts/format-contract.md) for lifetime,
mutation, preservation, diagnostics and size invariants.

## Nested traversal

Concrete descriptors are declared in
`tlv/formats/fixed.h`, `tlv/builtins/asn1/ber.h`,
`tlv/builtins/asn1/der.h`, and `tlv/builtins/asn1/cer.h`. The generic `format.h`
declares only the contract.

The optional `tlv_format_t::is_constructed` field identifies values containing
child TLVs in the same format. It receives the format's context and a parsed
tag. NULL means opaque values. The BER, DER and CER descriptors set it to
the shared `tlv_asn1_is_constructed`, which inspects the constructed bit; Fixed formats
leave it NULL.
Custom protocols can supply a different rule. Traversal follows the value element
and resumes at the complete encoded end, so BER EOCs are skipped correctly.

Use `tlv_walk_tree(data, size, format, max_depth, max_elements, visitor, context,
error_offset)` for bounded preorder traversal or NULL visitor for validation.
Depth is zero at the top level and cannot exceed `TLV_WALK_MAX_DEPTH` (64).
Limits are inclusive; zero is a real limit. Offsets identify failing elements.
STOP succeeds immediately without validating the remaining input. The original
flat reader and walker retain their behavior. See [architecture](../concepts/architecture.md).

See also the [C API reference: formats](../reference/c-api.md#formats).

### Formats whose length precedes the tag

Field order is part of the format configuration. `TLV_ELEMENT_ORDER_LTV`
uses the same binary-field primitives as `TLV_ELEMENT_ORDER_TLV`; neither
Reader nor Writer branches on a concrete format. Bluetooth counts Tag and
Value, while configurable Fixed can count Value alone or Tag and Value.
