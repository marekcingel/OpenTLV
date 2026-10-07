# C value codecs

Prerequisite: Understand Element and Value in [the basic model](../concepts/learning-model.md).

```text
Value bytes + selected Codec --> application value
```

`tlv/codec/codec.h` defines `tlv_codec_t`, an optional pair of decode and encode
callbacks with a borrowed, immutable context pointer. Codecs convert raw value
bytes and application-defined C representations. They do not receive tags,
formats, readers, or writers. Applications choose and invoke codecs explicitly;
reading an element never invokes one automatically.

For built-in Flags, Local Name and signed Tx Power conversions, see
[Bluetooth Advertising Data value codecs](../formats/bluetooth/README.md#basic-advertising-data-value-codecs).

Each codec documents the type and alignment of its representation. Decode takes
raw bytes plus a caller-owned destination object and its capacity in bytes.
Encode takes a C object and its size in bytes plus a caller-owned byte buffer.
No heap allocation or registration is required. A missing callback reports
`TLV_CODEC_ERR_UNSUPPORTED` for that direction.

For example, an application can define a zero-copy decoder:

```c
#include "tlv/codec/codec.h"

typedef struct { const uint8_t* data; size_t length; } byte_range_t;

static tlv_codec_result_t decode_bytes(const void* context,
    const uint8_t* data, size_t size, void* value, size_t capacity)
{
    byte_range_t* bytes = (byte_range_t*)value;
    (void)context;
    if (capacity < sizeof(*bytes)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    bytes->data = data;
    bytes->length = size;
    return TLV_CODEC_OK;
}

static const tlv_codec_t bytes_codec = {NULL, decode_bytes, NULL};
```

After a successful `tlv_read()`, convert the view's `tlv_size_t` value length with
`tlv_size_to_native()` (from `tlv/size.h`) before passing it to a codec, which takes a
native `size_t` size:

```c
size_t length;
byte_range_t bytes;
tlv_codec_result_t result;
if (tlv_size_to_native(view.value.size, &length) != TLV_OK) { /* value too large for this build */ }
result = tlv_codec_decode(&bytes_codec, view.value.data, length, &bytes, sizeof(bytes));
```

The resulting `bytes` borrows the original input. Keep that storage alive and
unmodified while using it. Other codecs can decode into scalars or structs,
including representations containing caller-provided buffers. Callers must
supply the documented type and alignment; the generic interface cannot check
C types. Callbacks must validate lengths and capacities before accessing storage.

For an application-defined encoder, query and encode explicitly:

```c
size_t required, written;
tlv_codec_result_t result = tlv_codec_encode(&my_codec,
    &value, sizeof(value), NULL, 0, &required);
if (result == TLV_CODEC_OK && required <= sizeof(raw)) {
    result = tlv_codec_encode(&my_codec, &value, sizeof(value),
        raw, sizeof(raw), &written);
    /* On success, pass raw and written to tlv_write(). */
}
```

An encode callback must support the `NULL, 0` destination query, validate the
object, and report its exact encoded size without writing. Decode consumes the
entire supplied value. Empty decode input may be `NULL, 0`; the representation
pointer is always required. Input and output must not overlap unless the codec
supports it. On failure destination contents are unspecified and encode's
`written` is zero. The descriptor, context, and buffers remain caller-owned.

`tlv_codec_result_t` and `tlv_codec_strerror()` report conversion errors
independently from parser/writer `tlv_result_t` errors. The existing C++ codec
trait and registry are separate APIs and are unchanged.

## C++11 typed fields and Value codecs

Include `<tlv++/codec/typed.hpp>` (also included by `<tlv++/tlv.hpp>`).
`field<Tag, T, Codec = codec<T>>` associates a canonical byte identifier with
a semantic C++ type and a tag-independent Value conversion. It does not add
a Definition registry, Schema, or protocol dependency.

```cpp
using Label = tlv::field<tlv::tag_constant<0x50>, std::string>;
using Counter = tlv::field<tlv::tag_constant<0x9F, 0x36>, uint16_t,
                           tlv::uint16_be_codec>;

auto label = document.get<Label>(); // expected<std::string, tlv::typed_error>
auto counter = element.decode<Counter>();
auto written = writer.write<Counter>(uint16_t{42});
// Check every result before accessing its value.
```

`tag_constant` lists identifier bytes in order, preserving leading zeros;
`tag_constant<>` represents an absent identifier. The destination Format decides
whether it can encode that identifier. Value endianness belongs to the explicitly
selected codec, independently of the Format's Length encoding.

`document.get<Field>()` selects the first matching top-level element.
`node.get<Field>()` selects the first matching direct child, without recursive
search. Duplicate tags retain first-match behavior. `node.decode<Field>()` and
`element.decode<Field>()` check the current tag before invoking the codec.
Scalar Node decoding rejects constructed Nodes, whose Value is represented by
children rather than a serialized byte view. Element decoding uses the Value
bytes supplied by the caller, including an explicitly selected structure codec.
These calls do not validate Schema, uniqueness, required fields or contextual
length limits.

`typed_error.kind` distinguishes missing fields, mismatched tags, invalid Node
handles, constructed Nodes, codec failures and Writer failures. Codec and Writer
failures retain their original `codec_code` and `framing_code`, respectively;
the other domain remains successful. Errors do not allocate.

Available adapters are `uint8_codec`, `uint16_be_codec`, `uint16_le_codec`,
`uint32_be_codec`, `uint32_le_codec`, and `int64_minimal_be_codec`. They delegate
to the C Value codecs. `tlv::native::codec_adapter<T, &descriptor>` (include `<tlv++/native.hpp>`) supports other C codecs
when `T` is exactly their documented, default-constructible C representation.
Do not use it to reinterpret an STL object as a C representation.

Defaults exist for `uint8_t`, `value_view` and `std::string`. Strings own the
exact bytes, including embedded NUL, without implicit UTF-8 validation.
`value_view` borrows input; Reader advancement, input changes, Document edits
and destruction retain their usual storage lifetime requirements. Multibyte
integers require an explicit codec. BCD and text validation likewise require
an explicit conversion with the desired policy.

Applications can specialize `tlv::codec<MyType>` or supply a separate codec as
the third field parameter. Both mechanisms use this C++11 contract:

```cpp
struct MyCodec {
    using value_type = MyType;
    static tlv::expected<MyType, tlv::codec_errc> decode(tlv::bytes input);
    static tlv::expected<size_t, tlv::codec_errc>
    encode(const MyType& value, tlv::byte* output, size_t capacity);
};
```

Decode consumes the entire Value and validates intrinsic representation rules.
Encode with `nullptr, 0` validates and reports the exact required byte count;
normal encode respects capacity and reports the same count. Codec operations
never receive a tag or perform a registry lookup. Field instantiation checks
the value type and return types. Owning/custom codec allocation exceptions
propagate rather than being converted to framing errors.

`writer.write<Field>(value)` uses stack storage for Values up to 64 bytes and a
temporary vector for larger Values. For caller-owned staging use:

```cpp
tlv::byte scratch[2];
auto result = writer.write<Counter>(uint16_t{42}, {scratch, sizeof(scratch)});
```

Scratch, input storage and Writer output must be disjoint. Insufficient scratch
fails before the Writer is invoked. Codec failures preserve the output cursor;
Writer failures also preserve it under the usual Writer contract, though bytes
past the cursor may change. Custom codecs may allocate even with caller-owned
scratch. The selected Format still generates all element framing.

The [compiled typed-field example](../../examples/tlv++/src/typed_fields.cpp)
uses C++11 with no optional protocol component and exercises Document lookup
when Document is enabled. The existing `is_tlv_codec`, `write_value()` and
runtime registry remain available with their original contracts.

## ASN.1 universal-type codecs

`tlv/builtins/asn1/asn1_codec.h` provides `tlv_codec_t` descriptors for the
ASN.1 primitive universal types (BOOLEAN, INTEGER, ENUMERATED, BIT STRING,
OCTET STRING, NULL, OBJECT IDENTIFIER and RELATIVE-OID), independent of any
BER-family format or standard. See
[BER-TLV: universal-type value codecs](../formats/asn1/ber.md#universal-type-value-codecs).

## Complete object mappings

Bindings belong to the codec layer. Include `tlv/codec/structure.h` for
`tlv_structure_codec_t`, which maps a complete TLV sequence to an application
object. Its callbacks receive the selected format explicitly and may use raw
reader/writer operations plus individual value codecs. The descriptor borrows
its context, format and optional `tlv_structure_schema_t`, and specifies depth
and element limits (zero is a real limit).

`tlv_structure_decode` validates the complete structure before invoking the
object mapper. `tlv_structure_encode` supports a NULL/0 size query and validates
produced bytes on an actual write. A query relies on the callback to validate
the object without generating bytes. Invalid framing/schema output returns
`TLV_CODEC_ERR_INVALID_STRUCTURE`. As with value codecs, destination contents
on failure are unspecified and failed encoding reports zero written bytes.
Object storage and encoded storage belong to the caller.

C++ `tlv::decode_structure<T>` and `tlv::encode_structure` in
`tlv++/codec/structure.hpp` adapt this descriptor without allocating temporary output.
T must match the descriptor's representation and be default constructible.
For a tested two-field mapping, see
[`architecture_test.cpp`](../../tests/integration/architecture_test.cpp) and
[`layers_test.cpp`](../../tests/integration/layers_test.cpp).

Existing tag-associated C++ codecs remain supported. Use
`tlv::write_value(writer, value)` from `tlv++/codec/codec.hpp` instead of the former
`writer.write(value)`. This explicit convenience helper may allocate a temporary
vector. Raw readers/writers now include only `tlv++/types.hpp` and the C I/O
contracts; they do not depend on codecs.

## Other languages

Python and Rust do not bind this generic callback model; each exposes its own,
narrower codec surface instead of a `tlv_codec_t`/`tlv_structure_codec_t`
equivalent. Python's `opentlv.codec` binds only the EMV amount codec (see
[Using OpenTLV from Python: Codec](python.md#codec)); Rust's `Codec`/`Value`
cover the full EMV dictionary but reimplement its decoding logic rather than
wrapping the C callbacks (see [Rust bindings: Codecs and the EMV
dictionary](../development/rust.md#codecs-and-the-emv-dictionary)). See the
[language bindings conceptual model](../concepts/bindings.md) for why the two
diverge from the C/C++ shape described above.

See also the [C API reference: codecs](../reference/c-api.md#codecs).

## Reusable primitive codecs

Include `tlv/codec/values.h` for `tlv_codec_uint8`,
`tlv_codec_uint16_be`, `tlv_codec_uint32_be`, their `_le` equivalents,
`tlv_codec_int64_minimal_be` and `tlv_codec_bytes`.
Include `tlv/codec/ipv4.h` for `tlv_codec_ipv4` and
`tlv_codec_ipv4_list`. They use the same Codec
contract and are available independently of protocol components.
Byte sequences decode to borrowed `tlv_value_t` views; IPv4 lists decode
to `tlv_ipv4_list_t` views with checked access through
`tlv_ipv4_list_at()`. The caller retains ownership of the input.

## Declarative numeric codecs

`tlv/codec/number.h` describes unsigned `uint64_t` conversion using ordinary
immutable data: binary BE/LE or unsigned BCD, representation width, and BCD
decimal precision. Width zero encodes the shortest representation and accepts
any supported input width. A nonzero width selects a fixed-width representation
with leading zero padding. Binary supports 1..8 bytes; BCD supports 1..9 bytes
and 1..18 decimal digits. Unused high decimal positions must be zero.

Field-length intervals, steps and alternatives belong to Schema. A codec cannot
choose a fixed output width from a validation rule it has not been given. The
caller/domain composes the two: choose the representation, encode, and validate
the resulting length. For variable-width fields, domain code can choose the
shortest schema-permitted width that fits. No codec performs tag lookup.

```c
#include "tlv/codec/number.h"

static const tlv_number_codec_config_t amount_config = {
    TLV_NUMBER_BCD, 6, 12
};
static const tlv_codec_t amount_codec = {
    &amount_config, tlv_number_decode, tlv_number_encode
};
```

Caller-owned configuration uses `tlv_number_codec(&config)` to create the same
borrowed descriptor. Keep the configuration alive and unchanged while it is in
use. No allocation, registration or protocol lookup occurs. Invalid configuration,
unrepresentable numbers and malformed digits are rejected, including during
encode size queries. The callback functions also support direct invocation and
leave output bytes unchanged on failure.

`tlv_codec_int64_minimal_be` converts minimal signed two's-complement values
without any ASN.1 dependency. It rejects redundant leading sign bytes and values
outside its eight-byte representation. Domain schemas still choose the codec
and impose any additional constraints.

## Digit strings and text

`tlv/codec/digits.h` packs decimal character strings high nibble first, with
trailing `F` padding. Leading zeros remain digits; this is distinct from numeric
BCD. Decode returns a NUL-terminated string; encode takes the digit count
**excluding** the NUL. Width zero selects the shortest encoding; nonzero width
selects fixed-width padding. Decode accepts trailing padding within that
representation. Field-length and digit-count constraints are applied separately
by Schema/domain validation.
Digits after padding and nibbles `A..E` are rejected.

```c
#include "tlv/codec/digits.h"

static const tlv_digits_codec_config_t identifier_config = {4};
static const tlv_codec_t identifier_codec = {
    &identifier_config, tlv_digits_decode, tlv_digits_encode
};
/* "00123" encodes as 00 12 3F FF; decoding preserves both leading zeros. */
```

`tlv/codec/text.h` converts explicitly selected ASCII text. Choose
`TLV_TEXT_ASCII_PRINTABLE` (space through `~`) or `TLV_TEXT_ASCII_ALNUM`
(letters and digits only). It does not infer the meaning of protocol labels
such as AN/ANS and is not a Unicode codec. Optional zero padding strips trailing
zero bytes on decode and pads to the selected fixed width on encode. Embedded
zeros, controls and bytes outside the selected alphabet are invalid.

```c
#include "tlv/codec/text.h"

static const tlv_text_codec_config_t label_config = {
    TLV_TEXT_ASCII_PRINTABLE, 16, 1
};
static const tlv_codec_t label_codec = {
    &label_config, tlv_text_decode, tlv_text_encode
};
```

The text C representation is `tlv_value_t`, not a C string. Decode returns an
unpadded borrowed span into the original wire bytes without adding a terminator;
encode takes the span object and `sizeof(tlv_value_t)`. Keep the wire storage
alive while using the view. An all-padding field represents empty text.

Both configurations can be caller-owned, using `tlv_digits_codec()` or
`tlv_text_codec()` to construct borrowed descriptors. Configurations must remain
alive and immutable. Size queries validate input, errors leave output unchanged,
and neither codec performs allocation, tag lookup or domain selection.

## Next step

Next: [schemas](schemas.md) for composition constraints and [format support](../formats/support.md) for standard modules.
