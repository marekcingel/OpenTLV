# EMV Contact Book 3 profile

Include `tlv/profiles/emv.h` and link `tlv`. The supported set is explicitly
**EMV Contact Book 3 v4.4 (October 2022)**, exposed as `TLV_EMV_SPECIFICATION`.
It covers all tagged data elements in Annex A Tables 37/38, including the
context-specific biometric meanings and nested tags in Annex C Tables 48/51/52.
The dictionary contains 144 distinct wire tags. Contactless kernels, payment
system proprietary tag sets, and bulletins issued after this edition are outside
this profile. Book 3 data elements without a tag are not assigned invented tags.

The reference is [EMVCo Book 3 v4.4](https://www.emvco.com/specifications/book-3-application-specification-2/),
also available as a [public copy of the specification](https://www.scribd.com/document/648236969/EMV-v4-4-Book-3-Application-Specification-1).
Tag constants, schema entries, length steps, and codec bindings are maintained
together in [emv_tags.def](../../../tlv/include/tlv/profiles/emv_tags.def).

## Framing and lookup

Use `&tlv_reader_format_ber` with the reader, walker, or scanner, and
`&tlv_writer_format_ber` with the writer.
There is no separate EMV parser and the reader never interprets values.
All `tlv_emv_tag_*` constants use the universal `tlv_tag_t`.

`tlv_emv_schema` is the base dictionary, compatible with `tlv_schema_find()`
and `tlv_schema_validate_length()`. `tlv_emv_find(context, tag)` returns an
immutable definition containing its schema entry, symbolic name, value kind,
optional codec, and length step. Unknown tags and invalid contexts return NULL.

```c
#include "tlv/profiles/emv.h"
#include "tlv/reader/reader.h"

/* Inside a function; wire contains an Amount, Authorised (Numeric) TLV. */
tlv_view_t view;
size_t consumed;
if (tlv_read(wire, wire_size, &tlv_reader_format_ber, &view, &consumed) == TLV_OK) {
    const tlv_emv_definition_t* def =
        tlv_emv_find(TLV_EMV_CONTEXT_BASE, &view.tag);
    if (def && tlv_emv_validate_length(def, view.value.length) == TLV_OK &&
        def->value_kind == TLV_EMV_VALUE_NUMBER && def->codec) {
        uint64_t amount;
        tlv_codec_result_t result = tlv_codec_decode(
            def->codec, view.value.data, view.value.length,
            &amount, sizeof(amount));
        /* Check result before using amount. */
    }
}
```

For writing, explicitly encode the C value with `tlv_codec_encode()` into
caller-owned storage, then pass those bytes and the tag to `tlv_write()` or
`tlv_writer_write()` with `&tlv_reader_format_ber`. Every semantic codec supports
the generic encoding size query (`data == NULL`, `capacity == 0`).

## Contexts

A tag's meaning can depend on its enclosing template. For example, `81` means
a four-byte binary amount in ordinary application data but a biometric type
within a Biometric Header Template. Select the context explicitly, using
`tlv_emv_schema_for()` or `tlv_emv_find()`:

| Context (`TLV_EMV_CONTEXT_` prefix) | Value being traversed |
| --- | --- |
| BASE | Ordinary application data, including ordinary FCI/record templates |
| BIT | `7F60` |
| BHT | First-level `A1` inside `7F60` |
| BHT_FORMAT | Second-level `A1` or `A2` inside the BHT |
| BIT_GROUP | `BF4A`, `BF4B`, or the terminal BIT group |
| BIOMETRIC_COUNTERS | `BF4C` |
| BIOMETRIC_ATTEMPTS | `BF4D` |
| BIOMETRIC_VERIFICATION | `BF4E` |

Context lookup never falls back to BASE. Traverse nested value buffers using
generic BER I/O and carry the context in application code. The `9F31` Card BIT
Group Template contains nested objects despite its primitive BER tag bit;
`TLV_EMV_VALUE_TEMPLATE` records this semantic distinction. Matching algorithm
parameters and proprietary template contents do not acquire invented schemas.

## Value representations

`def->value_kind` determines the C representation required by `def->codec`.

| Kind (`TLV_EMV_VALUE_` prefix) | Representation and examples |
| --- | --- |
| NUMBER | `uint64_t`: BCD amounts/currency codes, binary ATC/counters/exponents |
| FLAGS | `uint64_t`: AIP, TVR, TSI, capabilities, CVM result bytes; all bits preserved |
| DIGITS | NUL-terminated `char[]`: PAN and compressed-numeric track discretionary data |
| DATE | `tlv_emv_date_t`: YY, month, day |
| TIME | `tlv_emv_time_t`: hour, minute, second |
| ACCOUNT | `tlv_emv_account_type_t`: default, savings, cheque/debit, credit |
| CRYPTOGRAM | `tlv_emv_cryptogram_info_t`: AAC/TC/ARQC/RFU enum and remaining six bits |
| BIOMETRIC | `tlv_emv_biometric_type_t`: facial, voice, finger, iris, palm |
| NUMBER_LIST | `tlv_emv_number_list_t`: up to four reference currencies or exponents |
| BYTES, TEXT, TEMPLATE | No codec; use the original borrowed value bytes |

Decode capacity is at least `sizeof(the C representation)` and encode size is
exactly that size. Representations may be unaligned; input and output buffers
must not overlap. For DIGITS, decode needs the digit count plus one for NUL;
encode size is the digit count excluding NUL. Leading zeroes are preserved,
trailing `F` padding is removed, and nondecimal or interspersed padding is rejected.
The PAN codec rejects empty/all-padding values and more than 19 digits.

BCD numbers enforce the declared digit count, including zero high nibbles for
odd-width fields such as currency codes and exponents. Variable-length numbers
are encoded in the shortest permitted width; use the original view when exact
wire preservation matters. Currency amounts are unscaled minor units.
`tlv_emv_codec_amount` is a convenient standalone n12/six-byte amount codec.
`TLV_EMV_AIP_*` masks can be used with the decoded AIP flags.

Dates validate month/day ranges and leap years within YY. No century is chosen;
the caller must resolve the century for year 00. Times reject hours above 23
and minutes/seconds above 59. Account and biometric enums reject undefined
values. Cryptogram RFU and all flag bits are retained. Transaction type, POS
entry mode, and terminal type remain numbers: their complete enum definitions
are outside Book 3. Text is not converted to UTF-8 or NUL-terminated storage;
its original encoding/padding is preserved. Opaque cryptographic data, DOLs,
track-2 composite data, and nested templates are not converted to scalars.

## Validation limits

Generic schemas check inclusive minimum/maximum lengths. Use
`tlv_emv_validate_length()` for additional steps, such as AFL multiples of four,
even CVM-list lengths, BIC lengths 8/11, and RSA exponent lengths 1/3. The
semantic codecs enforce these rules too. Generic scanning with a schema checks
only its minimum/maximum bounds; it does not invoke profile validation/codecs.

Variable fields without a universal maximum use `SIZE_MAX`; key-dependent
certificate/remainder lengths need the application's key and algorithm context.
Unspecified variable minima use zero. Fixed-size entries describe present values;
Book 3 treats zero-length objects as absent, which the application must handle
before validating a required value. These tables do not enforce APDU size,
required tags, duplicates, template membership, or full transaction validity.

Generic BER reading also accepts constructed indefinite lengths; the EMV
dictionary and length schemas do not enforce a definite-only encoding policy.
APDU status bytes and EMV
padding are handled by the caller. Book 3 defines one- and two-byte tags;
three-byte tags remain readable by generic BER but are unknown to this profile.
With `TLV_TAG_MAX_SIZE == 1`, two-byte constants and entries are omitted;
configure the macro consistently for the library and all consumers.

## Byte example

EMV adds dictionary entries, contextual schemas, and explicit value codecs;
it does not introduce a separate wire-format descriptor.

```text
9F 02 06 00 00 00 00 12 34
Element (9 bytes)
|-- Tag:    9F 02 (Amount, Authorised, Numeric)
|-- Length: 06 = 6 value bytes
`-- Value:  00 00 00 00 12 34
    `-- Explicit EMV numeric decoding: 1234 minor units
```

Read the framing with `tlv_reader_format_ber`, then explicitly decode the value
with `tlv_emv_codec_amount` into caller-owned storage. Currency and decimal scale
come from application context; the codec does not assign them. This one data
object does not represent a complete or validated transaction.
[EMV profile and codecs](README.md)

