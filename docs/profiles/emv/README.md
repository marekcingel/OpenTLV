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
The existing `tlv_emv_tag_*` objects use the universal `tlv_tag_t`.
Each has a numeric integer constant expression with the `_u64` suffix,
such as `tlv_emv_tag_aip_u64` (`0x82`), usable in C and C++ `case` labels.
Both forms follow the configured tag capacity.

```c
/* Inside a function; tag points to a tlv_tag_t. */
uint64_t number;
if (tlv_tag_to_u64(tag, TLV_BYTE_ORDER_BIG_ENDIAN, &number) == TLV_OK) {
    switch (number) {
    case tlv_emv_tag_aip_u64:
        /* Handle AIP. */
        break;
    default:
        break;
    }
}
```

See [tag comparison and numeric conversion](../../core-types.md#tag-comparison-and-numeric-conversion)
for conversion limits and exact versus numeric equality.

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
| AFL | `tlv_emv_afl_t`: up to `TLV_EMV_AFL_MAX_ENTRIES` `tlv_emv_afl_entry_t` records (sfi, first/last record, offline-DA record count) |
| CVM_RESULT | `tlv_emv_cvm_result_t`: method, condition, and result bytes, preserved raw |
| TRACK2 | `tlv_emv_track2_t`: PAN, expiration year/month, service code, discretionary data |
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
`TLV_EMV_AIP_*` masks can be used with the decoded AIP flags; `TLV_EMV_TVR_*`,
`TLV_EMV_TSI_*`, `TLV_EMV_TERMINAL_CAPABILITIES_*`, and
`TLV_EMV_ADDITIONAL_TERMINAL_CAPABILITIES_*` mask the TVR (`95`), TSI (`9B`),
Terminal Capabilities (`9F33`), and Additional Terminal Capabilities (`9F40`)
FLAGS values the same way; `TLV_EMV_CVM_RESULT_*` names the well-known
`tlv_emv_cvm_result_t.result` byte values (unknown/failed/successful).

Dates validate month/day ranges and leap years within YY. No century is chosen;
the caller must resolve the century for year 00. Times reject hours above 23
and minutes/seconds above 59. Account and biometric enums reject undefined
values. Cryptogram RFU and all flag bits are retained. Transaction type, POS
entry mode, and terminal type remain numbers: their complete enum definitions
are outside Book 3. Text is not converted to UTF-8 or NUL-terminated storage;
its original encoding/padding is preserved. Opaque cryptographic data and
nested templates are not converted to scalars. The AFL (`94`) codec rejects
an sfi outside 1-30, a first_record of zero, a last_record below first_record,
and an offline_auth_record_count above the entry's record range. The Track 2
Equivalent Data (`57`) codec rejects a missing/misplaced field separator, a
PAN outside 1-19 digits, a non-decimal expiry/service-code/discretionary
digit, and an expiration_month outside 1-12, and handles the trailing
hex-F pad nibble used when the total digit count is odd. CVM Results (`9F34`)
stores its three bytes without further validation, like FLAGS.
`8C`/`8D`/`97`/`9F38`/`9F49` (CDOL1, CDOL2, TDOL, PDOL, DDOL) remain BYTES:
see [Data Object Lists](#data-object-lists-pdolcdolddol) for the dedicated
component that parses and constructs them.

## Diagnostics and tooling

`tlv_emv_value_kind_description(kind)` returns a short description of a value
kind's C representation and wire meaning (e.g. `"Bit flags"` for
`TLV_EMV_VALUE_FLAGS`), for logs or a dump tool. `tlv_emv_display_label(name)`
returns a curated human-readable label for a dictionary symbol (`def->name`),
such as `"Application File Locator (AFL)"` for `"afl"`, or `NULL` when none is
curated; `tlv_emv_titlecase_name(name, buffer, capacity)` then derives a
generic one (`"application_label"` -> `"Application Label"`) into caller-owned
storage, `TLV_ERR_BUFFER_TOO_SHORT` if `capacity` is less than
`strlen(name) + 1`. These back the `opentlv` CLI's `--profile emv` output.

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
With `TLV_TAG_CAPACITY == 1`, two-byte constants and entries are omitted;
configure the macro consistently for the library and all consumers.

## Data Object Lists (PDOL/CDOL/DDOL)

Include `tlv/profiles/dol.h`. A Data Object List is a sequence of tag/
requested-length pairs with no value bytes of its own; PDOL, CDOL1, CDOL2 and
DDOL all share this format (Book 3 section 5.4). Reading one with `tlv_read`
or `tlv_walk` would misinterpret the one-byte requested length as a BER
length field, so this is a dedicated value component rather than ordinary
TLV structure.

```c
#include "tlv/profiles/dol.h"

/* Inside a function; pdol holds a PDOL value's raw bytes. */
static tlv_result_t print_entry(const tlv_dol_entry_t* entry, size_t index, void* context) {
    (void)index;
    (void)context;
    /* entry->tag, entry->requested_length */
    return TLV_OK;
}
tlv_result_t rc = tlv_dol_read(pdol, pdol_size, NULL, print_entry, NULL, NULL);
```

Constructing the command data a DOL requests resolves each entry against
application data and applies Book 3 5.4's padding/truncation rules through a
`tlv_dol_resolve_fn` callback:

```c
static tlv_result_t resolve(const tlv_dol_entry_t* entry, size_t index, size_t skip,
                            uint8_t* data, size_t capacity, size_t* available_length,
                            tlv_dol_format_t* format, int* absent, void* context) {
    /* Look up entry->tag in application data; report *absent = 1 if unknown. */
    *absent = 0;
    *available_length = /* the value's own length */ 0;
    *format = TLV_DOL_FORMAT_BINARY; /* or TLV_DOL_FORMAT_NUMERIC for right-justified numeric data */
    if (data) {
        /* Write exactly capacity bytes of the value starting at offset skip. */
    }
    return TLV_OK;
}

/* Inside a function; pdol holds a PDOL value's raw bytes and command_data is
 * caller-owned storage at least as large as the size query below reports. */
size_t size;
tlv_result_t rc = tlv_dol_write(pdol, pdol_size, NULL, 0, NULL, NULL, NULL, &size, NULL);
/* rc == TLV_OK; allocate or otherwise obtain size bytes for command_data. */
rc = tlv_dol_write(pdol, pdol_size, command_data, size, NULL, resolve, NULL, &size, NULL);
```

`tlv_dol_write`'s output is always exactly the sum of the DOL's own requested
lengths, regardless of what `resolve` reports; a size query (`data == NULL`)
does not call `resolve` at all. An entry `resolve` reports unavailable is
filled with zero bytes. `TLV_DOL_FORMAT_BINARY` covers alphabetic,
alphanumeric, alphanumeric special, binary and compressed-numeric data:
short values are padded on the right and long values truncated from the
right. `TLV_DOL_FORMAT_NUMERIC` covers right-justified numeric data such as
BCD or binary amounts and counters: short values are padded on the left and
long values truncated from the left.

`tlv_dol_limits_t.max_entries` bounds how many entries `tlv_dol_read`/
`tlv_dol_write` visit; `tlv_dol_limits_t.max_value_length` bounds how long a
value `resolve` may report as available, and must not exceed the fixed
`TLV_DOL_MAX_VALUE_LENGTH` (255, matching the single-byte requested-length
field's own range). `tlv_dol_default_limits` selects generous defaults for
both. No allocation is used; tags follow the configured `TLV_TAG_CAPACITY`.

```text
9F 02 06 5A 08
|-- Entry 1: tag 9F 02 (Amount, Authorised), requested length 06
`-- Entry 2: tag 5A (PAN), requested length 08
```

No value bytes follow either length; the whole five bytes above is one
complete DOL with two entries.

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

## Example

[examples/emv/src/tag_decoding.c](../../../examples/emv/src/tag_decoding.c) walks
a whole record instead of one element: it looks up every child tag with
`tlv_emv_find()`, checks its length with `tlv_emv_validate_length()`, decodes it
according to `value_kind`, and leaves a tag that is unknown or has an invalid
length skipped rather than aborting the walk.
[EMV profile and codecs](README.md)
