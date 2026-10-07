# Configurable variable-width TLV

`tlv/field/variable.h` provides allocation-free identifier and length primitives.
`tlv/formats/variable.h` provides the definite-length format and adapters composed
from them. Both are always available, even when all builtins are disabled, and
do not require a runtime `.otlv` engine. They describe wire mechanics, not a
protocol or an ASN.1 encoding rule.

## Identifier encoding

`tlv_variable_identifier_t` selects inline bits in the first octet and an escape
pattern. An escaped identifier has one or more additional octets, each containing
configured payload bits and one continuation bit. A clear continuation bit ends
the identifier. The configuration also bounds its complete byte width.

The complete identifier is borrowed as raw bytes. Bits outside the inline mask
in the first octet are preserved without interpretation. Additional octets may
only contain the configured payload and continuation bits. Zero payloads,
nonminimal encodings and identifiers wider than an integer are supported
without a policy. Optional `tlv_identifier_policy_t` constrains forbidden leading
bytes, the first escaped payload and minimal number encoding. Protocol-specific
type semantics remain in concrete standards.

`tlv_variable_identifier_read()` returns the borrowed identifier and consumed
width. `tlv_variable_identifier_write()` validates a complete identifier and
copies its bytes unchanged; NULL output with zero capacity measures it.

## Length encoding

`tlv_variable_length_t` describes a prefix with a long-form bit and a payload
mask. With the long-form bit clear, the payload is the count. With the bit set,
the payload is the number of following count octets, in explicitly configured
big or little endian order. Payload mask bits are packed from least to most
significant, so the selector need not occupy the high bit.

Without a policy, `tlv_variable_length_read()` accepts nonminimal and zero-padded encodings if the
count fits `tlv_size_t`. It checks the complete field is available before checking
numeric overflow. On wire errors, `consumed` reports the available field prefix
for diagnostics; the count output remains unchanged. A zero long-form width is
not a definite length and returns `TLV_ERR_INVALID_LENGTH`. There are no
standard-specific reserved prefixes.

`tlv_variable_length_write()` chooses short form when possible and otherwise the
fewest full count octets. NULL output with zero capacity measures the field.
The prefix must be able to represent the required octet count. Arithmetic
overflow during decoding returns `TLV_ERR_OVERFLOW`; buffer truncation is
reported separately. Native buffer sizes remain subject to the shared
[Format contract](../concepts/format-contract.md).

## Complete format

`tlv_variable_format_init()` borrows a `const tlv_variable_format_t` configuration
and initializes an ordinary `tlv_format_t` for Reader, Writer and other consumers.
The configuration must outlive the descriptor and its users. It may live in
static storage or caller-owned runtime storage; it must remain unchanged during
use. Copying the descriptor does not create another configuration or ownership.

For example, this deliberately non-ASN.1 configuration uses identifier bits 4–6,
escape pattern `0x20`, continuation bit 0, and payload bits 4–7:

```c
#include "tlv/formats/variable.h"

static const tlv_variable_format_t config = {
    {0x70, 0x20, 0x01, 0xF0, 8, NULL},
    {0x80, 0x7F, TLV_BYTE_ORDER_LITTLE_ENDIAN, NULL},
    TLV_ELEMENT_ORDER_TLV,
    TLV_LENGTH_SCOPE_VALUE,
    NULL
};

/* In the caller: */
tlv_format_t format;
tlv_result_t result = tlv_variable_format_init(&format, &config);
```

Under that configuration, `A5 B1 C0 02 AA BB` represents identifier `A5 B1 C0`,
length 2 and value `AA BB`. The identifier's first octet selects escape; `B1`
continues and `C0` ends the identifier.

The format also supports LTV ordering and lengths counting both Tag and Value.
The latter uses the actual variable identifier width. Decoding publishes borrowed
Tag/Value and normal Header/Tag/Length/Value/Trailer source ranges. Ordinary
encoding regenerates the length field; use `tlv_source_preserve()` to reproduce
an unchanged source's nonminimal length bytes exactly.

## Declarative policies

The [policy design note](../concepts/field-policies.md) defines the generic and
protocol-owned boundaries, storage lifetimes and error precedence. Set the
identifier and length `policy` pointers to immutable caller-owned constraints;
NULL keeps the unconstrained wire primitives. Length policies select allowed
short/long forms, maximum long-form octets, maximum count and minimal encoding.
Indefinite lengths remain outside the definite primitive.

Set the Format's `constructed` pointer to a `tlv_constructed_bit_t` to classify
canonical Tag bytes by `(tag[byte_index] & mask) == value`. The mask must be
nonzero and value may contain only masked bits. A missing byte never matches.
The generic Format callbacks are public, so a static descriptor can use
`tlv_variable_decode`, `tlv_variable_measure`, `tlv_variable_encode` and
`tlv_variable_is_constructed` with the same configuration as its context.

For example, an EMV-like proprietary format can allow three-byte identifiers,
definite lengths through 65535, and minimal length encoding without adapters:

```c
static const uint8_t forbidden[] = {0};
static const tlv_identifier_policy_t tag_policy = {forbidden, 1, 1, 0};
static const tlv_length_policy_t length_policy = {1, 1, 1, 2, 65535};
static const tlv_constructed_bit_t constructed = {0, 0x20, 0x20};
static const tlv_variable_format_t constrained = {
    {0x1F, 0x1F, 0x80, 0x7F, 3, &tag_policy},
    {0x80, 0x7F, TLV_BYTE_ORDER_LITTLE_ENDIAN, &length_policy},
    TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE, &constructed
};
```

The [integration test](../../tests/integration/formats/variable_test.cpp) checks
this configuration against a hand-written little-endian wire vector. EMV uses
two-byte Tags and deliberately accepts nonminimal lengths; this example is not
the EMV preset.

The added policy and predicate pointers change the C configuration ABI. Rebuild
native clients and matching bindings; zero-initialize or explicitly initialize
all configuration members.

## Concrete rules and terminated framing

`tlv_variable_fields_init()` from `tlv/formats/variable.h` creates a caller-owned
`tlv_field_composition_t` from `tlv/formats/compose.h` with
variable field callbacks and a borrowed configuration context. A definite
composition can be used through `tlv_fields_format_init()`. For more specialized
composition, the standalone identifier and length helpers can be called from
callbacks with a concrete format's own context.

The existing optional `tlv_field_composition_t.resolve` callback handles value
boundary resolution for terminated TLV framing with VALUE scope. A concrete
format can recognize its length marker before invoking the definite count
decoder, resolve the logical Value boundary and report a validated Trailer.
The resolver's error offsets are relative to the bytes after Tag; the field
composition translates them into element offsets.

Formats writing trailers supply matching canonical `measure` and `encode`
callbacks. The default Variable format and default field writer emit definite
counts and no trailer. Changing a read resolver does not change write behavior.
Constructed classification is also supplied by the concrete format.

Termination recognition must respect that format's element boundaries. Searching
opaque Value bytes for a marker is insufficient when the same bytes can occur
inside a child payload. The integration tests demonstrate a synthetic terminated
container whose resolver skips complete definite children, including a child
whose Value contains the trailer bytes.

The primitives do not assign meaning to ASN.1 classes or numbers, constructed
bits, EOC, EMV identifiers, dictionaries, or canonical restrictions.
[ASN.1 BER](asn1/ber.md#generic-mechanics-and-asn1-rules) composes these primitives
with its own identifier, length and indefinite/EOC policy. DER/CER wrapper
refactoring and independent EMV framing remain separate work.
