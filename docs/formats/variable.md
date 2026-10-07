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
nonminimal encodings and identifiers wider than an integer are supported;
concrete standards must enforce any stricter rules themselves.

`tlv_variable_identifier_read()` returns the borrowed identifier and consumed
width. `tlv_variable_identifier_write()` validates a complete identifier and
copies its bytes unchanged; NULL output with zero capacity measures it.

## Length encoding

`tlv_variable_length_t` describes a prefix with a long-form bit and a payload
mask. With the long-form bit clear, the payload is the count. With the bit set,
the payload is the number of following count octets, in explicitly configured
big or little endian order. Payload mask bits are packed from least to most
significant, so the selector need not occupy the high bit.

`tlv_variable_length_read()` accepts nonminimal and zero-padded encodings if the
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
    {0x70, 0x20, 0x01, 0xF0, 8},
    {0x80, 0x7F, TLV_BYTE_ORDER_LITTLE_ENDIAN},
    TLV_ELEMENT_ORDER_TLV,
    TLV_LENGTH_SCOPE_VALUE
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
