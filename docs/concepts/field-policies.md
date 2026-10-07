# Declarative field policies

This design note records the implementation decisions for #542, following the
[packed Format work](../formats/packed.md) in #541. Policies configure existing
Field Encoding and Format contracts; they introduce no processing layer.

## Generic mechanisms and protocol ownership

| Rule | Owner and implementation |
| --- | --- |
| Forbidden first identifier bytes | Generic `tlv_identifier_policy_t`; the protocol supplies the borrowed byte table. |
| Nonzero first escaped payload | Generic identifier policy, applied to the available prefix before continuation parsing. |
| Maximum identifier width | Existing `tlv_variable_identifier_t.max_size`. |
| Minimal identifier number encoding | Optional generic identifier policy; arbitrary-width digits and sparse masks are supported. |
| Short/long definite forms, maximum long width and value, minimal count | Generic `tlv_length_policy_t` attached to `tlv_variable_length_t`. |
| Constructed flag encoded in canonical Tag bytes | Generic `tlv_constructed_bit_predicate` with byte index, mask and comparison value. |
| ASN.1 class/universal-number primitive/constructed rules | ASN.1-owned identifier callbacks; these describe ASN.1 types, not generic wire fields. |
| BER indefinite/EOC scanning and CER form-by-constructedness | Existing ASN.1 callbacks; terminated framing is outside this change. |

## Context and storage

Variable identifier and length configurations directly borrow optional immutable
policy objects. A NULL policy keeps the unconstrained field behavior. The
Variable Format configuration also borrows an optional constructed-bit predicate.
`tlv_variable_format_init()` installs a classifier only when it is configured.
The classifier receives the same Variable Format context as decode/measure/encode
and locates its predicate there. The standalone bit predicate instead takes the
bit configuration directly; these two callback contexts are not interchangeable.

Every configuration, policy, predicate and forbidden-byte table must outlive all
operations that use it. There is no allocation or hidden mutable state. Raw Tag
identity and borrowed source ranges do not change. Classification tests canonical
Tag bytes, including with format-supplied identifiers; it does not validate Tags.

## Encoding and error contracts

Identifier prefix restrictions run before the remaining identifier is parsed,
preserving EMV's error precedence on truncated or oversized inputs. Minimal
identifier encoding means no redundant leading zero digits, and no escaped
number that could have used the inline field. An escape value that is not the
maximum inline number is supported. Comparison saturates above the inline range
instead of narrowing arbitrary identifiers to a machine integer.

Length form and long-width limits reject the offending prefix with consumed=1,
even if its payload is absent. Other truncation reports the available field
prefix. Value/minimality failures report the complete field width and preserve
the value output. Policy-constrained arithmetic overflow is INVALID_LENGTH
because it violates the finite max_value bound; unconstrained fields retain
OVERFLOW. Encoding selects the shortest allowed form and checks policy before
writing. A long-only policy encodes zero as one following zero octet. Minimality
permits that form, but rejects extra padding. All lengths remain definite.

## Builtin adoption

EMV is entirely a `tlv_variable_format_t` configuration with generic callbacks:
one/two-byte identifiers, forbidden leading zero, nonzero first escaped payload,
short/long lengths through two following octets and 65535, and bit 0x20 in Tag
byte zero. Identifier and length minimality stay disabled to preserve existing
EMV wire acceptance, including raw identifiers such as `9F 1C`.

DER/CER's shared identifier reader uses the generic minimal-number policy before
applying ASN.1 universal-type semantics. Their minimal definite-length callback delegates to the generic
length primitive with a policy: short/long allowed, minimal encoding required,
maximum 126 following octets and UINT64_MAX. The width limit reserves prefix FF
without changing the existing prefix-error precedence. The small ASN.1 adapter
is intentional: it binds this package-owned configuration while retaining the
context used by ASN.1 identifier and bounds callbacks.

DER's universal-number checks remain intentional ASN.1 callbacks. Moving the
assigned universal type set into a generic policy table would expose ASN.1 type
semantics as generic wire configuration without benefiting a second protocol.
The shared ASN.1 constructed callback delegates to the generic bit predicate;
its domain API and context convention remain intact.

## Compatibility and scope

This change deliberately changes the C ABI of `tlv_variable_identifier_t`,
`tlv_variable_length_t` and `tlv_variable_format_t`. Rebuild native consumers and
matching bindings. Initialize the new policy/predicate pointers explicitly, or
zero-initialize the configuration before assigning members. Existing descriptor
symbols and builtin wire behavior are retained; no compatibility wrapper is
introduced. The changelog records the break.

Language presets continue to call the C engine. General idiomatic configuration
constructors across bindings remain a documented parity gap; raw/native interop
is not claimed as complete facade parity. Runtime `.otlv`, protocol dictionaries,
ASN.1 universal semantics and indefinite framing are not expanded here.
