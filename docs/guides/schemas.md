# Optional C schemas

Include `tlv/schema/schema.h` to describe known tags using constant tables.
This engine is format-agnostic and expresses occurrence, nesting and
membership only; it has no ASN.1 semantics. For DER-specific canonical rules
it cannot express (SET/SET OF ordering, CHOICE, implicit/explicit tagging,
DEFAULT omission), see
[schema-aware DER validation and encoding](../profiles/der/README.md#schema-aware-validation-and-encoding),
a distinct schema type built for that purpose.

```c
/* A schema entry borrows its tag bytes, so they need static storage. */
static const uint8_t tag_01[] = {0x01};
static const uint8_t tag_02[] = {0x02};
static const uint8_t tag_9f02[] = {0x9F, 0x02};

static const tlv_schema_entry_t entries[] = {
    /* tag (bytes, size), minimum length, maximum length, flags, name */
    {{tag_01, sizeof(tag_01)}, 4, 4, 0, "counter"},   /* Exactly four bytes. */
    {{tag_02, sizeof(tag_02)}, 0, 32, 0, NULL},       /* Zero through 32 bytes, inclusive. */
    {{tag_9f02, sizeof(tag_9f02)}, 1, SIZE_MAX, 0, NULL}
};
static const tlv_schema_t schema = {
    entries, sizeof(entries) / sizeof(entries[0])
};

/* After successfully parsing a tlv_view_t named view: */
const tlv_schema_entry_t* rule = tlv_schema_find(&schema, &view.tag);
if (rule == NULL) {
    /* Unknown tag: the application decides whether to accept or reject it. */
} else {
    tlv_result_t result = tlv_schema_validate_length(rule, view.value.length);
    /* TLV_OK or TLV_ERR_INVALID_LENGTH. */
    (void)result;
}
```

The reader does not use schemas and can parse unknown tags and values outside
schema constraints. Validation is an explicit application step.

Lookup performs a linear scan without allocation or runtime registration. It
compares tags with `tlv_tag_equal()` (size and bytes, whatever memory backs them),
returns a borrowed entry pointer, and selects the first match for duplicate
tags. Tables need not be sorted. Keep their storage, including the bytes of
every tag in it, alive while using returned pointers. An empty schema can use
`{NULL, 0}`.

## What a tag is, what a format allows and what a schema requires

These are three separate questions:

- A `tlv_tag_t` is arbitrary raw bytes with a length. It has no maximum length
  and knows nothing about encodings.
- A **format** defines how tags are encoded and which tag lengths are valid. BER
  accepts 1 to 8 bytes, the default format exactly one, and a format defined at
  runtime can accept any length, such as 12 bytes. A format rejects the tags it
  does not support, and decides whether an empty tag is valid.
- A **schema** defines which tags are allowed or required in a scope and how
  long their values may be. A schema entry can hold a tag of any length; whether
  such a tag can ever appear in the input is up to the format that reads it.

Equal length bounds specify an exact length; `SIZE_MAX` allows any representable
upper length. Reversed bounds always fail validation. Flags are reserved and
currently ignored; initialize them to zero for future compatibility. `name` is
an optional, borrowed field name such as `"counter"`, used only by
[schema diagnostics](diagnostics.md#schema-diagnostics); leave it `NULL` if
the entry has none.

## Complete structure validation

`tlv_structure_schema_t` defines rules within a parent. Each
`tlv_structure_rule_t` contains an existing length entry, `min_occurs`,
`max_occurs`, `kind` and optional `children` schema. Required singleton fields
use 1/1; optional fields use 0/1; repeatable fields can use `SIZE_MAX` as their
maximum. Tags must be unique within the rule table. `allow_unknown` explicitly
controls unlisted children. `kind` is ANY, PRIMITIVE or CONSTRUCTED. Child schemas
require CONSTRUCTED and are checked even for an empty container.

/// tab | C

```c
#include "tlv/schema/schema.h"
static const uint8_t tag_1[] = {1};
static const uint8_t tag_2[] = {2};
static const tlv_structure_rule_t rules[] = {
    { { { tag_1, sizeof(tag_1) }, 1, 8, 0, "counter" }, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL },
    { { { tag_2, sizeof(tag_2) }, 0, 255, 0, NULL }, 0, SIZE_MAX, TLV_SCHEMA_ANY, NULL }
};
static const tlv_structure_schema_t message = {rules, 2, 0};
/* tlv_schema_validate(data, size, format, is_constructed, &message, 16, 1000, &offset); */
```

Runnable version, validating a two-level nested schema and rejecting a
document missing a required field:
[validate.c](https://github.com/marekcingel/OpenTLV/blob/main/examples/tlv/src/validate.c).

///

/// tab | C++

```cpp
#include "tlv++/tlv.hpp"
static const uint8_t tag_1[] = {1};
static const uint8_t tag_2[] = {2};
static const tlv_structure_rule_t rules[] = {
    { { { tag_1, sizeof(tag_1) }, 1, 8, 0, "counter" }, 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr },
    { { { tag_2, sizeof(tag_2) }, 0, 255, 0, nullptr }, 0, SIZE_MAX, TLV_SCHEMA_ANY, nullptr }
};
static const tlv_structure_schema_t message = {rules, 2, 0};
// tlv::validate(tlv::bytes(data, size), format, is_constructed, message, 16, 1000);
```

`tlv::validate` wraps `tlv_schema_validate` and returns an `expected<void, error>`
instead of a result code and out-parameter offset. Runnable version:
[validate.cpp](https://github.com/marekcingel/OpenTLV/blob/main/examples/tlv++/src/validate.cpp).

///

/// tab | Python

```python
schema = opentlv.StructureSchema([
    opentlv.StructureRule(opentlv.Tag(b"\x01"), min_length=1, max_length=8, min_occurs=1,
                           max_occurs=1, kind=opentlv.Kind.PRIMITIVE),
    opentlv.StructureRule(opentlv.Tag(b"\x02"), min_length=0, max_length=255),
])
schema.validate(data, format=opentlv.Format.BER)
```

`StructureSchema.validate()` runs the same C validator and raises
`SchemaMissingError`, `SchemaError` or `InvalidLengthError` instead of
returning a result code; see [Using OpenTLV from Python](python.md#validating).
Runnable version, with a two-level nested schema:
[validate.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/validate.py)
(`python examples/validate.py`).

///

/// tab | Rust

```rust
let schema = StructureSchema::new(
    [
        StructureRule::new(Tag::from_bytes(&[0x01]))
            .length(1, 8)
            .required_once()
            .kind(Kind::Primitive),
        StructureRule::new(Tag::from_bytes(&[0x02])).length(0, 255),
    ],
    false,
);
schema.validate(&data, Format::Ber, &ValidationLimits::default())?;
```

`StructureSchema::validate` returns `Result<(), SchemaError>` instead of a
result code and offset; see [Rust bindings: Schemas](../development/rust.md#schemas)
for `LengthSchema`, builder methods and the EMV built-in schemas. Runnable
version, with a two-level nested schema:
[validate.rs](https://github.com/marekcingel/OpenTLV/blob/main/bindings/rust/opentlv/examples/validate.rs)
(`cargo run --example validate`).

///

`tlv_schema_validate` checks complete framing and nesting, then lengths,
occurrences and child membership. It never decodes values. Invalid rule tables,
unknown tags, excessive occurrences and kind mismatches return `TLV_ERR_SCHEMA`,
with the offset anchored to the actual offending element; length failures
retain `TLV_ERR_INVALID_LENGTH`, anchored the same way. A missing required
field (an occurrence count below its rule's `min_occurs`) instead returns
`TLV_ERR_SCHEMA_MISSING`, with the offset at the end of its parent's value - a
scope boundary rather than an element, which can coincide with the start of
an unrelated sibling in the enclosing scope. Distinguish the two codes before
using the offset to look up a tag. Framing and resource errors propagate.
Success leaves the offset unchanged.

No allocation or C recursion is used. Each scope is rescanned for each rule;
complexity is `O(rules * rules + elements * rules)` per scope. Tables must remain immutable.
Sibling ordering and cross-field/value semantics are application concerns.
`tlv::validate` exposes these same rules through the C++ API. For a concrete
structure schema built on this engine, see
[EMV structural validation](../profiles/emv/README.md#structural-validation).

## Reporting every violation

`tlv_schema_validate` stops at the first violation. To validate a template's
contents and get all problems at once, call `tlv_schema_validate_all` with the
same `tlv_structure_schema_t`. The rules, including tag and length bounds, are
not duplicated: a template schema is an ordinary structure schema whose rules
say which tags are required (`min_occurs`), which may repeat (`max_occurs`),
which children each constructed tag may hold (`children`), and whether unknown
tags are accepted (`allow_unknown`, or an override for the whole call with
`tlv_schema_unknown_policy_t`).

```c
tlv_schema_issue_t  issues[16];
tlv_schema_report_t report = {issues, 16, 0};
tlv_result_t rc = tlv_schema_validate_all(data, size, &tlv_reader_format_ber,
                                          tlv_ber_is_constructed, &template_schema, 16, 1000,
                                          TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, &offset);
if (rc == TLV_ERR_SCHEMA) {
    for (size_t i = 0; i < report.count && i < report.capacity; ++i) {
        char path[64];
        (void)tlv_schema_issue_path_string(&issues[i], path, sizeof(path), NULL);
        printf("%s at %s", tlv_schema_issue_kind_string(issues[i].kind), path);
        if (issues[i].has_offset) printf(" (offset %zu)", issues[i].offset);
        printf("\n");
    }
}
```

Each `tlv_schema_issue_t` has a `kind` (`MISSING`, `DUPLICATE`, `UNEXPECTED`,
`KIND` for a primitive/constructed mismatch, `LENGTH`), the `path` from the
outermost scope to the affected tag (`70/77/9F36` as text), and the byte
`offset` of the element. The path tags borrow the input that was validated (and
the schema, for a missing tag), so both must outlive the issue. A missing tag has no element of its own, so its offset
is that of the enclosing element; a tag missing at the top level has no offset
(`has_offset` is zero). The return value is `TLV_OK`, `TLV_ERR_SCHEMA` when
violations were found (`report.count` is the total, even beyond `capacity`), or
another error. A malformed or truncated wire encoding is not a violation: it
aborts the call with the reader's error and no violations are reported.
An element rejected as unexpected or of the wrong form is not descended into,
but its siblings are still checked. Paths are limited to `TLV_SCHEMA_PATH_MAX`
tags; a schema nested deeper returns `TLV_ERR_LIMIT`. `tlv::validate_all`
wraps the same call in C++.

## Diagnostics for a violation

`tlv_schema_issue_t` is compact but only says which rule and tag failed. To
also get the schema field name and the expected-versus-actual detail behind a
violation, call `tlv_schema_validate_all_diag()` instead of
`tlv_schema_validate_all()`: same rules, order and storage conventions,
but each violation is a `tlv_schema_diagnostic_t` that pairs a
`tlv_diagnostic_t` (code, offset) with the enclosing `path`, the affected
`tag`, the rule's `field` name (its entry's `name`, or `NULL` if unnamed),
and, depending on `kind`, occurrence counts, length bounds or the
primitive/constructed mismatch. See
[Schema diagnostics](diagnostics.md#schema-diagnostics) for the fields and a
worked example. `tlv::validate_all_diag` wraps the same call in C++.

See also the [C API reference: schemas](../reference/c-api.md#schemas) and the [C++ API reference](../reference/cxx-api.md).
