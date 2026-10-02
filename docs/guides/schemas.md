# Optional C schemas

Include `tlv/schema/schema.h` to describe known tags using constant tables.
This engine is format-agnostic: it expresses occurrence, ordering, mutually
exclusive alternatives, nesting and membership using generic primitives, with
no ASN.1-specific semantics. [Ordered, unordered and CHOICE-like
structures](#ordered-unordered-and-choice-like-structures) below maps these
primitives to the ASN.1 shapes they cover (SEQUENCE, SET, SET OF, CHOICE). For
DER-specific canonical rules this engine still cannot express (implicit/explicit
tagging, DEFAULT-value comparison against the encoded bytes, canonical SET/SET
OF tag- or encoding-based sort order), see
[schema-aware DER validation and encoding](../standards/der/README.md#schema-aware-validation-and-encoding),
a distinct schema type built for that purpose.

A nonzero `tlv_schema_entry_t.length_multiple` requires the value length to be
divisible by that width as well as satisfying the inclusive bounds. Zero
disables the multiple constraint; an empty value satisfies any multiple when
the minimum permits it. All schema validators use this rule. Length diagnostics expose the expected `length_multiple`.
The [Bluetooth AD schema](../formats/bluetooth/README.md#advertising-data-schema)
uses it for UUID lists without decoding their values.

Set `flags = TLV_SCHEMA_LENGTH_ENDPOINTS` to permit only `min_length` or
`max_length`, for example 4 or 8 bytes while rejecting 5, 6 and 7. Both endpoints
must still satisfy `length_multiple` when it is nonzero. Equal bounds remain an
exact length; flags zero retains the inclusive interval. Unknown flag bits are
ignored. Length diagnostics also expose `length_flags`, so an endpoint-only
constraint can be distinguished from an interval. Rebuild consumers of the
extended `tlv_schema_diagnostic_t`; `tlv_schema_entry_t` retains its layout.

```c
/* A schema entry borrows its tag bytes, so they need static storage. */
static const uint8_t tag_01[] = {0x01};
static const uint8_t tag_02[] = {0x02};
static const uint8_t tag_9f02[] = {0x9F, 0x02};

static const tlv_schema_entry_t entries[] = {
    /* tag (bytes, size), minimum length, maximum length, flags, name, length multiple */
    {{tag_01, sizeof(tag_01)}, 4, 4, 0, "counter", 0},   /* Exactly four bytes. */
    {{tag_02, sizeof(tag_02)}, 0, 32, 0, NULL, 0},       /* Zero through 32 bytes, inclusive. */
    {{tag_9f02, sizeof(tag_9f02)}, 1, SIZE_MAX, 0, NULL, 0}
};
static const tlv_schema_t schema = {
    entries, sizeof(entries) / sizeof(entries[0])
};

/* After successfully parsing a tlv_element_t named element: */
const tlv_schema_entry_t* rule = tlv_schema_find(&schema, &element.tag);
if (rule == NULL) {
    /* Unknown tag: the application decides whether to accept or reject it. */
} else {
    tlv_result_t result = tlv_schema_validate_length(rule, element.value.size);
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
  accepts 1 to 8 bytes, and a format defined at
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
`tlv_structure_rule_t` references an existing field schema, `min_occurs`,
`max_occurs`, `kind` and optional `children` schema. Required singleton fields
use 1/1; optional fields use 0/1; repeatable fields can use `SIZE_MAX` as their
maximum. Tags must be unique within the rule table. `allow_unknown` explicitly
controls unlisted children. `kind` is ANY, PRIMITIVE or CONSTRUCTED. Child schemas
require CONSTRUCTED and are checked even for an empty container.

Each language below defines the same unordered schema: tag `01` is required
once, primitive and 1–8 bytes long; tag `02` is optional, repeatable and 0–255
bytes long. Unknown tags are rejected. Validate the same BER input, for example
`01 01 2A 02 00`, to compare the public API and error handling.

/// tab | C

```c
#include "tlv/schema/schema.h"
static const uint8_t tag_1[] = {1};
static const uint8_t tag_2[] = {2};
static const tlv_schema_entry_t rules_fields[] = {
    { { tag_1, sizeof(tag_1) }, 1, 8, 0, "counter", 0},
    { { tag_2, sizeof(tag_2) }, 0, 255, 0, NULL, 0}
};
static const tlv_structure_rule_t rules[] = {
    {&rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&rules_fields[1], 0, SIZE_MAX, TLV_SCHEMA_ANY, NULL, 0}
};
static const tlv_structure_schema_t message = {rules, 2, 0, NULL, 0, TLV_SCHEMA_ORDER_ANY};
size_t offset;
tlv_result_t rc = tlv_schema_validate(data, size, format, &message, 16, 1000, &offset);
if (rc != TLV_OK) return 1;
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
static const tlv_schema_entry_t rules_fields[] = {
    { { tag_1, sizeof(tag_1) }, 1, 8, 0, "counter", 0},
    { { tag_2, sizeof(tag_2) }, 0, 255, 0, nullptr, 0}
};
static const tlv_structure_rule_t rules[] = {
    {&rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&rules_fields[1], 0, SIZE_MAX, TLV_SCHEMA_ANY, nullptr, 0}
};
static const tlv_structure_schema_t message = {rules, 2, 0, NULL, 0, TLV_SCHEMA_ORDER_ANY};
auto result = tlv::validate(tlv::bytes(data, size), format, message, 16, 1000);
if (!result) return 1;
```

`tlv::validate` wraps `tlv_schema_validate` and returns an `expected<void, error>`
instead of a result code and out-parameter offset. Runnable version:
[validate.cpp](https://github.com/marekcingel/OpenTLV/blob/main/examples/tlv++/src/validate.cpp).

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

/// tab | Lua

```lua
local opentlv = require("opentlv")
local schema = opentlv.schema {allow_unknown = false, rules = {
    {tag = string.char(1), min_length = 1, max_length = 8,
     min_occurs = 1, max_occurs = 1, kind = "primitive"},
    {tag = string.char(2), min_length = 0, max_length = 255,
     min_occurs = 0, max_occurs = math.huge},
}}
local result = schema:validate(data, opentlv.formats.ber)
assert(result.ok, result.code)
```

Lua returns a validation report with `ok`, native status and owned diagnostics. Invalid schema arguments raise errors. Go has no public Schema facade yet.

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

No allocation or C recursion is used. Each scope is rescanned for each rule and
each group; complexity is `O((rules + groups) * (rules + elements))` per scope.
Tables must remain immutable. Sibling order is a schema concern only when a
scope opts into it (see below); cross-field/value semantics stay an
application concern. `tlv::validate` exposes these same rules through the C++
API. For a concrete structure schema built on this engine, see
[EMV structural validation](../standards/emv/README.md#structural-validation).

## Ordered, unordered and CHOICE-like structures

`tlv_structure_schema_t` has two more fields beyond `rules`, `count` and
`allow_unknown`: `order` and `groups`/`group_count`. Together with
`min_occurs`/`max_occurs`, they let a schema express the generic shapes ASN.1
constructed types need, without any ASN.1-specific schema object:

| Generic OpenTLV concept | ASN.1 equivalent |
| --- | --- |
| `order = TLV_SCHEMA_ORDER_ANY` (the default) | SET |
| `order = TLV_SCHEMA_ORDER_SEQUENCE` | SEQUENCE |
| A rule with `max_occurs = SIZE_MAX` | SET OF (with `order` left `ANY`) or SEQUENCE OF (with `order = TLV_SCHEMA_ORDER_SEQUENCE`) |
| `min_occurs = 1` | a required member |
| `min_occurs = 0` | an optional member, or a defaulted one (see below) |
| A `tlv_structure_group_t` with `min_occurs = 1`, `max_occurs = 1`, and every member rule's own `min_occurs = 0` | CHOICE |

`TLV_SCHEMA_ORDER_SEQUENCE` requires elements that match a rule to appear in
the same relative order as their rules are listed in the table; repeated
matches of one rule may still appear consecutively, and elements matching no
rule are not constrained by it.

A `tlv_structure_group_t` groups rules that share a nonzero
`tlv_structure_rule_t::group`. Occurrence bounds then apply to the sum of
matches across every member tag, instead of to each tag individually: a group
with `min_occurs` 1 and `max_occurs` 1 requires exactly one occurrence of
exactly one alternative. A member rule's own `min_occurs` must be 0, because
requiredness is expressed by the group; its `max_occurs` still bounds how many
times that one alternative may repeat.

This is enough to express the ASN.1 example from
[issue #308](https://github.com/marekcingel/OpenTLV/issues/308):

```asn1
Person ::= SEQUENCE {
    id      INTEGER,
    name    UTF8String,
    comment UTF8String OPTIONAL
}
```

/// tab | C

```c
static const tlv_schema_entry_t person_rules_fields[] = {
    {TLV_TAG(1), 1, 8, 0, "id", 0},
    {TLV_TAG(2), 0, 255, 0, "name", 0},
    {TLV_TAG(3), 0, 255, 0, "comment", 0}
};
static const tlv_structure_rule_t person_rules[] = {
    {&person_rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&person_rules_fields[1], 1, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0},
    {&person_rules_fields[2], 0, 1, TLV_SCHEMA_PRIMITIVE, NULL, 0}
};
static const tlv_structure_schema_t person_schema = {
    person_rules, 3, 0, NULL, 0, TLV_SCHEMA_ORDER_SEQUENCE};
```

///

/// tab | C++

```cpp
static const tlv_schema_entry_t person_rules_fields[] = {
    {TLV_TAG(1), 1, 8, 0, "id", 0},
    {TLV_TAG(2), 0, 255, 0, "name", 0},
    {TLV_TAG(3), 0, 255, 0, "comment", 0}
};
static const tlv_structure_rule_t person_rules[] = {
    {&person_rules_fields[0], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&person_rules_fields[1], 1, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0},
    {&person_rules_fields[2], 0, 1, TLV_SCHEMA_PRIMITIVE, nullptr, 0}
};
static const tlv_structure_schema_t person_schema = {
    person_rules, 3, 0, nullptr, 0, TLV_SCHEMA_ORDER_SEQUENCE};
```

///

/// tab | Rust

```rust
let person = StructureSchema::with_constraints(
    [
        StructureRule::new(Tag::from_bytes(&[1])).length(1, 8)
            .required_once().kind(Kind::Primitive),
        StructureRule::new(Tag::from_bytes(&[2])).length(0, 255)
            .required_once().kind(Kind::Primitive),
        StructureRule::new(Tag::from_bytes(&[3])).length(0, 255)
            .occurs(0, 1).kind(Kind::Primitive),
    ],
    false, SchemaOrder::Sequence, [],
);
```

Import `SchemaOrder`, `StructureSchema`, `StructureRule`, `Tag` and `Kind` from `opentlv`.

///

/// tab | Python

```python
person = opentlv.StructureSchema([
    opentlv.StructureRule(opentlv.Tag(b"\x01"), min_length=1, max_length=8,
        min_occurs=1, max_occurs=1, kind=opentlv.Kind.PRIMITIVE),
    opentlv.StructureRule(opentlv.Tag(b"\x02"), min_length=0, max_length=255,
        min_occurs=1, max_occurs=1, kind=opentlv.Kind.PRIMITIVE),
    opentlv.StructureRule(opentlv.Tag(b"\x03"), min_length=0, max_length=255,
        min_occurs=0, max_occurs=1, kind=opentlv.Kind.PRIMITIVE),
], order=opentlv.SchemaOrder.SEQUENCE)
```

///

/// tab | Lua

```lua
local person = opentlv.schema {order = "sequence", allow_unknown = false, rules = {
    {tag = string.char(1), name = "id", min_length = 1, max_length = 8,
     min_occurs = 1, max_occurs = 1, kind = "primitive"},
    {tag = string.char(2), name = "name", min_length = 0, max_length = 255,
     min_occurs = 1, max_occurs = 1, kind = "primitive"},
    {tag = string.char(3), name = "comment", min_length = 0, max_length = 255,
     min_occurs = 0, max_occurs = 1, kind = "primitive"},
}}
```

These rules constrain the same `01`, `02`, `03` wire tags as the C example; ASN.1 names are descriptive and do not change identifiers.

///

The reader still provides the nested TLV elements; the schema layer only
validates their relationship (order, required/optional, and, with a `group`,
mutual exclusivity), the same way it already validates occurrence and
membership. DEFAULT has no dedicated representation here: since this engine
never decodes values, a defaulted member is written the same way as an
optional one (`min_occurs = 0`), and comparing an encoded value against its
default stays a format-specific concern, as it already is for DER (see
[schema-aware DER validation and encoding](../standards/der/README.md#schema-aware-validation-and-encoding)).

## Value constraints on decoded values

`tlv_structure_schema_t` never decodes values, so it cannot express an
ASN.1-style constraint that depends on a value's *decoded* meaning, such as
an INTEGER's numeric range or a fixed set of legal values. `tlv/schema/constraint.h`
adds a small, generic `tlv_value_constraint_t` for exactly that: check it
against the C value a codec's decode produces (see
[value codecs](codecs.md)), separately from the wire-level checks above.

```c
#include "tlv/schema/constraint.h"
#include "tlv/builtins/asn1/asn1_codec.h"

/* Version ::= INTEGER (0..255) */
static const tlv_value_constraint_t version_range = {
    TLV_VALUE_CONSTRAINT_RANGE, 0, 255, NULL, 0
};

int64_t version;
tlv_codec_decode(&tlv_asn1_codec_integer, element.value.data, element.value.size,
                  &version, sizeof(version));
tlv_result_t rc = tlv_value_constraint_validate(&version_range, version);
/* TLV_OK, or TLV_ERR_SCHEMA if version is outside 0-255. */
```

A fixed set of legal values (`TLV_VALUE_CONSTRAINT_ALLOWED_VALUES`) works the same way:

```c
/* CurrencyCode ::= INTEGER (978 | 840 | 826) */
static const int64_t currency_codes[] = {978, 840, 826};
static const tlv_value_constraint_t currency_constraint = {
    TLV_VALUE_CONSTRAINT_ALLOWED_VALUES, 0, 0, currency_codes, 3, NULL
};
```

`allowed_value_names`, the trailing field left `NULL` above, optionally attaches a display
name to each entry of `allowed_values` (an ASN.1 named number, as in `INTEGER {red(0), green(1),
blue(2)}`), parallel to it and the same length. It is purely descriptive and
`tlv_value_constraint_validate()` ignores it entirely; look a name up with
`tlv_value_constraint_name()`:

```c
/* Color ::= INTEGER {red(0), green(1), blue(2)} */
static const int64_t color_values[] = {0, 1, 2};
static const char* const color_names[] = {"red", "green", "blue"};
static const tlv_value_constraint_t color_constraint = {
    TLV_VALUE_CONSTRAINT_ALLOWED_VALUES, 0, 0, color_values, 3, color_names
};

const char* name = tlv_value_constraint_name(&color_constraint, 1); /* "green" */
```

A `NULL` `allowed_value_names` array (as with `currency_constraint` above) means no entry has a
name; a `NULL` entry within a non-`NULL` array means only that one value has none.

Together with the length and occurrence bounds `tlv_structure_schema_t`
already has, this covers the ASN.1 constraints relevant to binary TLV
validation without an ASN.1 constraint expression parser:

| ASN.1 constraint | Generic OpenTLV concept | Represented by |
| --- | --- | --- |
| `SIZE(8)` (exact size) | size | Equal `min_length`/`max_length` on a #tlv_schema_entry_t |
| `SIZE(1..1024)` (size range) | size-range | `min_length`/`max_length` on a #tlv_schema_entry_t |
| `INTEGER (0..255)` (value range) | value-range | `tlv_value_constraint_t` with `kind = TLV_VALUE_CONSTRAINT_RANGE` |
| a fixed set of legal values | allowed-values | `tlv_value_constraint_t` with `kind = TLV_VALUE_CONSTRAINT_ALLOWED_VALUES` |
| named numbers (`INTEGER {red(0), green(1)}`) | named allowed-values | `tlv_value_constraint_t`'s optional `allowed_value_names`, looked up with `tlv_value_constraint_name()` |
| exact `SIZE` of a SET OF/SEQUENCE OF | count | Equal `min_occurs`/`max_occurs` on a #tlv_structure_rule_t or #tlv_structure_group_t |
| minimum `SIZE` | min-count | `min_occurs` |
| maximum `SIZE` | max-count | `max_occurs` |

For example, `OCTET STRING (SIZE(8))` needs nothing new:

```c
static const uint8_t tag_id[] = {0x04};
static const tlv_schema_entry_t identifier = {{tag_id, sizeof(tag_id)}, 8, 8, 0, "identifier", 0};
```

## Reporting every violation

`tlv_schema_validate` stops at the first violation. To collect all violations,
call `tlv_schema_validate_all_diag` with the same `tlv_structure_schema_t`.
The rules, including occurrence, ordering, groups, form and length constraints,
are shared with fail-fast validation.

```c
tlv_schema_diagnostic_t diagnostics[16];
tlv_schema_diagnostic_report_t report = {diagnostics, 16, 0};
tlv_result_t rc = tlv_schema_validate_all_diag(data, size, &tlv_format_ber,
    &template_schema, 16, 1000, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, &offset);
if (rc == TLV_ERR_SCHEMA) {
    for (size_t i = 0; i < report.count && i < report.capacity; ++i) {
        const tlv_schema_diagnostic_t* d = &diagnostics[i];
        char path[256];
        if (tlv_diagnostic_path_string(&d->path, path, sizeof(path), NULL) == TLV_OK)
            printf("%s in %s", tlv_schema_issue_kind_string(d->kind), path);
        if (d->diagnostic.has_offset) printf(" (offset %zu)", d->diagnostic.offset);
        printf("\n");
    }
}
```

Each diagnostic contains its violation `kind`, affected `tag`, enclosing scope
`path`, field name, common diagnostic code/offset and applicable expected/actual
constraints. The path excludes the affected tag. Tags and names borrow input,
Format or Schema storage, which must outlive retained C diagnostics. Missing
fields use their enclosing element's offset; a missing root field has no offset.

`TLV_OK` means no violations. `TLV_ERR_SCHEMA` supplies the total count, which can
exceed storage capacity. Zero capacity counts only. Wire errors abort validation
without a partial report. Unexpected or wrongly formed elements are not descended
into; siblings are still checked. Paths use the shared `TLV_DIAGNOSTIC_PATH_MAX`
bound. C++ exposes `tlv::validate_all_diag`; Rust and Python expose
`StructureSchema.validate_diagnostics` with owned report records.

## Diagnostics for a violation

See [Schema diagnostics](diagnostics.md#schema-diagnostics) for the expected/actual
fields and an example. The compact issue/report API and its separate path formatter
were removed in #401; use the shared diagnostic representation throughout.

See also the [C API reference: schemas](../reference/c-api.md#schemas) and the [C++ API reference](../reference/cxx-api.md).

## Sharing field rules across structural contexts

`tlv_structure_rule_t.entry` is a required borrowed pointer to exactly one
`tlv_schema_entry_t`. That object supplies the tag, diagnostic name and all
field-length rules. Occurrence, wire form, groups and child schemas remain
properties of the structural rule. There is no inline alternative or override.
A NULL field pointer makes the structural schema invalid.

A dictionary, standalone validation and several parent contexts can share one
immutable field description. Keep the field object, tag bytes and name alive
and unchanged for every use of the rule, including borrowed diagnostic results.
Static arrays need no allocation. Owning builders (such as Rust and Python)
keep field storage stable before forming rule pointers. Validation does not
allocate. EMV templates borrow their dictionary's exact field objects.

For migration, extract each former inline field into a named object or array,
initialize `entry` with its address, remove the trailing `entry_ref`, and rebuild
consumers. The accessor `tlv_structure_rule_entry()` is removed; read `rule.entry`
directly.

## Composing field Schema with numeric conversion

Include `tlv/schema/number.h` for the optional `tlv_schema_number_t` adapter.
It borrows one authoritative Schema and a numeric representation configuration.
Decode checks the field length before delegating to `tlv_number_decode()`.
With representation width zero, encode selects the shortest supported width
that both fits the number and satisfies Schema. A fixed representation width
must satisfy Schema and is never silently widened.

```c
#include "tlv/schema/number.h"

static const uint8_t field_tag[] = {1};
static const tlv_schema_entry_t field = {
    {field_tag, sizeof(field_tag)}, 1, 3, TLV_SCHEMA_LENGTH_ENDPOINTS, "counter", 0
};
static const tlv_schema_number_t number = {
    &field, {TLV_NUMBER_BINARY_BE, 0, 0}
};
static const tlv_codec_t codec = {
    &number, tlv_schema_number_decode, tlv_schema_number_encode
};
/* uint64_t 256 encodes as 00 01 00: Schema excludes the two-byte width. */
```

`tlv_schema_number_codec(&number)` constructs the same descriptor for
caller-owned storage. Keep configuration and Schema alive and immutable while
used. No tag lookup, allocation or mandatory registry is involved. EMV numeric
entries use this adapter; LLDP tests exercise it against TTL field constraints
with an explicitly selected `uint64_t` representation.
