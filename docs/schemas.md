# Optional C schemas

Include `tlv/schemas/schema.h` to describe known tags using constant tables:

```c
static const tlv_schema_entry_t entries[] = {
    /* tag bytes, tag size, minimum length, maximum length, flags */
    {{{0x01}, 1}, 4, 4, 0},       /* Exactly four bytes. */
    {{{0x02}, 1}, 0, 32, 0},      /* Zero through 32 bytes, inclusive. */
    {{{0x9F, 0x02}, 2}, 1, SIZE_MAX, 0}
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
compares tag size and active bytes, returns a borrowed entry pointer, and selects
the first match for duplicate tags. Tables need not be sorted. Keep their storage
alive while using returned pointers. An empty schema can use `{NULL, 0}`.

Equal length bounds specify an exact length; `SIZE_MAX` allows any representable
upper length. Reversed bounds always fail validation. Flags are reserved and
currently ignored; initialize them to zero for future compatibility.

## Complete structure validation

`tlv_structure_schema_t` defines rules within a parent. Each
`tlv_structure_rule_t` contains an existing length entry, `min_occurs`,
`max_occurs`, `kind` and optional `children` schema. Required singleton fields
use 1/1; optional fields use 0/1; repeatable fields can use `SIZE_MAX` as their
maximum. Tags must be unique within the rule table. `allow_unknown` explicitly
controls unlisted children. `kind` is ANY, PRIMITIVE or CONSTRUCTED. Child schemas
require CONSTRUCTED and are checked even for an empty container.

```c
#include "tlv/schemas/schema.h"
static const tlv_structure_rule_t rules[] = {
    { { {{1}, 1}, 1, 8, 0 }, 1, 1, TLV_SCHEMA_PRIMITIVE, NULL },
    { { {{2}, 1}, 0, 255, 0 }, 0, SIZE_MAX, TLV_SCHEMA_ANY, NULL }
};
static const tlv_structure_schema_t message = {rules, 2, 0};
/* tlv_schema_validate(data, size, format, is_constructed, &message, 16, 1000, &offset); */
```

`tlv_schema_validate` checks complete framing and nesting, then lengths,
occurrences and child membership. It never decodes values. Invalid rule tables,
unknown tags, missing fields, excessive occurrences and kind mismatches return
`TLV_ERR_SCHEMA`; length failures retain `TLV_ERR_INVALID_LENGTH`. Framing and
resource errors propagate. Failure offsets identify the element, or the end
of a parent with missing fields. Success leaves the offset unchanged.

No allocation or C recursion is used. Each scope is rescanned for each rule;
complexity is O(rules * rules + elements * rules) per scope. Tables must remain immutable.
Sibling ordering and cross-field/value semantics are application concerns.
`tlv::validate` exposes these same rules through the C++ API.
