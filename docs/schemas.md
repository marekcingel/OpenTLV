# Optional C schemas

Include `tlv/schema.h` to describe known tags using constant tables:

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
