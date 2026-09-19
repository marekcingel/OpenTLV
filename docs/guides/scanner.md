# TLV scanning and recovery

Include `tlv/reader/scanner.h` to search from an arbitrary byte offset. The scanner
calls the generic `tlv_read()` at successive offsets and returns the first
complete candidate, without allocating or copying values.

```c
#include "tlv/reader/scanner.h"

const uint8_t data[] = {0xFF, 0xFF, 0x42, 1, 0xAB};
tlv_view_t view;
size_t offset, consumed;
tlv_result_t result = tlv_scan(data, sizeof(data), 0,
    &tlv_reader_format_fixed_1byte, NULL, &view, &offset, &consumed);
/* TLV_OK: offset == 2, consumed == 3, view.value.data == data + 4. */
```

`offset` is relative to the original buffer, even with a nonzero starting
position. To continue after a match, pass `offset + consumed` as the next start.
The view borrows the input; keep the buffer alive while using it.

Pass an optional `const tlv_schema_t*` instead of `NULL` to require both a known
tag and a value length within its inclusive bounds. An empty schema rejects
every candidate. Schema lookup and validation use the [schema API](schemas.md),
including its first-match behavior for duplicate tags.

Parsing and schema failures cause a one-byte advance, even when a candidate is
truncated or has a decoded length that would skip later valid candidates.
No match returns `TLV_ERR_END_OF_BUFFER`, including empty input and starts at or
beyond the buffer end. All outputs remain unchanged on failure. Invalid pointer
arguments or missing read callbacks return `TLV_ERR_NULL_ARG`; see the header
for the full argument contract.

A syntactically valid candidate can occur in noise or inside another value.
Schemas reduce false positives but cannot guarantee the original TLV boundary.
The supplied format determines tag and length syntax; the built-in formats use
one-byte tags. Custom format callbacks must obey the allocation-free format
contract. The scanner uses constant auxiliary memory; schema lookup is linear
in the number of entries for each successfully parsed candidate.

Scanning is separate from ordinary reading and walking. Neither API skips
invalid bytes or implicitly applies schemas.
