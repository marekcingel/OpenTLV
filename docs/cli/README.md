# Command-line tool

The optional `otlv` executable inspects and structurally validates TLV
data using the public C library through the `tlv++` wrapper. Building it
requires a C++11 (or newer) compiler; the underlying library itself remains a
dependency-free C99 core, so this requirement affects only the CLI target.

## Build and install

```sh
cmake -S . -B build-cli -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF -DOPENTLV_BUILD_CLI_TESTS=ON
cmake --build build-cli --config Release
ctest --test-dir build-cli -C Release --output-on-failure
cmake --install build-cli --config Release --prefix install-cli
```

For single-configuration generators, also configure `-DCMAKE_BUILD_TYPE=Release`.
The executable is installed in the standard runtime directory (normally `bin`).
Shared builds install the TLV runtime as well; retain the installed directory
layout so the executable can locate it. `OPENTLV_BUILD_CLI` defaults to `ON`
and requires `OPENTLV_BUILD_CXX=ON` (also the default); a C-only build
(`OPENTLV_BUILD_CXX=OFF`) silently skips the CLI instead of failing.
`OPENTLV_BUILD_CLI_TESTS` initially defaults to `OPENTLV_BUILD_TESTS`; CLI
tests use CMake only and can run with library unit/integration tests disabled.
Building the CLI fetches [nlohmann/json](https://github.com/nlohmann/json)
(header-only, used for `--output json`) via CMake `FetchContent`; the `tlv`
and `tlv++` libraries themselves remain dependency-free.

## Commands

```sh
otlv --help
otlv --version
otlv formats
otlv dump --format ber --hex "E1 03 5A 01 12" --tree
otlv dump --format fixed-1byte --input sample.bin
otlv dump --format bluetooth-ltv --hex "02 01 06 03 09 48 69"
otlv validate --format der --input sample.der
otlv validate --format ber --input -
otlv dump --format ber --profile emv --hex "6F0784050102030405" --pretty --describe
otlv dump --format ber --input capture.hex --input-encoding hex
otlv dump --format ber --profile emv --decode --hex "9F0206000000001000"
otlv dump --format ber --profile emv --decode --output json --hex "9F0206000000001000"
otlv validate --format ber --profile emv --input input.bin
otlv encode --format ber --tag 9F02 --value 000000001000
otlv tag 9F02 --profile emv
```

`dump` and `validate` require an explicit `--format` and exactly one input
source. `--input -` reads binary stdin, including on Windows. File input is
binary as well by default. Use `--input-encoding hex` for hex text files or
hex text on stdin; `--input-encoding binary` explicitly selects binary input.
Input encoding is never guessed. `--hex` accepts case-insensitive contiguous hex bytes or
whitespace between complete byte pairs; prefixes such as `0x`, separators,
and incomplete pairs are rejected. An empty hex string or empty file is valid.
The same hex syntax applies to files and stdin, including CR/LF between pairs.
`--max-input-size` limits decoded bytes; hex whitespace is discarded as it is
read without buffering the encoded text. It does not limit the number of
whitespace characters read from a stream.

`formats` lists only enabled formats: `default`, `fixed-1byte`, `ber`,
`der`, and `bluetooth-ltv`. Existing library CMake component options control availability. Unknown
or disabled formats fail before reading input. No format detection is performed.

### Output

The tree example above prints:

```text
offset=0 tag=E1 length=3 value=5A0112
  offset=2 tag=5A length=1 value=12
```

Offsets are decimal, zero-based absolute positions of tags in the original
input. Tags and values are uppercase hexadecimal in wire order. Lengths are
decimal value byte counts. Constructed values include their encoded children.
Indefinite BER additionally prints `encoding=indefinite`; its resolved value
length and value exclude the enclosing EOC. EOC is never a separate element.

By default, `dump` prints top-level elements only. `--tree` prints nested
BER/DER elements with two spaces per level; other formats and `validate`
reject this option. Both dump modes still check nested BER/DER structure.
Output is deterministic text for inspection, not a versioned serialization
format. A malformed input may produce a partial dump before failure.

### Graphical trees and colors

`--pretty` implies `--tree` and prints UTF-8 branches (`├──`, `└──`, `│`)
instead of indentation alone. Top-level elements remain separate roots.
The original `--tree` layout remains available.

Tags are cyan when stdout is a supported terminal. Redirected output is
colorless by default. `NO_COLOR` (when present) and `TERM=dumb` disable
automatic color. `--force-color` emits ANSI sequences even when redirected
and overrides those environment settings; `--no-color` always disables color.
These two flags cannot be combined. Windows console mode and UTF-8 output
code page are temporarily configured as needed and restored after printing.

### EMV annotations

`dump --format ber --profile emv` appends a readable name for each known tag.
`--describe` additionally prints the dictionary's value representation and
length bounds/step, for example:

```text
offset=0 tag=5A length=1 value=12 name="Primary Account Number (PAN)" description="Decimal digits; dictionary length: 1..10 bytes; step: 1"
```

Annotations use the built-in EMV Contact Book 3 v4.4 dictionary. Common
abbreviations have expanded display labels; other symbolic names are rendered
as words. Descriptions are type and length metadata, not a complete prose
explanation of every EMV data element or a copy of another parser's dictionary.
No value decoding, EMV length enforcement, or transaction validation is added
by these presentation options; raw values remain visible.

Known biometric containers select their specific dictionary contexts during
BER traversal. Unknown tags remain raw and are labelled unknown in the current
context; unknown containers do not cause their descendants to be guessed as
ordinary EMV tags. Primitive BER values remain opaque, including EMV elements
that describe embedded structures. A standalone context-specific fragment has
no enclosing context and begins in the base dictionary.

The EMV profile must be compiled in. `--describe`, `--decode`, `--output`, and
color flags are dump-only options; `--describe` and `--decode` require
`--profile emv`. `--profile emv` itself is also accepted by `validate`, where
it selects EMV schema validation instead of annotating output (see below).
EMV annotations and schema validation both require BER.

### Value decoding

`--decode` additionally decodes each known tag's value through the OpenTLV
codec layer (`tlv/codec/`) and appends it as `decoded="..."`, for example:

```text
offset=0 tag=9F02 length=6 value=000000001000 name="Amount, Authorised" decoded="1000"
```

The raw `value=` field is always present; decoding never replaces it. Only
tags with a dictionary entry and a registered codec are decoded - an unknown
tag, or a known tag whose value kind carries no codec (raw bytes, text, or a
template), is left with no `decoded` field and is not treated as an error. A
value that fails to decode (wrong length, invalid BCD, an undefined enum
value, and so on) instead reports `decode-error="..."`, drawn from the
codec's own diagnostic; the element itself is still printed, and the command
does not fail because of it.

Decoded output favors the codec's own C representation over further
interpretation: numeric fields (including currency amounts, which the codec
returns as unscaled minor units - see `tlv/codec/emv.h`) print as a plain
decimal integer, bit flags print as hexadecimal, dates/times print as
`YYYY-MM-DD`/`HH:MM:SS` (the century of a date is assumed, as the dictionary
value itself does not carry one), and enumerated or composite kinds (account
type, cryptogram information, biometric type, AFL, CVM Results, Track 2) print
a short label or a compact field list. `--decode` cannot be combined with
`--pdol`, since a DOL entry carries a requested length, not a value.

### JSON output

`--output json` prints a single JSON document instead of the key=value text
above: a top-level object with an `elements` array, carrying the same
information under stable field names (`offset`, `tag`, `length`,
`indefinite` when true, `value`, `name`, `description`, `decoded`,
`decode_error`) and, for `--pdol`, (`offset`, `tag`, `requested_length`,
`name`). Fields that do not apply to an element (an unset `--describe`
description, an undecoded value, and so on) are simply omitted rather than
set to `null`. When `--tree` is set, a constructed BER/DER element carries
its children in its own nested `elements` array instead of a flat list, so
the document's shape mirrors the input's structure; without `--tree`, only
top-level elements appear and no element has an `elements` field.
`--pretty`'s graphical tree connectors are a text-mode presentation only and
have no effect on `--output json`. A malformed input may still produce a
document containing the elements parsed before the failure, matching the
partial-output-on-failure behavior described above; the diagnostic itself is
always reported separately, on stderr.

### Encoding

`encode` writes one TLV element with the OpenTLV writer for the format chosen
by `--format`, so the format alone determines the tag and length encoding:

```sh
otlv encode --format ber --tag 9F02 --value 000000001000
```

```text
9F0206000000001000
```

`--format` and `--tag` are required; `--value` is optional and defaults to an
empty value. `--tag` and `--value` use the same hex syntax as `--hex`
(case-insensitive, complete byte pairs, optional whitespace between pairs).
`--value` is limited by `--max-input-size`; a tag longer than the library's
tag capacity is rejected. Output is uppercase hex followed by a newline by
default; `--output-encoding binary` writes the raw encoded bytes with no
newline, including on Windows. Either output can be read back with `otlv dump`
(`--input -`, plus `--input-encoding hex` for the hex form).

The writer validates the tag and length before anything is printed, so a
rejected element produces no output. Malformed hex, unknown or disabled
formats, and options other than `--format`, `--tag`, `--value`,
`--output-encoding`, and `--max-input-size` exit with code 2. An element the
format cannot encode (an invalid BER tag, or a value too long for
`fixed-1byte`) reports `otlv: cannot encode element N: <reason>` and exits
with code 1. Internally, encoding runs over a list of element specs, so
structured multi-element input can be added as another source for that list.

### Tag lookup

`tag` looks up one BER tag in the OpenTLV EMV dictionary, so the CLI can serve
as a quick tag reference. The metadata comes from the profile layer
(`tlv_emv_find` in the base context); the CLI keeps no dictionary of its own.

```sh
otlv tag 9F02 --profile emv
```

```text
Tag:         9F02
Name:        Amount Authorised
Type:        Numeric value (binary or decimal BCD, tag-dependent)
Form:        Primitive
Length:      6
```

The tag is a positional argument in the same hex syntax as `--hex`, and must
be exactly one complete BER tag. `--profile emv` is required. `Length step` is
printed only when the dictionary's permitted lengths advance by more than one
byte (for example the AFL). `--output json` prints one object with `tag`,
`profile`, `known` and, for known tags, `name`, `symbol`, `type`,
`constructed`, `min_length`, `max_length` (omitted when unbounded) and
`length_step`.

A tag with no dictionary entry is a valid result, not malformed data: text
output prints `Result:      Unknown tag in the EMV profile (base context)`,
JSON output has `"known":false`, and the exit code is 0. An invalid or
incomplete tag, an unknown profile, or any option other than `--profile` and
`--output` exits with code 2.

`tags` lists every tag in the dictionary (base context), sorted by tag, when
you do not know which tag to look up:

```sh
otlv tags --profile emv --search amount
```

```text
81      Amount Authorised Binary
9F02    Amount Authorised
9F03    Amount Other
...
```

`--search TEXT` keeps only tags whose displayed name contains `TEXT`
(case-insensitive). `--output json` prints `{"profile":"emv","tags":[...]}`
where each element has the same fields as a known `tag` result. A search with
no matches is not an error: it prints nothing (or an empty array) and exits 0.
`tags` accepts only `--profile`, `--output` and `--search`; `--search` is
rejected by every other command.

### PDOL / DOL inspection

Use `--pdol` to read a raw PDOL value as ordered tag/length pairs:

```sh
otlv dump --format ber --pdol --hex "9F02069F1A02" --profile emv
otlv validate --format ber --pdol --input pdol.hex --input-encoding hex
```

Without annotations, the output is:

```text
offset=0 tag=9F02 requested-length=6
offset=3 tag=9F1A requested-length=2
```

Supply the contents of tag `9F38`, not its enclosing TLV header. Ordinary TLV
dumping still leaves that value opaque. The same pair layout is used by other
EMV DOLs. Tags contain one or two bytes; each requested length is exactly one
unsigned byte (0..255), including `80` and `FF`. No value follows the length.
Order and duplicate tags are preserved. This mode neither constructs terminal
response data nor checks whether the requested lengths match dictionary bounds.

All existing input sources, decoded-input and element-count limits apply.
Empty input succeeds. Missing lengths, malformed tags, and tags longer than
two bytes fail with offsets. `--tree` and `--pretty` are rejected because a DOL
is flat; `--max-depth` has no effect. BER must be enabled; the EMV dictionary
is needed only for optional `--profile emv` annotations.

### EMV schema validation

`validate --format ber --profile emv` additionally checks the parsed input
against `tlv_emv_structure_schema` (see
[EMV structural validation](../profiles/emv/README.md#structural-validation)):
mandatory tags, forbidden/unknown tags, duplicate tags, length bounds, and
required nesting for the FCI Template, Application Template, and GPO
Response Message Template Format 2. It runs only after the input has parsed
as valid BER, only for `validate` (`dump --profile emv` only annotates
tags), and not with `--pdol` (a DOL's tag/length pairs are not a TLV
structure to check against a schema).
A schema violation is reported like any other failure, but prefixed with
`schema` to keep it distinguishable from a format/framing error. A missing
mandatory tag reports the distinct `TLV_ERR_SCHEMA_MISSING`, without a `tag=`
field (its offset is the end of the enclosing element's value, not a tag);
every other violation (a forbidden/unknown/duplicate tag reports
`TLV_ERR_SCHEMA`, a length outside bounds reports `TLV_ERR_INVALID_LENGTH`)
includes the offending tag:

```sh
$ otlv validate --format ber --profile emv --hex "6F00"
otlv: schema TLV_ERR_SCHEMA_MISSING at byte 2: required schema field missing
```

The exit code contract is unchanged (1 for a schema violation, 3 for an
exceeded limit). Unmodeled top-level tags, such as the Read Record Template,
are accepted unchecked; this is not a full EMV transaction or value validator.

### Validation and limits

`validate` is silent on success. Both commands consume all concatenated
elements; empty input succeeds and invalid trailing bytes fail. Default,
fixed-1byte and bluetooth-ltv values are opaque. BER uses constructed-tag recognition; DER uses
the existing structural validator. This does not provide full ASN.1 value
validation or canonical SET/SET OF ordering; EMV structural profile
validation is available via `--profile emv`, above.

| Option | Default | Meaning |
| --- | --- | --- |
| `--max-input-size N` | 16777216 | Maximum decoded input bytes (16 MiB) |
| `--max-depth N` | 64 | Maximum descendant depth; top-level depth is zero |
| `--max-elements N` | 100000 | Maximum visited elements, including hidden descendants |

Limits are inclusive nonnegative decimal integers fitting native `size_t`.
Depth is restricted to 0..64. Zero is a real limit, not an unlimited setting.
Traversal follows library depth semantics: empty constructed values require
no descent. BER indefinite-length resolution also has the library's fixed
64-scope bound. The input is buffered in CLI-owned memory; this does not change
the allocation-free library core. Limits constrain accepted input and traversal;
they are not a wall-clock timeout or incremental streaming interface.

## Diagnostics and exit codes

Command output goes to stdout; diagnostics go to stderr. Library failures
include the symbolic `TLV_ERR_*` name, description, and byte offset, plus the
tag at that offset when one is available. Generic traversal reports the
failing element; errors resolving an indefinite BER container may identify
that container. DER can identify individual failing fields. Offsets do not
promise the exact corrupted byte. A `TLV_ERR_SCHEMA_MISSING` failure (a
missing mandatory tag) never prints a `tag=` field: its offset is the end of
the enclosing element's value, not a tag, and could otherwise coincide with
an unrelated sibling at the enclosing scope. An EMV schema violation
(`validate --profile emv`) is additionally prefixed with `schema` to
distinguish it from a format/framing error.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Invalid TLV data |
| 2 | Invalid command, option, hex input, or unavailable format |
| 3 | I/O failure, allocation failure, or exceeded resource limit |

Encoding, EMV semantic validation, recovery scanning, and prebuilt release
binaries are outside this initial CLI scope.
