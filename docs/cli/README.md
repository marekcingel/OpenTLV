# Command-line tool

The optional `otlv` executable inspects and structurally validates TLV
data, converts it to and from a [versioned JSON document](json-schema.md), and
recovers elements from damaged input, using the public C library through the
`tlv++` wrapper. Building it
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
(header-only, used for JSON output and the JSON document of `decode` and
`encode --input`) via CMake `FetchContent`; the `tlv`
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
otlv decode --format ber --profile emv --input capture.bin > capture.json
otlv encode --format ber --input capture.json --output-encoding binary --output-file out.bin
otlv dump --format ber --input damaged.bin --recover --tree
otlv validate --format ber --profile emv --emv-check dictionary --hex "9F02050000000010"
otlv tag 9F02 --profile emv
otlv query 6F/A5/50 --format ber --input card.bin --value
```

`dump`, `validate` and `decode` require an explicit `--format` and exactly one input
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
no enclosing context and begins in the base dictionary unless you select
another one with `--emv-context NAME` (see [EMV contexts](#emv-contexts)).

The EMV profile must be compiled in. `--describe`, `--decode` and
`--emv-context` are accepted by `dump` and `decode` (and require
`--profile emv`); `--output` and the color flags are dump-only.
`--profile emv` itself is also accepted by `validate`, where it selects EMV
checks instead of annotating output (see below). EMV annotations and checks
both require BER, selected with `--format ber`; the wire format and the
profile are separate options, so `--format der --profile emv` is an error.

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

### JSON export

`decode` parses the input like `dump --tree` and prints it as the
[versioned JSON document](json-schema.md): tags and primitive values as
hexadecimal strings, constructed elements as nested `children` arrays, and for
BER an explicit `length_mode` of `definite` or `indefinite`:

```sh
otlv decode --format ber --hex "E1 05 5A 01 12 5A 00 30 80 04 01 AA 00 00"
```

```json
{"schema":"opentlv.tlv","version":1,"format":"ber","elements":[{"tag":"E1","length_mode":"definite","children":[{"tag":"5A","value":"12"},{"tag":"5A","value":""}]},{"tag":"30","length_mode":"indefinite","children":[{"tag":"04","value":"AA"}]}]}
```

`decode` takes the input, limit and profile options of `dump` (`--format`,
`--input`/`--hex`, `--input-encoding`, `--max-*`, `--profile emv`,
`--describe`, `--decode`, `--emv-context`, `--recover`) and rejects the text
presentation options (`--tree`, `--pretty`, colors, `--output`, `--pdol`).
The whole input is always parsed as a tree, so BER and DER nesting is followed
up to `--max-depth`. A failed export prints nothing on stdout, unlike `dump`,
so a partial document is never mistaken for a complete one. With
`--profile emv` each known element carries its dictionary `name`; unknown tags
carry only their raw `tag` and `value`.

Offsets are not part of the document. Use `dump --output json` when you need
them.

### Encoding

`encode` writes TLV data with the OpenTLV writer for the format chosen by
`--format`, so the format alone determines the tag and length encoding. It has
two input modes: one element from `--tag`/`--value`, or a whole
[JSON document](json-schema.md) from `--input`.

```sh
otlv encode --format ber --tag 9F02 --value 000000001000
otlv encode --format ber --input elements.json
otlv encode --format ber --input - --output-encoding binary --output-file out.bin
```

```text
9F0206000000001000
```

For a single element, `--format` and `--tag` are required; `--value` is
optional and defaults to an empty value. `--tag` and `--value` use the same hex
syntax as `--hex` (case-insensitive, complete byte pairs, optional whitespace
between pairs). `--value` is limited by `--max-input-size`; a tag longer than
8 bytes, the longest tag any built-in format accepts, is rejected.

`--input PATH` reads a JSON document instead (`-` for stdin, read as bytes on
Windows too); it cannot be combined with `--tag` or `--value`. Every length is
derived while encoding, children are written inside their parent, and BER
elements marked `"length_mode":"indefinite"` get the `80` length and the
end-of-contents octets. Before anything is printed the encoded bytes are read
back with the format's reader and checked like `otlv validate` does, so the
output is always accepted by the library reader and structural validator.
`--max-input-size` limits the JSON text and the encoded bytes, `--max-depth`
the nesting of `children` and `--max-elements` the number of elements. Nothing
about the JSON is guessed: a document that does not follow the
[schema](json-schema.md), names another format than `--format`, or needs a
representation the format lacks (children under `default`, indefinite length
under `der`) is rejected. The round trip `decode` then `encode` preserves
element structure and raw primitive values but not the exact bytes of length
fields; see [Round trip](json-schema.md#round-trip).

Output is uppercase hex followed by a newline by default;
`--output-encoding binary` writes the raw encoded bytes with no newline,
including on Windows. `--output-file PATH` writes the result to a file instead
of stdout, and only after the whole document was accepted, so a rejected
document leaves no file behind. Either encoding can be read back with
`otlv dump` (`--input -`, plus `--input-encoding hex` for the hex form).

Nothing is printed for a rejected input. Malformed hex, an invalid JSON
document, unknown or disabled formats, and options `encode` does not take exit
with code 2; `encode` takes `--format`, `--tag`, `--value`, `--input`,
`--output-encoding`, `--output-file`, `--max-input-size`, `--max-depth` and
`--max-elements`. An element the writer rejects (an invalid BER tag, or a value
too long for `fixed-1byte`) reports `otlv: cannot encode element N: <reason>`
and exits with code 1; N counts elements from zero in document order. Exceeded
limits and unreadable or unwritable files exit with code 3.

### Path queries

`query` prints the elements addressed by a path of hexadecimal tags, so a
script can read one value from nested data without post-processing the whole
dump. The path is a positional argument and the input options are the same as
for `dump`.

```sh
otlv query 6F/A5/50 --format ber --input card.bin
otlv query 6F/A5/50 --format ber --input card.bin --value
otlv query 6F/A5/50 --format ber --input card.bin --output json
```

```text
offset=8 tag=50 length=2 value=4142
```

`6F/A5/50` means a top-level `6F`, its direct child `A5` and that element's
direct child `50`. Every element reached this way is printed in document
order; a tag that occurs several times can therefore produce several lines.
Tags are hex in either case, separated by one `/`; spaces, empty steps and a
leading or trailing `/` are usage errors. This first version supports exact tag
paths only, with no wildcards, indexes or recursive search. The syntax and
matching come from the library ([Path queries](../guides/queries.md)), not
from the CLI.

- Text output is one line per match in the format of `dump`, without nesting.
- `--value` prints only the value bytes of each match as one line of hex, an
  empty line for an empty value.
- `--output json` prints `{"matches":[...]}`; each match has `path`, `offset`,
  `tag`, `length` and `value`. It cannot be combined with `--value`.
- A path of more than one tag needs `--format ber` or `--format der`, the
  formats that have nested values; other formats accept one-tag paths.
- The whole input is still parsed, so damaged data after a match fails the
  command with exit code 1, and `--max-depth`, `--max-elements` and
  `--max-input-size` apply as for `dump`.
- No match is reported as `otlv: no match for query ...` with exit code 5, so a
  script can tell a missing element from invalid data.

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

### EMV checks

`validate --profile emv` runs the checks chosen by `--emv-check`, always on
input that has already parsed as valid BER:

| `--emv-check` | Checks | `compact` prefix |
| --- | --- | --- |
| `structure` (default) | The structural schema above. | `schema` |
| `dictionary` | Every element whose tag is in the EMV dictionary, in the context it appears in, has a length the dictionary permits (its bounds and length step). | `dictionary` |
| `all` | `structure`, then `dictionary`; the first failure is reported. | either |

The `compact` prefix distinguishes the two checks on one line; `human` and
`json` do the same with structured detail instead: a structural violation
carries a `path` and, for most kinds, a `field` name, while a dictionary
violation carries a `dictionary` `stage`.

The dictionary check uses the same lookup and contexts as `dump --profile emv`
and the library's `tlv_emv_validate_length`. It reports the first offending
element, labeled `dictionary`, with exit code 1; see
[Diagnostics and exit codes](#diagnostics-and-exit-codes) for the `--diagnostics`
renderers. In `compact` form:

```sh
$ otlv validate --format ber --profile emv --emv-check dictionary --hex "9F02050000000010" --diagnostics compact
otlv: dictionary TLV_ERR_INVALID_LENGTH at byte 0 tag=9F02: invalid length encoding
```

What runs, and what does not:

- Tags with no dictionary entry in their context are **not** errors; they are
  preserved and left unchecked. The dictionary check does not require a tag to
  be known, does not check that mandatory tags are present outside the
  templates the structural schema models, and does not decode or check values
  (BCD digits, dates, enumerations); `--decode` shows those diagnostics
  without failing.
- Children of a container are looked up in that container's context, and
  containers the dictionary does not know contribute no context, so their
  children are unchecked (as they are labelled unknown by `dump`).
- Neither check is an EMV kernel, transaction, or cryptographic validation,
  and cross-tag rules (for example that a tag must agree with another) are out
  of scope.
- `--emv-check` applies to `validate` only, and not with `--pdol`.

### EMV contexts

The dictionary is context dependent: the same tag can mean different things
inside different templates (for example `82` is the 2-byte Application
Interchange Profile at the top level but a 1-byte Biometric Subtype inside a
Biometric Header Template). During a walk the CLI switches context on known
containers such as the Biometric Information Template `7F60`. A fragment cut
out of such a container has no enclosing element to say which context applies,
so select it explicitly with `--emv-context NAME`, for `dump`, `decode` and
`validate --emv-check dictionary`:

| Name | Context |
| --- | --- |
| `base` (default) | Ordinary application data. |
| `bit` | Inside `7F60` (Biometric Information Template). |
| `bht` | Inside `A1` within `7F60` (Biometric Header Template). |
| `bht-format` | Inside a level-2 `A1`/`A2` within the BHT. |
| `bit-group` | Inside `BF4A`/`BF4B` or a terminal group. |
| `biometric-counters` | Inside `BF4C`. |
| `biometric-attempts` | Inside `BF4D`. |
| `biometric-verification` | Inside `BF4E`. |

```sh
otlv dump --format ber --profile emv --emv-context bht --hex "820101"
otlv validate --format ber --profile emv --emv-check dictionary --emv-context bht --hex "82020101"
```

The first prints the element as `Biometric Subtype`; the second fails because
`82` is 1 byte in that context. Contexts never fall back to the base
dictionary. The structural schema models base-context templates only, so
`--emv-check structure` (and `all`) require the base context; use
`--emv-check dictionary` with any other. `--emv-context` requires
`--profile emv` and cannot be combined with `--pdol`.

### Recovery scanning

`dump` and `decode` stop at the first damaged byte by default. With
`--recover` they instead resynchronize and keep going, using the library's
recovery scanner (`tlv_scan`): when the element at the current offset cannot
be read, or its contents are malformed, the scanner looks at each following
offset for the next plausible element, and the bytes in between are skipped.

```sh
$ otlv dump --format ber --hex "5A0112 0000 5A0134" --recover
offset=0 tag=5A length=1 value=12
skipped offset=3 length=2 error=TLV_ERR_INVALID_TAG error-offset=3
offset=5 tag=5A length=1 value=34
otlv: skipped 2 byte(s) at offset 3: TLV_ERR_INVALID_TAG at byte 3: invalid tag
otlv: output is incomplete: recovery skipped 1 range(s), 2 byte(s) in total
$ echo $?
4
```

- **Skipped ranges** are reported where they occur (`skipped offset= length=
  error= error-offset=` lines in `dump` text output), and again on stderr with
  a summary. `error` and `error-offset` describe the first failure that made
  the range unreadable; the offset of that failure can lie inside or after the
  range.
- **Incomplete output.** In `--output json` and in `decode`, the document
  gains `"complete":false` and a `"skipped"` array of objects with `offset`,
  `length`, `error`, `error_offset` and `message`. An undamaged input under
  `--recover` reports `"complete":true` and an empty array. A recovered
  `decode` document is incomplete and is rejected by `encode`.
- **Exit status 4** means recovery skipped data, so the output is incomplete;
  it is distinct from 1 (strict failure). Without `--recover`, or when nothing
  was skipped, the exit codes are unchanged.
- **Offsets** are absolute positions in the input. A recovered element is
  always reported as a top-level element, even when the scanner found it inside
  a damaged constructed element.
- **Limits are not damage.** `--max-input-size`, `--max-depth` and
  `--max-elements` still fail the run with exit code 3, and `--max-elements`
  counts only the elements that were output.
- **Heuristic.** The scanner accepts what looks like a well-formed element
  (syntactic checks only, no dictionary or schema), so a match is not proof of
  an original element boundary; damaged bytes can be mistaken for an element,
  and an element inside a skipped range can be output where a byte-level
  decoder would have skipped it. Treat recovered output as evidence for
  inspection, not as a repaired copy.
- `validate` stays strict and rejects `--recover`, as do `--pdol` and `encode`.
  It is the only command whose exit status certifies that the input is valid.

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

Command output goes to stdout; diagnostics go to stderr. `--diagnostics NAME`
selects how a failure is rendered: `human` (the default), `compact`, or
`json`. All three describe the same underlying detail, collected
independently of how it is presented: the symbolic `TLV_ERR_*` code, a
description, a byte offset, the affected tag when known, and, for a failure
inside a constructed element, the hierarchical path of tags enclosing it
(`dump`, `validate`, `decode` and `query` all track this, not just `dump`).
Offsets do not promise the exact corrupted byte.

`human` prints one field per line:

```sh
$ otlv validate --format ber --profile emv --hex "6F048402AABB"
otlv: error: invalid length encoding

code: TLV_ERR_INVALID_LENGTH
offset: 0x2 (2)
path: 6F
tag: 84
field: df_name
expected length: 5..16
actual length: 2
```

`compact` prints the same detail on one line: this is the CLI's original
wording (`otlv: schema TLV_ERR_INVALID_LENGTH at byte 2 tag=84: invalid
length encoding` for the example above), kept for scripts that scrape
stderr. `json` prints a single-line JSON object with the same fields
(`code`, `message`, `offset`, `tag`, `path`, `field`, and so on), for
scripts that would otherwise have to reparse the human or compact text; a
`--recover` run additionally wraps each skipped range's diagnostic with the
`skipped_offset`/`skipped_length` of the range it recovered from.

A plain wire-level failure (no `--profile emv`) additionally reports which
step failed (`tag`, `length`, `value` or `trailer`) and, for a value or
trailer that does not fit, the declared length versus the bytes actually
available:

```sh
$ otlv validate --format default --hex "0402AA"
otlv: error: buffer too short

code: TLV_ERR_BUFFER_TOO_SHORT
offset: 0x2 (2)
tag: 04
while reading: value
declared length: 2
available: 1
```

This declared-length/available detail comes from re-reading the failing
element on its own once the walk has located it, bounded to the value it
actually sits in (not necessarily the whole input); it is shown whenever
that re-read reproduces the original failure exactly. BER and DER's
constructed-length handling does not currently surface it back through this
path, so a BER/DER value-length overrun shows the step, offset, tag and
path, but not the two length lines above; every other format does.

An EMV schema violation (`validate --profile emv`) additionally carries the
schema field name and the expected-versus-actual detail for the violated
rule (occurrence counts, length bounds, or a primitive/constructed
mismatch), computed directly by the schema check, so it is unaffected by
that BER limitation. A dictionary-length violation (`--emv-check
dictionary`) is labeled `dictionary` (see [EMV checks](#emv-checks)) and
similarly reports the permitted-versus-actual length and the dictionary
field name. `TLV_ERR_SCHEMA_MISSING` (a missing mandatory tag) reports the
tag that is absent and the offset of its enclosing element — both borrowed
from the schema itself, and so reliable — since the missing tag itself has
no position of its own.

Formatting is presentation only, layered on top of the library's structured
diagnostics; see [Diagnostics](../guides/diagnostics.md) for the underlying
model.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Invalid TLV data, or an element `encode` cannot write |
| 2 | Invalid command, option, hex input, JSON document, or unavailable format |
| 3 | I/O failure, allocation failure, or exceeded resource limit |
| 4 | `--recover` skipped damaged data: the output is incomplete |
| 5 | `query` matched no element |

Automatic format detection, custom text input syntax, full ASN.1 value
validation, EMV kernel behavior, and prebuilt release binaries are outside the
scope of the CLI.
