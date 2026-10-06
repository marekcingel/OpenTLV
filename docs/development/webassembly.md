# WebAssembly build (experimental)

The optional `OPENTLV_BUILD_WASM` build compiles the OpenTLV C core to
WebAssembly with [Emscripten](https://emscripten.org/), so browser tooling runs
the same parser as native applications. It defaults to `OFF` and adds nothing
to normal C and C++ builds.

The first interface is intentionally small: it parses a byte buffer and returns
the element structure or the parser error. It wraps the existing C API in
`bindings/wasm/src/opentlv_wasm.c`; no parsing logic is duplicated. Editing,
schemas and OTLV are not exposed; the EMV dictionary is available as an annotation module (below).
Unlike a general-purpose binding, it does not follow the Reader/Writer/Element
shape of the [language bindings conceptual model](../concepts/bindings.md); see
that page for why.

## Build

Install and activate an Emscripten SDK (CI pins the version set in
`.github/workflows/wasm.yml`), then:

```sh
emcmake cmake -S . -B build-wasm -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOPENTLV_BUILD_WASM=ON -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF \
  -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF
cmake --build build-wasm --target opentlv-wasm
```

The artifacts are written to `build-wasm/bindings/wasm/dist/`:

| File | Purpose |
| --- | --- |
| `opentlv.mjs` | JavaScript entry point (`loadOpenTLV`, `hexToBytes`) |
| `query.mjs` | Owning compiled Query and checked Document facade |
| `opentlv-core.js` | Generated Emscripten ES module loader |
| `opentlv-core.wasm` | The compiled OpenTLV core |

Serve these files from the same directory. With the same Emscripten version
and configuration the artifacts are byte-for-byte identical; CI builds twice
and compares them. Format options such as `OPENTLV_FORMAT_BER` apply as in
native builds, and a compiled-out format is rejected as an invalid argument.

## Use from JavaScript

### Compiled Query and Document

`loadOpenTLV()` also provides `compileQuery(text, options)`, `loadQuery(image,
options)` and `document(input, options)`. Compilation and evaluation delegate to
the native C engine. Query formats currently support `ber`, `der` and `cer`;
disabled components are rejected. Arbitrary callback providers and schema-aware
Query edits remain unavailable.

Programs expose `info`, `format()`, `explain()`, `image()`, `evaluate(input)` and
`execution(limits)`. Declare `variables: { name: "integer" | "bytes" | "string" }`
at compilation; bind values with `execution.bind(name, value)` or the `bindings`
option of `evaluate`. Integer inputs accept safe JS integers or signed 64-bit
`bigint`; results outside the safe integer range return `bigint`. Named Tags can
be supplied as `names: { symbol: Uint8Array }`.

An execution owns its native workspace. `setInput(input, { discard, final })`
copies and retains input windows until `reset()` or `close()`; original source
offsets survive legal continuation. `next()` returns a copied match or `null`
at final exhaustion; needing input raises `QueryError` with the native status.
`visit(callback)` stops when the callback returns `false` and resumes on the next
call. Callback exceptions invalidate the execution until reset; reentrant calls
on that execution are rejected. Scalars use `finish()` then `result()`; `info`
reports native validation and resource coverage. Explicit limits include
`max_depth`, `max_nodes` and `max_work`.

`evaluateDocument(document, { value_capacity })` evaluates the canonical Document
backend. Results are checked Nodes with `tag`, `value`, `constructed`,
`firstChild`, `next`, `parent`, `setValue(bytes)` and `erase()`. Constructed Nodes
return `null` for `value`. Document edits invalidate previous Query selections;
erased and closed handles raise `QueryError`. Call `close()` on executions,
programs and Documents for deterministic release. Native executions retain their
program and Document owners, while the public facade rejects access after a
Document is closed.

### Parse tooling

```js
import { loadOpenTLV, hexToBytes } from "./opentlv.mjs";

const opentlv = await loadOpenTLV();
const result = opentlv.parse(
  hexToBytes("6F 0A 84 03 41 42 43 A5 03 50 01 01"),
  { format: "ber" },
);
```

`parse` takes a `Uint8Array`, a `format` (`fixed`, `bluetooth-ltv`, `bluetooth-ad`,
`ber`, `der`, `cer` or `emv`; default `ber`) and optionally a `module` (`none` or `emv`; default
`none`) and returns:

Bluetooth modes annotate known AD Types with `name` from the C registry.
`bluetooth-ltv` keeps strict element framing. `bluetooth-ad` adds Advertising
Data container semantics: validated trailing zeros are reported separately as
`padding: { offset, length }`. Nonzero padding is an error at its original
source offset. Neither mode validates schemas or decodes value payloads.

For `format: "fixed"`, `fixedTagSize` (default `1`), `fixedLengthSize` (1-8, default
`1`) and `fixedByteOrder` (`"big"` or `"little"`, default `"big"`) configure the
configurable fixed-width format's tag width, length width and length byte order
(`tlv_fixed_format_t`). `fixedElementOrder` selects `"tlv"` (default) or `"ltv"`;
`fixedLengthScope` selects `"value"` (default) or `"tag-and-value"`.
These options apply only to Fixed. Invalid JavaScript configuration values throw
`TypeError`; invalid encoded input is reported through `result.error`.
`opentlv.formats` and `opentlv.modules` list the modes supported by the loaded build.

```json
{
  "format": "ber",
  "elements": [
    {
      "offset": 0, "depth": 0, "tag": "6F", "length": 10, "headerSize": 2, "constructed": true,
      "children": [
        { "offset": 2, "depth": 1, "tag": "84", "length": 3, "headerSize": 2, "constructed": false, "value": "414243" },
        { "offset": 7, "depth": 1, "tag": "A5", "length": 3, "headerSize": 2, "constructed": true,
          "children": [
            { "offset": 9, "depth": 2, "tag": "50", "length": 1, "headerSize": 2, "constructed": false, "value": "01" }
          ] }
      ]
    }
  ]
}
```

Tags and values are uppercase hexadecimal. Only BER, DER, CER and EMV elements can be
constructed; the other formats return flat elements with opaque values. An
element occupies `encodedSize` bytes from `offset`, including any trailer.
`source` contains absolute `{offset, length}` ranges for `header`, `tag`,
`length`, `value` and `trailer`; empty regions have length zero. The logical
Value excludes the enclosing trailer. Field order comes from these ranges,
so LTV and BER end-of-contents need no byte-layout guessing in the viewer.
The JSON example above omits `encodedSize` and `source` for brevity.

`format: "cer"` uses the generic tree visitor with `tlv_format_cer`, preserving
preorder output and EOC source ranges. It checks framing only; full CER
validation (including string segmentation and semantic values) is not applied.

With `module: "emv"` (BER or EMV framing; other formats report an invalid-argument
error) the result also has `"module": "emv"`. Every element the
[EMV dictionary](../standards/emv/README.md) knows carries `symbol` (the
dictionary name), `name` (a display name) and `lengthValid` (whether `length`
is permitted for the tag); other elements carry none of these.

Invalid input does not throw. The result carries an `error` object with the
numeric `code` of `tlv_result_t`, its `message` and the input `offset`, together
with every element read before the failure:

```json
{ "format": "ber", "elements": [ ... ],
  "error": { "code": 1, "message": "buffer too short", "offset": 5 } }
```

`parse` throws only for programming errors (a non-`Uint8Array` argument) or
when memory runs out. Input is processed entirely in the browser. A single
call reads at most 65,536 elements and 64 levels of nesting.

## Documentation playground

The [TLV playground](../playground/index.md) in the documentation site is built
on this module: `docs/playground/playground.js` calls `parse` once and renders
the result as tree, hex and JSON views, with no parsing logic of its own; the
JSON view serializes the parse result itself. The Documentation workflow builds the
module and `tools/docs/hooks.py` publishes it as `playground/wasm/`. To try it
locally, build the module as above and run `mkdocs serve`; use
`OPENTLV_WASM_DIR` if the build directory is not `build-wasm`. Without the
module the site still builds and the playground page says it is unavailable.

## Testing

`bindings/wasm/test/smoke.mjs` runs the module in Node.js and is registered with CTest
when `node` is found:

```sh
ctest --test-dir build-wasm -L wasm --output-on-failure
```
