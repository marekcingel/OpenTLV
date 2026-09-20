# WebAssembly build (experimental)

The optional `OPENTLV_BUILD_WASM` build compiles the OpenTLV C core to
WebAssembly with [Emscripten](https://emscripten.org/), so browser tooling runs
the same parser as native applications. It defaults to `OFF` and adds nothing
to normal C and C++ builds.

The first interface is intentionally small: it parses a byte buffer and returns
the element structure or the parser error. It wraps the existing C API in
`bindings/wasm/src/opentlv_wasm.c`; no parsing logic is duplicated. Editing, schemas,
schemas and OTDL are not exposed; the EMV dictionary is available as an annotation profile (below).

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
| `opentlv-core.js` | Generated Emscripten ES module loader |
| `opentlv-core.wasm` | The compiled OpenTLV core |

Serve the three files from the same directory. With the same Emscripten version
and configuration the artifacts are byte-for-byte identical; CI builds twice
and compares them. Format options such as `OPENTLV_FORMAT_BER` apply as in
native builds, and a compiled-out format is rejected as an invalid argument.

## Use from JavaScript

```js
import { loadOpenTLV, hexToBytes } from "./opentlv.mjs";

const opentlv = await loadOpenTLV();
const result = opentlv.parse(
  hexToBytes("6F 0A 84 03 41 42 43 A5 03 50 01 01"),
  { format: "ber" },
);
```

`parse` takes a `Uint8Array`, a `format` (`default`, `fixed-1byte`, `ber` or
`der`; default `default`) and optionally a `profile` (`none` or `emv`; default
`none`) and returns:

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

Tags and values are uppercase hexadecimal. Only BER and DER elements can be
constructed; the other formats return flat elements with opaque values. An
element occupies `headerSize + length` encoded bytes from `offset`, the first
bytes being its encoded `tag`; a constructed element's value is the byte range
its `children` cover.

With `profile: "emv"` (BER only; other formats report an invalid-argument
error) the result also has `"profile": "emv"`. Every element the
[EMV dictionary](../profiles/emv/README.md) knows carries `symbol` (the
dictionary name), `name` (a display name) and `lengthValid` (whether `length`
is permitted for the tag); other elements carry none of these.

Invalid input does not throw. The result carries an `error` object with the
numeric `code` of `tlv_result_t`, its `message` and the input `offset`, together
with every element read before the failure:

```json
{ "format": "default", "elements": [ ... ],
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
