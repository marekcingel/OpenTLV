// Smoke test for the WebAssembly build: node smoke.mjs <directory with opentlv.mjs>
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { join, resolve } from "node:path";

const dist = resolve(process.argv[2] ?? ".");
const { loadOpenTLV, hexToBytes } = await import(pathToFileURL(join(dist, "opentlv.mjs")).href);
const opentlv = await loadOpenTLV();

assert.match(opentlv.version, /^\d+\.\d+\.\d+/);

// The default format has no constructed tags: one flat element holds the whole value.
const sample = hexToBytes("6F 0A 84 03 41 42 43 A5 03 50 01 01");
let result = opentlv.parse(sample);
assert.equal(result.error, undefined);
assert.deepEqual(
  result.elements.map(({ tag, length, value }) => [tag, length, value]),
  [["6F", 10, "8403414243A503500101"]],
);

// The same bytes as BER: 6F is constructed and nests 84 and A5 (which nests 50).
result = opentlv.parse(sample, { format: "ber" });
assert.equal(result.error, undefined);
const [fci] = result.elements;
assert.equal(fci.tag, "6F");
assert.equal(fci.constructed, true);
assert.deepEqual(
  fci.children.map((child) => [child.tag, child.offset, child.depth]),
  [["84", 2, 1], ["A5", 7, 1]],
);
assert.equal(fci.children[0].value, "414243");
assert.equal(fci.children[1].children[0].tag, "50");
assert.equal(fci.children[1].children[0].value, "01");

// Errors are reported to the caller together with the elements read before them.
result = opentlv.parse(hexToBytes("84 03 41 42 43 84 05 41"), { format: "default" });
assert.equal(result.elements.length, 1);
assert.equal(result.elements[0].tag, "84");
assert.ok(result.error, "truncated input must report an error");
assert.equal(result.error.offset, 5);
assert.equal(typeof result.error.message, "string");
assert.notEqual(result.error.code, 0);

// Unknown formats and bad arguments.
assert.ok(opentlv.parse(sample, { format: "nope" }).error);
assert.deepEqual(opentlv.parse(new Uint8Array(0)).elements, []);
assert.throws(() => opentlv.parse("6F"), TypeError);
assert.throws(() => hexToBytes("6F 0"), TypeError);

// Larger input grows module memory; results must still be correct.
const big = new Uint8Array(20 * 1024 * 1024);
big.set([0x84, 0xff]);
assert.ok(opentlv.parse(big, { format: "ber" }).error);

console.log("opentlv wasm smoke test passed");
