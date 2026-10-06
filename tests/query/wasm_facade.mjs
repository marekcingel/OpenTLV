// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
const { loadOpenTLV, hexToBytes } = await import(pathToFileURL(resolve(process.argv[2], "opentlv.mjs")));
const api = await loadOpenTLV();
const cases = JSON.parse(await readFile(process.argv[3], "utf8"));
const hex = bytes => Buffer.from(bytes).toString("hex");
function scalar(value) {
  if (typeof value === "boolean") return `bool:${Number(value)}`;
  if (typeof value === "number" || typeof value === "bigint") return `int:${value}`;
  if (typeof value === "string") return `string:${hex(new TextEncoder().encode(value))}`;
  return `bytes:${hex(value)}`;
}
let checks = 0;
for (const fixture of cases) {
  const wire = hexToBytes(fixture.wire);
  for (const optimize of [false, true]) {
    const variables = Object.fromEntries(Object.entries(fixture.variables ?? {}).map(([name, value]) =>
      [name, value.type === "int" ? "integer" : value.type]));
    const options = { optimize, variables,
      names: { "fixture:leaf": hexToBytes("5a"), "fixture:container": hexToBytes("70") } };
    let program;
    try { program = api.compileQuery(fixture.query, options); }
    catch (error) {
      assert.ok(fixture.diagnostic, `${fixture.id}: ${error}`);
      assert.equal(error.code, fixture.diagnostic.code, fixture.id);
      assert.equal(error.query.kind, fixture.diagnostic.kind, fixture.id);
      if (fixture.diagnostic.begin !== undefined) {
        assert.equal(error.query.begin, fixture.diagnostic.begin, fixture.id);
        assert.equal(error.query.end, fixture.diagnostic.end, fixture.id);
      }
      checks += 1;
      continue;
    }
    assert.equal(fixture.diagnostic, undefined, fixture.id);
    const execution = retained => {
      const query = program.execution({ retained });
      for (const [name, value] of Object.entries(fixture.variables ?? {})) {
        query.bind(name, value.type === "bytes" ? hexToBytes(value.value) : value.value);
      }
      return query;
    };
    const verify = (query, matches) => {
      const actual = program.info.result_kind ? scalar(query.result()) : matches;
      assert.deepEqual(actual, fixture.matches, fixture.id);
      checks += 1;
    };
    try {
      if (program.info.level !== 3) {
        for (const retained of [true, false]) {
          if (!retained && program.info.level > 1) continue;
          for (let split = 0; split <= wire.length; split += 1) {
            const query = execution(retained);
            try {
              const matches = [];
              query.setInput(wire.subarray(0, split), { final: false });
              assert.throws(() => query.visit(match => { matches.push(match.offset); }), error => error.code === 18, fixture.id);
              query.setInput(wire);
              query.visit(match => { matches.push(match.offset); });
              verify(query, matches);
            } finally { query.close(); }
          }
        }
      }
      if (!fixture.query.includes("@offset") && !fixture.query.includes("@hlen")) {
        const document = api.document(wire);
        const query = execution(true);
        try {
          const offsets = new Map(), stack = [];
          let node = document.first;
          while (node !== null) {
            offsets.set(node.identity, fixture.offsets[offsets.size]);
            if (node.next !== null) stack.push(node.next);
            node = node.firstChild;
            if (node === null && stack.length) node = stack.pop();
          }
          query.evaluateDocument(document);
          verify(query, program.info.result_kind ? [] : [...query].map(node => offsets.get(node.identity)));
        } finally { query.close(); document.close(); }
      }
    } finally { program.close(); }
  }
}
// Image ownership, continuation, callback failure and stale Document results.
const program = api.compileQuery("//5A");
const loaded = api.loadQuery(program.image());
assert.deepEqual(loaded.evaluate(hexToBytes("5a0101")).map(match => match.offset), [0]);
assert.throws(() => api.loadQuery(program.image().subarray(1)));
const query = loaded.execution({ retained: false });
query.setInput(hexToBytes("5a0101"), { final: false });
const first = query.next();
assert.throws(() => query.next(), error => error.code === 18);
query.setInput(hexToBytes("5a01015a0102"));
query.visit(match => {
  assert.equal(match.offset, 3);
  assert.throws(() => query.close(), error => error.code === 10);
  assert.throws(() => query.reset(), error => error.code === 10);
  return false;
});
assert.equal(query.next(), null);
query.reset().setInput(hexToBytes("5a00"));
const failure = new Error("callback failure");
assert.throws(() => query.visit(() => { throw failure; }), error => error === failure);
assert.throws(() => query.next(), error => error.code === 10);
query.reset().setInput(hexToBytes("5a005a"));
assert.equal(query.exists({ early_return: true }), true);
assert.equal(query.info.full_validation, 0);
assert.throws(() => query.exists(), error => error.code === 1);
assert.deepEqual(first.value, hexToBytes("01"));
program.close(); loaded.close(); query.close();
const selected = api.compileQuery("//5A/preceding-sibling::*");
const document = api.document(hexToBytes("70065a01015a0102"));
const selection = selected.execution().evaluateDocument(document);
const node = selection.next();
assert.deepEqual(node.value, hexToBytes("01"));
node.setValue(hexToBytes("07"));
assert.throws(() => selection.next(), error => error.code === 10);
selection.reset().evaluateDocument(document);
assert.deepEqual(selection.next().value, hexToBytes("07"));
document.close();
assert.throws(() => selection.next(), error => error.code === 10);
selection.reset(); selection.close(); selected.close();
console.log(`JS/WASM public Query facade: ${cases.length} fixtures, ${checks} backend/window checks passed`);

const metadataSeen = [];
const providers = { num: { id: 101, decode(value, metadata) {
  metadataSeen.push(metadata);
  return BigInt(value[0]) * -10n;
} } };
const custom = api.compileQuery("num(//5A)", { providers });
assert.equal(custom.evaluate(hexToBytes("5a0103")), -30);
assert.equal(metadataSeen.at(-1).offset, 0);
const customImage = custom.image();
assert.throws(() => api.QueryProgram.load(customImage), error => error.code === 10);
const customLoaded = api.QueryProgram.load(customImage, { providers });
assert.equal(customLoaded.evaluate(hexToBytes("5a0104")), -40);
const ongoing = custom.execution().setInput(hexToBytes("5a0105"));
custom.close();
ongoing.finish();
assert.equal(ongoing.result(), -50);
ongoing.close(); customLoaded.close();
const textProvider = api.compileQuery("text(//5A)", { providers: {
  text: { id: 102, max_result_bytes: 3, decode: () => "a\0b" },
} });
assert.equal(textProvider.evaluate(hexToBytes("5a00")), "a\0b");
textProvider.close();
const shortProvider = api.compileQuery("text(//5A)", { providers: {
  text: { id: 102, max_result_bytes: 2, decode: () => "a\0b" },
} });
assert.throws(() => shortProvider.evaluate(hexToBytes("5a00")), error => error.query.codec === 2);
shortProvider.close();
let active;
const reentrant = api.compileQuery("num(//5A)", { providers: {
  num: { id: 103, decode: () => { active.reset(); return 1; } },
} });
active = reentrant.execution().setInput(hexToBytes("5a00"));
assert.throws(() => active.finish(), error => error.code === 10);
active.reset(); active.close(); reentrant.close();
const exceptional = api.compileQuery("num(//5A)", { providers: {
  num: { id: 104, decode: () => { throw null; } },
} });
assert.throws(() => exceptional.evaluate(hexToBytes("5a00")), error => error === null);
exceptional.close();
console.log("JS/WASM custom providers: lifetime, image compatibility, bounded results and callback failures passed");
const feedProgram = api.compileQuery("//5A");
const feedExecution = feedProgram.execution({ retained: false });
assert.equal(feedExecution.feed({ kind: "element", tag: hexToBytes("5a"), value: hexToBytes("01") }).offset, 0);
assert.throws(() => feedExecution.setInput(hexToBytes("5a00")), error => error.code === 10);
feedExecution.finish();
assert.equal(feedExecution.info.full_validation, 1);
feedExecution.reset();
assert.throws(() => feedExecution.feed({ kind: "end" }), error => error.query.kind === 5);
assert.equal(feedExecution.info.invalid, 1);
feedExecution.reset(); feedExecution.close();
const retainedFeed = feedProgram.execution();
assert.equal(retainedFeed.feed({ kind: "element", tag: hexToBytes("5a"), offset: 7 }), null);
retainedFeed.finish();
assert.equal(retainedFeed.next().offset, 7);
assert.equal(retainedFeed.next(), null);
retainedFeed.close(); feedProgram.close();
console.log("JS/WASM event feeds: immediate/retained publication, malformed events and reset passed");
const editingDocument = api.document(hexToBytes("70065a01015a01025a0103"));
const editingProgram = api.compileQuery("//5A");
const editing = editingProgram.execution().evaluateDocument(editingDocument);
assert.throws(() => editing.editDocument("replace", { value: hexToBytes("09"), target_capacity: 2 }),
  error => error.code === 1 && error.applied === 0);
assert.deepEqual(editingDocument.first.firstChild.value, hexToBytes("01"));
assert.equal(editing.editDocument("replace", { value: hexToBytes("09"), target_capacity: 3 }), 3);
assert.throws(() => editing.next(), error => error.code === 10);
editing.reset().evaluateDocument(editingDocument);
assert.equal(editing.editDocument("insert_after", { tag: hexToBytes("5b"), value: hexToBytes("04") }), 3);
const ancestorProgram = api.compileQuery("//70 | //5A");
const ancestors = ancestorProgram.execution().evaluateDocument(editingDocument);
assert.equal(ancestors.editDocument("remove"), 2);
assert.deepEqual(editingDocument.first.tag, hexToBytes("5b"));
assert.equal(editingDocument.first.next, null);
ancestors.close(); ancestorProgram.close(); editing.close(); editingProgram.close(); editingDocument.close();
console.log("JS/WASM completed-selection edits: short-capacity retry, replacement, insertion and ancestor dominance passed");
