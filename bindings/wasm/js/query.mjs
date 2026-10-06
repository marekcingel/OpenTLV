// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
// Ownership and transfer only. The C engine owns all Query semantics.
export function queryFacade(wasm) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const types = Object.freeze({ integer: 2, bytes: 3, string: 4 });
  class QueryError extends Error {
    constructor(code, query = {}) {
      super(`OpenTLV Query status ${code}`);
      this.code = code;
      this.query = Object.freeze(query);
    }
  }
  function check(code) { if (code) throw new QueryError(code); }
  function response(pointer) {
    if (!pointer) throw new QueryError(4);
    const reply = JSON.parse(wasm.UTF8ToString(pointer));
    if (reply.code) throw new QueryError(reply.code, reply.query);
    return reply;
  }
  function bytes(value) {
    if (!(value instanceof Uint8Array)) throw new TypeError("Uint8Array required");
    return value;
  }
  function unhex(value) {
    return Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair, 16));
  }
  function size(value) {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new RangeError("nonnegative wasm32 size required");
    }
    return value;
  }
  function string(value) {
    if (typeof value !== "string" || value.includes("\0")) throw new TypeError("NUL-free string required");
    return encoder.encode(value + "\0");
  }
  function temporary(data, run) {
    const pointer = wasm._opentlv_wasm_alloc(data.length);
    if (!pointer) throw new QueryError(4);
    try { wasm.HEAPU8.set(data, pointer); return run(pointer); }
    finally { wasm._opentlv_wasm_free(pointer); }
  }
  function scalar(reply) {
    if (reply.kind === 1) return reply.value;
    if (reply.kind === 2) {
      const value = BigInt(reply.value);
      return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(value) : value;
    }
    if (reply.kind === 3) return unhex(reply.value);
    if (reply.kind === 4) return decoder.decode(unhex(reply.value));
    throw new TypeError("scalar Query required");
  }
  class QueryProgram {
    constructor(text, options = {}, image = false) {
      if (!image && typeof text !== "string") throw new TypeError("Query text must be string");
      const data = image ? bytes(text) : encoder.encode(text);
      this._pointer = temporary(string(options.format ?? "ber"), name => wasm._opentlv_wasm_program_new(name));
      if (!this._pointer) throw new QueryError(15);
      try {
        const optionNames = ["optimize", "max_text", "max_tokens", "max_nesting", "max_states", "max_pattern", "max_resolved_tag"];
        for (const [key, value] of Object.entries(options)) {
          if (["format", "variables", "names"].includes(key)) continue;
          const index = optionNames.indexOf(key);
          if (index < 0) throw new TypeError(`unknown compile option: ${key}`);
          check(wasm._opentlv_wasm_program_option(this._pointer, index, index ? size(value) : Number(Boolean(value))));
        }
        for (const [name, type] of Object.entries(options.variables ?? {})) {
          if (!Object.hasOwn(types, type)) throw new TypeError("integer, bytes or string declaration required");
          temporary(string(name), pointer => check(wasm._opentlv_wasm_program_variable(this._pointer, pointer, types[type])));
        }
        for (const [name, tag] of Object.entries(options.names ?? {})) {
          temporary(string(name), pointer => temporary(bytes(tag), dataPointer =>
            check(wasm._opentlv_wasm_program_name(this._pointer, pointer, dataPointer, tag.length))));
        }
        this.info = Object.freeze(temporary(data, pointer =>
          response(wasm._opentlv_wasm_program_compile(this._pointer, pointer, data.length, Number(image))).info));
        this.variables = Object.freeze({ ...(options.variables ?? {}) });
      } catch (error) { this.close(); throw error; }
    }
    static load(image, options = {}) { return new QueryProgram(image, options, true); }
    _check() { if (!this._pointer) throw new QueryError(10); }
    close() {
      if (this._pointer) wasm._opentlv_wasm_program_free(this._pointer);
      this._pointer = 0;
    }
    format() { this._check(); return response(wasm._opentlv_wasm_program_render(this._pointer, 0)).value; }
    explain() { this._check(); return response(wasm._opentlv_wasm_program_render(this._pointer, 1)).value; }
    image() {
      this._check();
      const pointer = wasm._opentlv_wasm_program_image(this._pointer);
      const length = wasm._opentlv_wasm_program_image_size(this._pointer);
      return wasm.HEAPU8.slice(pointer, pointer + length);
    }
    execution(options = {}) { this._check(); return new QueryExecution(this, options); }
    evaluate(input, { bindings = {}, ...limits } = {}) {
      const execution = this.execution(limits);
      try {
        for (const [name, value] of Object.entries(bindings)) execution.bind(name, value);
        execution.setInput(input);
        if (this.info.result_kind) { execution.finish(); return execution.result(); }
        const matches = [];
        execution.visit(match => { matches.push(match); });
        return matches;
      } finally { execution.close(); }
    }
  }
  class QueryExecution {
    constructor(program, { max_depth = 64, max_nodes = 1024, max_work = 100000000, retained = true } = {}) {
      this._program = program;
      this._pointer = wasm._opentlv_wasm_execution_new(program._pointer,
        size(max_depth), size(max_nodes), size(max_work), Number(Boolean(retained)));
      if (!this._pointer) response(wasm._opentlv_wasm_program_render(program._pointer, -1));
      this._busy = false;
      this._invalid = false;
      this._document = null;
    }
    _check(allowInvalid = false) {
      if (!this._pointer || this._busy || (!allowInvalid && this._invalid)) throw new QueryError(10);
      if (!allowInvalid && this._document) this._document._check();
    }
    _operation(operation, argument = 0) {
      this._check();
      return response(wasm._opentlv_wasm_execution_operation(this._pointer, operation, size(argument)));
    }
    close() {
      if (this._busy) throw new QueryError(10);
      if (this._pointer) wasm._opentlv_wasm_execution_free(this._pointer);
      this._pointer = 0; this._document = null;
    }
    reset() {
      this._check(true);
      response(wasm._opentlv_wasm_execution_operation(this._pointer, 0, 0));
      this._invalid = false; this._document = null;
      return this;
    }
    setInput(input, { discard = 0, final = true } = {}) {
      this._check(); bytes(input);
      temporary(input, pointer => response(wasm._opentlv_wasm_execution_input(this._pointer,
        pointer, input.length, size(discard), Number(Boolean(final)))));
      return this;
    }
    bind(name, value) {
      this._check();
      const type = this._program.variables[name];
      let integer = "0", data = new Uint8Array();
      if (type === "integer") {
        if (typeof value !== "bigint" && !Number.isSafeInteger(value)) throw new RangeError("safe integer or bigint required");
        const number = BigInt(value);
        if (number < -(1n << 63n) || number >= (1n << 63n)) throw new RangeError("int64 required");
        integer = String(number);
      } else if (type === "bytes") data = bytes(value);
      else if (type === "string") {
        if (typeof value !== "string") throw new TypeError("string binding required");
        data = encoder.encode(value);
      } else throw new TypeError("declared variable required");
      temporary(string(name), namePointer => temporary(string(integer), integerPointer => temporary(data, dataPointer =>
        response(wasm._opentlv_wasm_execution_bind(this._pointer, namePointer, types[type], integerPointer, dataPointer, data.length)))));
      return this;
    }
    context(ordinal) { this._operation(5, ordinal); return this; }
    pruning(enabled = true) { this._operation(6, Number(Boolean(enabled))); return this; }
    get info() { return Object.freeze(this._operation(3).value); }
    exists({ early_return = false } = {}) { return this._operation(4, Number(Boolean(early_return))).value; }
    finish() { this._operation(7); return this; }
    result() { return scalar(this._operation(2)); }
    next() {
      try {
        const value = this._operation(1).value;
        if (this._document) return new Node(this._document, value);
        return Object.freeze({ offset: value.offset, depth: value.depth, constructed: value.kind === 0,
          tag: unhex(value.tag), value: unhex(value.bytes) });
      } catch (error) { if (error.code === 5) return null; throw error; }
    }
    visit(callback) {
      this._check();
      if (typeof callback !== "function") throw new TypeError("callback required");
      if (this._program.info.result_kind) { this.finish(); return; }
      for (;;) {
        const match = this.next();
        if (match === null) return;
        this._busy = true;
        let action;
        try { action = callback(match); }
        catch (error) { this._invalid = true; throw error; }
        finally { this._busy = false; }
        if (action === false) return;
      }
    }
    evaluateDocument(document, { value_capacity = document._inputSize } = {}) {
      this._check();
      if (!(document instanceof Document)) throw new TypeError("Document required");
      document._check();
      response(wasm._opentlv_wasm_execution_document(this._pointer, document._pointer, size(value_capacity)));
      this._document = document;
      return this;
    }
    *[Symbol.iterator]() { for (let node = this.next(); node !== null; node = this.next()) yield node; }
  }
  class Document {
    constructor(input, { format = "ber" } = {}) {
      bytes(input);
      const program = new QueryProgram("//*", { format });
      try {
        this._pointer = temporary(input, pointer => wasm._opentlv_wasm_document_new(program._pointer, pointer, input.length));
        if (!this._pointer) response(wasm._opentlv_wasm_program_render(program._pointer, -1));
      } finally { program.close(); }
      this._inputSize = input.length;
    }
    _check() { if (!this._pointer) throw new QueryError(10); }
    close() { if (this._pointer) wasm._opentlv_wasm_document_free(this._pointer); this._pointer = 0; }
    _node(node, operation, data = new Uint8Array()) {
      this._check();
      return temporary(string(node?.identity ?? "0"), identity => temporary(data, pointer =>
        response(wasm._opentlv_wasm_document_node(this._pointer, node?._address ?? 0, identity, operation, pointer, data.length)).value));
    }
    get first() { const value = this._node(null, 0); return value ? new Node(this, value) : null; }
  }
  class Node {
    constructor(document, value) { this._document = document; this._address = value.node; this.identity = value.identity; }
    _get(operation) { return this._document._node(this, operation); }
    _navigate(operation) { const value = this._get(operation); return value ? new Node(this._document, value) : null; }
    get tag() { return unhex(this._get(6).tag); }
    get value() { const value = this._get(6); return value.constructed ? null : unhex(value.bytes); }
    get constructed() { return Boolean(this._get(6).constructed); }
    get firstChild() { return this._navigate(1); }
    get next() { return this._navigate(2); }
    get parent() { return this._navigate(3); }
    setValue(value) { this._document._node(this, 4, bytes(value)); }
    erase() { this._get(5); }
  }
  return { QueryProgram, QueryExecution, QueryError, Document, Node,
    compileQuery: (text, options) => new QueryProgram(text, options),
    loadQuery: (image, options) => QueryProgram.load(image, options),
    document: (input, options) => new Document(input, options) };
}
