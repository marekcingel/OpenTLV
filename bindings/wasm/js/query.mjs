// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
// Ownership and transfer only. The C engine owns all Query semantics.
export function queryFacade(wasm) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const types = Object.freeze({ integer: 2, bytes: 3, string: 4 });
  class QueryError extends Error {
    constructor(code, query = {}, applied = 0, rule = null, schema = null) {
      super(`OpenTLV Query status ${code}`);
      this.code = code;
      this.query = Object.freeze(query);
      this.applied = applied;
      this.rule = rule;
      this.schema = schema;
    }
  }
  function check(code) { if (code) throw new QueryError(code); }
  function response(pointer) {
    if (!pointer) throw new QueryError(4);
    const reply = JSON.parse(wasm.UTF8ToString(pointer));
    if (reply.code) throw new QueryError(reply.code, reply.query, reply.applied, reply.rule, reply.schema);
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
  function pointers(values) {
    const data = new Uint8Array(values.length * 4);
    const view = new DataView(data.buffer);
    values.forEach((value, index) => view.setUint32(index * 4, value, true));
    return data;
  }
  function temporaries(data, run) {
    const allocated = [];
    try {
      for (const item of data) {
        const pointer = wasm._opentlv_wasm_alloc(item.length);
        if (!pointer) throw new QueryError(4);
        allocated.push(pointer);
        wasm.HEAPU8.set(item, pointer);
      }
      return run(allocated);
    } finally { for (const pointer of allocated) wasm._opentlv_wasm_free(pointer); }
  }
  class QueryProgram {
    constructor(text, options = {}, image = false) {
      if (!image && typeof text !== "string") throw new TypeError("Query text must be string");
      const data = image ? bytes(text) : encoder.encode(text);
      this._pointer = temporary(string(options.format ?? "ber"), name => wasm._opentlv_wasm_program_new(name));
      if (!this._pointer) throw new QueryError(15);
      this._callbacks = [];
      this._references = 1;
      this._providerActive = false;
      this._providerError = null;
      this._providerFailed = false;
      try {
        const optionNames = ["optimize", "max_text", "max_tokens", "max_nesting", "max_states", "max_pattern", "max_resolved_tag"];
        for (const [key, value] of Object.entries(options)) {
          if (["format", "variables", "names", "providers"].includes(key)) continue;
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
        const conversions = { num: 0, bcd: 1, text: 2, date: 3 };
        for (const [name, provider] of Object.entries(options.providers ?? {})) {
          if (!Object.hasOwn(conversions, name) || typeof provider?.decode !== "function" || !size(provider.id)) {
            throw new TypeError("providers require num/bcd/text/date, nonzero uint32 ID and decode callback");
          }
          const capacity = size(provider.max_result_bytes ?? 0);
          const decode = provider.decode;
          const callback = wasm.addFunction((context, event, data, length, scratch, available, result) => {
            this._providerActive = true;
            try {
              const metadata = event ? Object.freeze({
                kind: wasm._opentlv_wasm_provider_event(event, 0),
                depth: wasm._opentlv_wasm_provider_event(event, 1),
                offset: wasm._opentlv_wasm_provider_event(event, 2),
                tag: (() => {
                  const start = wasm._opentlv_wasm_provider_event(event, 3);
                  return wasm.HEAPU8.slice(start, start + wasm._opentlv_wasm_provider_event(event, 4));
                })(),
                value: (() => {
                  const start = wasm._opentlv_wasm_provider_event(event, 5);
                  return wasm.HEAPU8.slice(start, start + wasm._opentlv_wasm_provider_event(event, 6));
                })(),
              }) : null;
              const value = decode(wasm.HEAPU8.slice(data, data + length), metadata);
              if (name === "text") {
                if (typeof value !== "string") throw new TypeError("text provider must return string");
                const output = encoder.encode(value);
                if (output.length > available) return 2;
                wasm.HEAPU8.set(output, scratch);
                wasm._opentlv_wasm_provider_text(result, scratch, output.length);
              } else {
                if (typeof value !== "bigint" && !Number.isSafeInteger(value)) throw new TypeError("integer provider must return safe integer or bigint");
                const integer = BigInt(value);
                if (integer < -(1n << 63n) || integer >= (1n << 63n)) throw new RangeError("int64 required");
                wasm._opentlv_wasm_provider_integer(result, Number(BigInt.asUintN(32, integer)),
                  Number(BigInt.asUintN(32, integer >> 32n)));
              }
              return 0;
            } catch (error) { this._providerError = error; this._providerFailed = true; return 3; }
            finally { this._providerActive = false; }
          }, "iiiiiiii");
          this._callbacks.push(callback);
          check(wasm._opentlv_wasm_program_provider(this._pointer, conversions[name], provider.id, capacity, callback));
        }
        this.info = Object.freeze(temporary(data, pointer =>
          response(wasm._opentlv_wasm_program_compile(this._pointer, pointer, data.length, Number(image))).info));
        this.variables = Object.freeze({ ...(options.variables ?? {}) });
      } catch (error) { this.close(); throw error; }
    }
    static load(image, options = {}) { return new QueryProgram(image, options, true); }
    _check() { if (!this._pointer || this._providerActive) throw new QueryError(10); }
    _release() {
      if (--this._references === 0) {
        for (const callback of this._callbacks) wasm.removeFunction(callback);
        this._callbacks = [];
      }
    }
    close() {
      if (this._providerActive) throw new QueryError(10);
      if (this._pointer) { wasm._opentlv_wasm_program_free(this._pointer); this._release(); }
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
  class QuerySchema {
    constructor(rules, { format = "ber" } = {}) {
      this._programs = [];
      this._pointers = [];
      this._names = [];
      this._busy = false;
      this._owner = new QueryProgram("//*", { format });
      this._closed = false;
      try {
        for (const { context, assertion, name = "" } of rules) {
          for (const program of [context, assertion]) {
            if (!(program instanceof QueryProgram)) throw new TypeError("compiled context and assertion required");
            program._check();
            wasm._opentlv_wasm_program_retain(program._pointer);
            ++program._references;
            this._programs.push(program);
            this._pointers.push(program._pointer);
          }
          this._names.push(string(name));
        }
      } catch (error) { this.close(); throw error; }
    }
    close() {
      if (this._busy) throw new QueryError(10);
      if (this._closed) return;
      this._pointers.forEach((pointer, index) => {
        wasm._opentlv_wasm_program_free(pointer);
        this._programs[index]._release();
      });
      this._pointers = []; this._programs = []; this._owner.close(); this._closed = true;
    }
    _validate(input, document, { max_depth = 64, max_nodes = 1024, max_work = 100000000,
      max_contexts = max_nodes, value_capacity = null } = {}) {
      if (this._closed || this._busy || this._programs.some(program => program._providerActive)) throw new QueryError(10);
      if (document) document._check();
      bytes(input);
      this._busy = true;
      try {
        if (document) ++document._active;
        return temporaries(this._names, names => temporary(pointers(names), namePointer =>
          temporary(pointers(this._pointers), programPointer => temporary(input, dataPointer =>
            response(wasm._opentlv_wasm_schema_validate(this._owner._pointer, programPointer,
              namePointer, this._names.length, document?._pointer ?? 0, dataPointer, input.length,
              size(max_depth), size(max_nodes), size(max_work), size(max_contexts),
              value_capacity === null ? 0 : size(value_capacity), Number(value_capacity === null)))))));
      } finally {
        this._busy = false;
        if (document) --document._active;
        for (const program of this._programs) {
          if (program._providerFailed) {
            const error = program._providerError;
            program._providerFailed = false; program._providerError = null;
            throw error;
          }
        }
      }
    }
    validateBuffer(input, options) { this._validate(input, null, options); }
    validateDocument(document, options) {
      if (!(document instanceof Document)) throw new TypeError("Document required");
      this._validate(new Uint8Array(), document, options);
    }
  }
  class QueryExecution {
    constructor(program, { max_depth = 64, max_nodes = 1024, max_work = 100000000, retained = true } = {}) {
      this._program = program;
      this._pointer = wasm._opentlv_wasm_execution_new(program._pointer,
        size(max_depth), size(max_nodes), size(max_work), Number(Boolean(retained)));
      if (!this._pointer) response(wasm._opentlv_wasm_program_render(program._pointer, -1));
      ++program._references;
      this._maxNodes = max_nodes;
      this._busy = false;
      this._invalid = false;
      this._document = null;
    }
    _check(allowInvalid = false) {
      if (!this._pointer || this._busy || this._program._providerActive || (!allowInvalid && this._invalid)) throw new QueryError(10);
      if (!allowInvalid && this._document) this._document._check();
    }
    _operation(operation, argument = 0) {
      this._check();
      return this._native(() => wasm._opentlv_wasm_execution_operation(this._pointer, operation, size(argument)));
    }
    _native(run) {
      try { return response(run()); }
      finally {
        if (this._program._providerFailed) {
          const error = this._program._providerError;
          this._program._providerError = null;
          this._program._providerFailed = false;
          this._invalid = true;
          throw error;
        }
      }
    }
    close() {
      if (this._busy || this._program._providerActive) throw new QueryError(10);
      if (this._pointer) { wasm._opentlv_wasm_execution_free(this._pointer); this._program._release(); }
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
    feed({ kind, tag = new Uint8Array(), value = new Uint8Array(), depth = 0, offset = 0, skipped = false }) {
      this._check();
      const kinds = { begin: 0, element: 1, end: 2 };
      if (!Object.hasOwn(kinds, kind)) throw new TypeError("begin, element or end event required");
      bytes(tag); bytes(value);
      const reply = temporary(tag, tagPointer => temporary(value, valuePointer => this._native(() =>
        wasm._opentlv_wasm_execution_feed(this._pointer, kinds[kind], tagPointer, tag.length,
          valuePointer, value.length, size(depth), size(offset), Number(Boolean(skipped))))));
      return reply.value === null ? null : this._match(reply.value);
    }
    result() { return scalar(this._operation(2)); }
    _match(value) {
      return Object.freeze({ offset: value.offset, depth: value.depth, constructed: value.kind === 0,
        tag: unhex(value.tag), value: unhex(value.bytes) });
    }
    next() {
      try {
        const value = this._operation(1).value;
        if (this._document) return new Node(this._document, value);
        return this._match(value);
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
      ++document._active;
      try { this._native(() => wasm._opentlv_wasm_execution_document(this._pointer, document._pointer, size(value_capacity))); }
      finally { --document._active; }
      this._document = document;
      return this;
    }
    editDocument(kind, { tag = new Uint8Array(), value = new Uint8Array(), target_capacity = this._maxNodes } = {}) {
      this._check();
      const kinds = { remove: 0, replace: 1, insert_after: 2 };
      if (!this._document || !Object.hasOwn(kinds, kind)) throw new TypeError("Document selection and remove/replace/insert_after required");
      if (this._document._active) throw new QueryError(10);
      bytes(tag); bytes(value);
      return temporary(tag, tagPointer => temporary(value, valuePointer => this._native(() =>
        wasm._opentlv_wasm_execution_edit(this._pointer, kinds[kind], tagPointer, tag.length,
          valuePointer, value.length, size(target_capacity))))).applied;
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
      this._active = 0;
    }
    _check() { if (!this._pointer) throw new QueryError(10); }
    close() { if (this._active) throw new QueryError(10); if (this._pointer) wasm._opentlv_wasm_document_free(this._pointer); this._pointer = 0; }
    _node(node, operation, data = new Uint8Array()) {
      this._check();
      if (this._active && (operation === 4 || operation === 5)) throw new QueryError(10);
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
  return { QueryProgram, QueryExecution, QuerySchema, QueryError, Document, Node,
    compileQuery: (text, options) => new QueryProgram(text, options),
    loadQuery: (image, options) => QueryProgram.load(image, options),
    querySchema: (rules, options) => new QuerySchema(rules, options),
    document: (input, options) => new Document(input, options) };
}
