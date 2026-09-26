// Browser and Node.js entry point of the experimental OpenTLV WebAssembly build.
//
//   import { loadOpenTLV, hexToBytes } from "./opentlv.mjs";
//   const opentlv = await loadOpenTLV();
//   const result = opentlv.parse(hexToBytes("6F 0A 84 03 41 42 43 A5 03 50 01 01"), { format: "ber" });
//
// All parsing happens in the OpenTLV C core; this file only moves bytes in and
// the JSON result out. Parse failures are reported in `result.error`, they are
// not thrown.
import createOpenTLV from "./opentlv-core.js";

/** Formats the module can parse (a build may compile out some of them). */
export const FORMATS = Object.freeze(["default", "fixed", "bluetooth-ltv", "ber", "der"]);

/** Profiles that annotate elements with known tag names ("none" adds nothing). */
export const PROFILES = Object.freeze(["none", "emv"]);

/**
 * Converts hexadecimal text to bytes. Whitespace is ignored; an optional "0x"
 * prefix is not accepted. Throws a TypeError for invalid or odd-length input.
 */
export function hexToBytes(text) {
  const digits = String(text).replace(/\s+/g, "");
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(digits)) {
    throw new TypeError("expected an even number of hexadecimal digits");
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Loads the WebAssembly module.
 *
 * @param {object} [moduleOptions] Passed to the Emscripten factory, e.g.
 *   `{ locateFile: (name) => "/static/" + name }` to serve the .wasm file
 *   from another location.
 * @returns {Promise<{version: string, parse: Function}>}
 */
export async function loadOpenTLV(moduleOptions = {}) {
  const module = await createOpenTLV(moduleOptions);

  // Copies `size` bytes into module memory; the caller frees the result.
  function allocate(size) {
    const pointer = module._opentlv_wasm_alloc(size);
    if (!pointer) throw new Error("OpenTLV: out of memory");
    return pointer;
  }

  return {
    version: module.UTF8ToString(module._opentlv_wasm_version()),

    /**
     * Parses `bytes` and returns
     * `{ format, profile?, elements: [{ offset, depth, tag, length, headerSize, constructed,
     * value | children, symbol?, name?, lengthValid? }], error? }`.
     * `error` is `{ code, message, offset }` and comes with every element read
     * before the failure. Tags and values are uppercase hexadecimal strings.
     * An element spans `headerSize + length` bytes starting at `offset`.
     *
     * @param {Uint8Array} bytes
     * @param {{format?: string, profile?: string, fixedTagSize?: number,
     *   fixedLengthSize?: number, fixedByteOrder?: "big"|"little"}} [options] `format`
     *   defaults to "default"; `profile` ("none" or "emv") defaults to "none".
     *   `fixedTagSize`, `fixedLengthSize` (1-8) and `fixedByteOrder` configure
     *   `format: "fixed"`'s tag width, length width and length byte order
     *   (`tlv_fixed_config_t`); ignored for every other format.
     */
    parse(bytes, { format = "default", profile = "none", fixedTagSize = 1, fixedLengthSize = 1,
                  fixedByteOrder = "big" } = {}) {
      if (!(bytes instanceof Uint8Array)) throw new TypeError("bytes must be a Uint8Array");
      const formatSize = module.lengthBytesUTF8(format) + 1;
      const profileSize = module.lengthBytesUTF8(profile) + 1;
      const input = allocate(bytes.length);
      let name = 0;
      let profileName = 0;
      let result = 0;
      try {
        name = allocate(formatSize);
        profileName = allocate(profileSize);
        // HEAPU8 is re-read on every use: it is replaced when memory grows.
        module.HEAPU8.set(bytes, input);
        module.stringToUTF8(format, name, formatSize);
        module.stringToUTF8(profile, profileName, profileSize);
        result = module._opentlv_wasm_parse(input, bytes.length, name, profileName, fixedTagSize,
                                            fixedLengthSize, fixedByteOrder === "big" ? 1 : 0);
        if (!result) throw new Error("OpenTLV: out of memory");
        const json = module.UTF8ToString(
          module._opentlv_wasm_result_json(result),
          module._opentlv_wasm_result_json_size(result),
        );
        return JSON.parse(json);
      } finally {
        if (result) module._opentlv_wasm_result_free(result);
        if (profileName) module._opentlv_wasm_free(profileName);
        if (name) module._opentlv_wasm_free(name);
        module._opentlv_wasm_free(input);
      }
    },
  };
}
