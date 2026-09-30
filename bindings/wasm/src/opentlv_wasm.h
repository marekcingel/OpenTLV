#ifndef OPENTLV_WASM_H
#define OPENTLV_WASM_H

/*
 * Browser-facing boundary of the experimental OpenTLV WebAssembly build.
 *
 * A thin wrapper over the OpenTLV C API: it parses nothing itself. Callers copy
 * the input into memory obtained from opentlv_wasm_alloc(), call
 * opentlv_wasm_parse(), read the JSON document from the result and release
 * everything again. bindings/wasm/js/opentlv.mjs does this for JavaScript callers.
 *
 * The JSON document has the shape
 *
 *   {"format": "ber", "module": "emv",
 *    "elements": [{"offset": 0, "depth": 0, "tag": "6F", "length": 10,
 *                  "headerSize": 2, "constructed": true,
 *                  "symbol": "fci_template", "name": "FCI Template",
 *                  "lengthValid": true, "children": [ ... ]},
 *                 {"offset": 2, "depth": 1, "tag": "84", "length": 3,
 *                  "headerSize": 2, "constructed": false, "value": "414243"}],
 *    "error": {"code": 1, "message": "...", "offset": 12}}
 *
 * "error" is present only on failure; "elements" then holds every element
 * that was read before the error. Only BER, DER and CER elements can be
 * constructed. Tags and values are uppercase hexadecimal. An element occupies
 * "encodedSize" bytes starting at "offset", including its trailer. "source"
 * gives absolute {offset, length} ranges for header, tag, length, value and
 * trailer. "headerSize" and logical value "length" exclude the trailer.
 * "tag" holds the identifier bytes.
 * Bluetooth modes also add known AD Type names. "bluetooth-ad" validates
 * trailing zero padding and reports "padding": {"offset", "length"} when present.
 * "bluetooth-ltv" retains strict framing. Values remain opaque in both modes.
 * "module", "symbol" and "lengthValid" appear only
 * when a module was requested (and "symbol", "name" only for tags it knows).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define OPENTLV_WASM_API EMSCRIPTEN_KEEPALIVE
#else
#define OPENTLV_WASM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque parse result; release it with opentlv_wasm_result_free(). */
typedef struct opentlv_wasm_result opentlv_wasm_result_t;

/*
 * Parses `size` bytes as `format` ("fixed", "bluetooth-ltv", "bluetooth-ad", "lldp", "nfc-type2",
 * "ber", "der" or "cer"). `module` annotates elements with dictionary metadata: NULL, "" or "none"
 * for none, or "emv" (EMV Contact Book 3 tags) with the "ber" format. `fixed_tag_size`,
 * `fixed_length_size` and `fixed_big_endian` (nonzero for big-endian) configure `format ==
 * "fixed"`'s tag width, length width (1-8 bytes) and length byte order (tlv_fixed_format_t);
 * ignored for every other format. Nonzero `fixed_length_first` selects LTV; nonzero
 * `fixed_counts_tag` makes the length count Tag + Value. Both default to zero for conventional TLV.
 * Returns NULL only when memory runs out. An unknown format or module, invalid fixed-format widths,
 * or invalid input, is reported through the result, never by returning NULL.
 */
OPENTLV_WASM_API opentlv_wasm_result_t*
opentlv_wasm_parse(const uint8_t* data, size_t size, const char* format, const char* module,
                   size_t fixed_tag_size, size_t fixed_length_size, int fixed_big_endian,
                   int fixed_length_first, int fixed_counts_tag);

/* tlv_result_t of the parse; 0 (TLV_OK) on success. */
OPENTLV_WASM_API int opentlv_wasm_result_code(const opentlv_wasm_result_t* result);

/* Input offset at which the parse failed; 0 on success. */
OPENTLV_WASM_API size_t opentlv_wasm_result_error_offset(const opentlv_wasm_result_t* result);

/* NUL-terminated JSON document, owned by the result. */
OPENTLV_WASM_API const char* opentlv_wasm_result_json(const opentlv_wasm_result_t* result);

/* Length of the JSON document in bytes, without the terminating NUL. */
OPENTLV_WASM_API size_t opentlv_wasm_result_json_size(const opentlv_wasm_result_t* result);

OPENTLV_WASM_API void opentlv_wasm_result_free(opentlv_wasm_result_t* result);

/* Allocates input or format-name memory for the caller; release with opentlv_wasm_free(). */
OPENTLV_WASM_API uint8_t* opentlv_wasm_alloc(size_t size);

OPENTLV_WASM_API void opentlv_wasm_free(void* pointer);

/* OpenTLV version this module was built from. */
OPENTLV_WASM_API const char* opentlv_wasm_version(void);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_WASM_H */
