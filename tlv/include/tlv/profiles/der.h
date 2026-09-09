#ifndef OPENTLV_DER_H
#define OPENTLV_DER_H

#include "tlv/formats/asn1/der.h"
#include "tlv/reader/walker.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of constructed ancestors; top-level elements have depth 0.
 * max_depth may be 0 through TLV_DER_MAX_DEPTH. All limits are inclusive;
 * zero is a real limit. NULL limits selects tlv_der_default_limits.
 * max_input_size bounds supplied input / complete encoded output, max_value_size
 * bounds each value, and max_elements bounds total visited elements.
 */
#define TLV_DER_MAX_DEPTH 64
typedef struct tlv_der_limits {
    size_t max_depth;
    size_t max_input_size;
    size_t max_value_size;
    size_t max_elements;
} tlv_der_limits_t;
extern const tlv_der_limits_t tlv_der_default_limits;

/* Zero-copy preorder traversal. offset is the tag's absolute input offset.
 * Callback view is temporary; its value borrows input. STOP succeeds without
 * validating the rest; callback side effects are not rolled back on errors.
 */
typedef tlv_visit_result_t (*tlv_der_visitor_t)(const tlv_view_t* view,
                                               size_t depth, size_t offset,
                                               void* context);

/* Validates one complete element, including all descendants; ignores trailing
 * bytes (but max_input_size covers size). Empty input returns END_OF_BUFFER.
 * Outputs remain unchanged on failure, except optional error_offset, which
 * receives the start of the failing tag, length, or value field. Nested offsets
 * are relative to data. Argument/input-limit errors use 0. Success leaves it
 * unchanged. No allocations and no C recursion are used.
 */
tlv_result_t tlv_der_read(const uint8_t* data, size_t size,
                          const tlv_der_limits_t* limits, tlv_view_t* view,
                          size_t* consumed, size_t* error_offset);

/* Validates all concatenated elements recursively; empty input succeeds.
 * visitor may be NULL for validation only. Same offset and limit conventions.
 */
tlv_result_t tlv_der_walk(const uint8_t* data, size_t size,
                          const tlv_der_limits_t* limits,
                          tlv_der_visitor_t visitor, void* context,
                          size_t* error_offset);

/* Writes canonical tag/length bytes, copying value verbatim. Constructed values
 * must already contain canonical DER-TLV children; they are validated first.
 * No ASN.1 value semantics or SET/SET OF ordering validation is performed.
 * NULL data with zero capacity queries size, including validation. Value and
 * destination must not overlap. Output and written remain unchanged on error.
 * error_offset is relative to the would-be output, using read conventions.
 */
tlv_result_t tlv_der_write(uint8_t* data, size_t capacity, tlv_tag_t tag,
                           const uint8_t* value, size_t length,
                           const tlv_der_limits_t* limits, size_t* written,
                           size_t* error_offset);

#ifdef __cplusplus
}
#endif
#endif /* OPENTLV_DER_H */
