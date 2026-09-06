#ifndef OPENTLV_ERROR_H
#define OPENTLV_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum tlv_result {
    TLV_OK = 0,
    TLV_ERR_BUFFER_TOO_SHORT = 1,
    TLV_ERR_INVALID_LENGTH   = 2,
    TLV_ERR_NULL_ARG         = 3,
    TLV_ERR_OUT_OF_MEMORY    = 4,
    TLV_ERR_END_OF_BUFFER    = 5,
    TLV_ERR_INVALID_TAG      = 6,
    TLV_ERR_VISITOR          = 7
} tlv_result_t;

/* Returns a readable description of an error code (static string; no need to free). */
const char* tlv_strerror(tlv_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* OPENTLV_ERROR_H */
