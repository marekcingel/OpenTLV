#include "tlv/error.h"

const char* tlv_strerror(tlv_result_t result) {
    switch (result) {
        case TLV_OK:                     return "OK";
        case TLV_ERR_BUFFER_TOO_SHORT:    return "buffer too short";
        case TLV_ERR_INVALID_LENGTH:      return "invalid length encoding";
        case TLV_ERR_NULL_ARG:            return "null argument";
        case TLV_ERR_OUT_OF_MEMORY:       return "out of memory";
        case TLV_ERR_END_OF_BUFFER:       return "end of buffer";
        case TLV_ERR_INVALID_TAG:         return "invalid tag";
        case TLV_ERR_VISITOR:             return "visitor error";
        case TLV_ERR_LIMIT:               return "resource limit exceeded";
        default:                         return "unknown error";
    }
}
