#ifndef OPENTLV_TLVPP_TYPES_HPP
#define OPENTLV_TLVPP_TYPES_HPP
#include <string>
#include "tlv++/compat.hpp"
#include "tlv/types.h"
namespace tlv {
// Idiomatic C++ error that wraps a C error code and context.
struct error {
    tlv_result_t code;
    std::string  message;

    static error from_c(tlv_result_t c_code) {
        return error{c_code, tlv_strerror(c_code)};
    }
};

using tag_t = tlv_tag_t;
using bytes = span<const byte>;

// A TLV item on the C++ side (value points into the original buffer; zero-copy).
struct entry {
    tag_t tag;
    bytes value;
};

}
#endif
