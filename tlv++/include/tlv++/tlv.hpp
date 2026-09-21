#ifndef OPENTLV_TLVPP_TLV_HPP
#define OPENTLV_TLVPP_TLV_HPP

/**
 * @file tlv.hpp
 * @brief Main include that aggregates the complete tlv++ API.
 *
 * Usage: `#include <tlv++/tlv.hpp>`
 */

#include "tlv/tlv.h"
#include "tlv++/codec.hpp"
#include "tlv++/fixed_format.hpp"
#include "tlv++/reader.hpp"
#include "tlv++/writer.hpp"
#include "tlv++/registry.hpp"
#include "tlv++/structure.hpp"
#include "tlv++/walker.hpp"
#include "tlv++/query.hpp"
#include "tlv++/schema.hpp"
#if OPENTLV_FORMAT_BER
#include "tlv++/ber.hpp"
#endif
#if OPENTLV_DOCUMENT
#include "tlv++/document.hpp"
#endif

#endif // OPENTLV_TLVPP_TLV_HPP
