#ifndef OPENTLV_TLVPP_TLV_HPP
#define OPENTLV_TLVPP_TLV_HPP

/**
 * @file tlv.hpp
 * @brief Main include that aggregates the complete tlv++ API.
 *
 * Usage: `#include <tlv++/tlv.hpp>`
 */

#include "tlv/tlv.h"
#include "tlv++/codec/codec.hpp"
#include "tlv++/diagnostic.hpp"
#include "tlv++/builtins/fixed/fixed_format.hpp"
#include "tlv++/reader/reader.hpp"
#include "tlv++/writer/writer.hpp"
#include "tlv++/codec/registry.hpp"
#include "tlv++/codec/structure.hpp"
#include "tlv++/reader/walker.hpp"
#include "tlv++/query/query.hpp"
#include "tlv++/schema/schema.hpp"
#if OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#endif
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#endif

#endif // OPENTLV_TLVPP_TLV_HPP
