#ifndef OPENTLV_TLVPP_TLV_HPP
#define OPENTLV_TLVPP_TLV_HPP

/**
 * @file tlv.hpp
 * @brief Main include that aggregates the complete tlv++ API.
 *
 * Usage: `#include "tlv++/definition.hpp"
#include <tlv++/tlv.hpp>`
 */

#include "tlv/tlv.h"
#include "tlv++/format.hpp"
#include "tlv++/codec/codec.hpp"
#include "tlv++/diagnostic.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/reader/reader.hpp"
#include "tlv++/reader/tree.hpp"
#include "tlv++/writer/writer.hpp"
#include "tlv++/writer/tree.hpp"
#include "tlv++/codec/registry.hpp"
#include "tlv++/codec/structure.hpp"
#include "tlv++/query/query.hpp"
#include "tlv++/schema/schema.hpp"
#if OPENTLV_NFC
#include "tlv++/builtins/nfc/type2.hpp"
#endif
#if OPENTLV_DHCP
#include "tlv++/builtins/dhcp/dhcpv4.hpp"
#include "tlv++/builtins/dhcp/container.hpp"
#endif
#if OPENTLV_EMV
#include "tlv++/builtins/emv/format.hpp"
#endif
#if OPENTLV_LLDP
#include "tlv++/builtins/lldp/lldp.hpp"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#endif
#if OPENTLV_DOCUMENT
#include "tlv++/document/document.hpp"
#endif

#endif // OPENTLV_TLVPP_TLV_HPP
