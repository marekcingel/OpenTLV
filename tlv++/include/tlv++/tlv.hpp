// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_TLV_HPP
#define OPENTLV_TLVPP_TLV_HPP

/**
 * @file tlv.hpp
 * @brief Main include that aggregates the complete tlv++ API.
 *
 * Usage: `#include <tlv++/tlv.hpp>`
 */

/* Core primitives and generic formats */
#include "tlv/config.h"
#include "tlv/tlv.h"
#include "tlv++/format.hpp"
#include "tlv++/diagnostic.hpp"
#include "tlv++/version.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/formats/runtime_fixed.hpp"

/* Core capabilities */
#if OPENTLV_READER
#include "tlv++/reader/reader.hpp"
#include "tlv++/reader/tree.hpp"
#endif

#if OPENTLV_WRITER
#include "tlv++/writer/writer.hpp"
#include "tlv++/writer/tree.hpp"
#include "tlv++/writer/builder.hpp"
#include "tlv++/generator.hpp"
#endif

#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER && OPENTLV_QUERY && OPENTLV_CODEC
#include "tlv++/document/document.hpp"
#endif

#if OPENTLV_QUERY && OPENTLV_READER
#include "tlv++/query/query.hpp"
#include "tlv++/query/program.hpp"
#include "tlv++/query/builder.hpp"
#endif

#if OPENTLV_SCHEMA && OPENTLV_READER
#include "tlv++/schema/schema.hpp"
#endif

#if OPENTLV_CODEC
#include "tlv++/codec/codec.hpp"
#include "tlv++/codec/dynamic.hpp"
#include "tlv++/codec/typed.hpp"
#include "tlv++/codec/registry.hpp"
#if OPENTLV_SCHEMA && OPENTLV_READER
#include "tlv++/codec/structure.hpp"
#endif
#endif

/* Builtin protocols and formats */
#if OPENTLV_FORMAT_BER
#include "tlv++/builtins/asn1/ber.hpp"
#if OPENTLV_QUERY && OPENTLV_READER && OPENTLV_CODEC
#include "tlv++/builtins/asn1/query.hpp"
#endif
#if OPENTLV_CODEC
#include "tlv++/builtins/asn1/codec.hpp"
#endif
#endif

#if OPENTLV_FORMAT_DER
#include "tlv++/builtins/asn1/der.hpp"
#endif

#if OPENTLV_FORMAT_CER
#include "tlv++/builtins/asn1/cer.hpp"
#endif

#if OPENTLV_EMV
#include "tlv++/builtins/emv/format.hpp"
#if OPENTLV_QUERY && OPENTLV_READER && OPENTLV_SCHEMA && OPENTLV_CODEC
#include "tlv++/builtins/emv/query.hpp"
#endif
#if OPENTLV_CODEC && OPENTLV_SCHEMA
#include "tlv++/builtins/emv/codec.hpp"
#include "tlv++/builtins/emv/dictionary.hpp"
#endif
#endif

#if OPENTLV_BLUETOOTH
#include "tlv++/builtins/bluetooth/ltv.hpp"
#if OPENTLV_SCHEMA && OPENTLV_READER
#include "tlv++/builtins/bluetooth/metadata.hpp"
#endif
#if OPENTLV_CODEC
#include "tlv++/builtins/bluetooth/codec.hpp"
#endif
#endif

#if OPENTLV_NFC
#include "tlv++/builtins/nfc/type2.hpp"
#endif

#if OPENTLV_DHCP
#include "tlv++/builtins/dhcp/dhcpv4.hpp"
#if OPENTLV_CODEC
#include "tlv++/builtins/dhcp/codec.hpp"
#endif
#if OPENTLV_READER
#include "tlv++/builtins/dhcp/container.hpp"
#endif
#endif

#if OPENTLV_LLDP
#include "tlv++/builtins/lldp/lldp.hpp"
#if OPENTLV_CODEC
#include "tlv++/builtins/lldp/codec.hpp"
#endif
#endif

#endif // OPENTLV_TLVPP_TLV_HPP
