// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLV_H
#define OPENTLV_TLV_H

/**
 * @file
 * @brief Convenience header for the configured C API.
 * @ingroup core
 */

/* Core primitives and generic formats */
#include "tlv/config.h"
#include "tlv/attributes.h"
#include "tlv/compiler.h"
#include "tlv/defaults.h"
#include "tlv/definition.h"
#include "tlv/element.h"
#include "tlv/size.h"
#include "tlv/value.h"
#include "tlv/copy.h"
#include "tlv/diagnostic.h"
#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/field/encoding.h"
#include "tlv/field/fixed.h"
#include "tlv/field/packed.h"
#include "tlv/field/variable.h"
#include "tlv/field/escaped.h"
#include "tlv/formats/packed.h"
#include "tlv/formats/compose.h"
#include "tlv/formats/fixed.h"
#include "tlv/formats/variable.h"
#include "tlv/formats/escaped.h"

/* Core capabilities */
#if OPENTLV_READER
#include "tlv/reader/reader.h"
#include "tlv/reader/tree.h"
#include "tlv/reader/visitor.h"
#endif

#if OPENTLV_WRITER
#include "tlv/writer/writer.h"
#include "tlv/writer/tree.h"
#include "tlv/generator.h"
#endif

#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif

#if OPENTLV_QUERY
#include "tlv/query/query.h"
#endif

#if OPENTLV_SCHEMA
#include "tlv/schema/schema.h"
#include "tlv/schema/constraint.h"
#if OPENTLV_QUERY && OPENTLV_READER
#include "tlv/schema/query.h"
#endif
#endif

#if OPENTLV_CODEC
#include "tlv/codec/codec.h"
#if OPENTLV_SCHEMA && OPENTLV_READER
#include "tlv/codec/structure.h"
#endif
#endif

/* Builtin protocols and formats */
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif

#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#include "tlv/builtins/asn1/der_validation.h"
#endif

#if OPENTLV_EMV && OPENTLV_SCHEMA && OPENTLV_CODEC
#include "tlv/builtins/emv/emv.h"
#endif

#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/ad_types.h"
#endif

#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif

#endif /* OPENTLV_TLV_H */
