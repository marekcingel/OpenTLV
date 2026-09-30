#ifndef OPENTLV_TLV_H
#define OPENTLV_TLV_H

/**
 * @file
 * @brief Convenience header for the configured C API.
 * @ingroup core
 */

#include "tlv/attributes.h"
#include "tlv/compiler.h"
#include "tlv/element.h"
#include "tlv/definition.h"
#include "tlv/size.h"
#include "tlv/value.h"
#include "tlv/codec/codec.h"
#include "tlv/codec/structure.h"
#include "tlv/copy.h"
#include "tlv/diagnostic.h"
#include "tlv/endian.h"
#include "tlv/format.h"
#include "tlv/layout.h"

#include "tlv/reader/reader.h"
#include "tlv/reader/tree.h"
#include "tlv/reader/visitor.h"
#include "tlv/query/query.h"
#include "tlv/writer/writer.h"
#include "tlv/schema/schema.h"
#include "tlv/schema/constraint.h"
#include "tlv/config.h"
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/ad_types.h"
#endif
#include "tlv/formats/fixed.h"
#include "tlv/formats/variable.h"
#if OPENTLV_LLDP
#include "tlv/builtins/lldp/lldp.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der_validation.h"
#endif
#if OPENTLV_EMV
#include "tlv/builtins/emv/emv.h"
#endif
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif

#endif /* OPENTLV_TLV_H */
