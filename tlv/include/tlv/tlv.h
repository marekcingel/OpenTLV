#ifndef OPENTLV_TLV_H
#define OPENTLV_TLV_H

/**
 * @file
 * @brief Convenience header for the configured C API.
 * @ingroup core
 */

#include "tlv/view.h"
#include "tlv/length.h"
#include "tlv/value.h"
#include "tlv/codec/codec.h"
#include "tlv/codec/structure.h"
#include "tlv/copy.h"
#include "tlv/diagnostic.h"
#include "tlv/endian.h"
#include "tlv/format.h"

#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/reader/scanner.h"
#include "tlv/query/query.h"
#include "tlv/writer/writer.h"
#include "tlv/schema/schema.h"
#include "tlv/schema/constraint.h"
#include "tlv/config.h"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/builtins/fixed/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/builtins/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der_profile.h"
#endif
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/emv/emv.h"
#endif
#if OPENTLV_DOCUMENT
#include "tlv/document/document.h"
#endif

#endif /* OPENTLV_TLV_H */
