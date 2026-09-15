#ifndef OPENTLV_BER_INTERNAL_H
#define OPENTLV_BER_INTERNAL_H
#include "tlv/formats/format.h"
extern const tlv_reader_format_t tlv_ber_reader_wire;
extern const tlv_writer_format_t tlv_ber_writer_wire;

/* Walk only framing, skipping primitive contents in one step, starting just
 * after a tag whose length field begins at data[0]. indefinite selects
 * whether the outer scope itself is EOC-terminated (the caller already
 * consumed its introducing 0x80). Each nested frame's end is a hard bound
 * inherited from the closest definite enclosing scope; an EOC outside that
 * bound cannot terminate a nested value. On success, *value_size receives
 * the content length up to (but excluding) any matching outer EOC and
 * *consumed receives the same plus that EOC's 2 bytes when indefinite.
 * Bounded by TLV_BER_MAX_DEPTH nested scopes; no allocation, no recursion.
 * Shared by tlv_reader_format_ber, tlv_ber_write_indefinite, and CER. */
tlv_result_t tlv_ber_scan_contents(const uint8_t* data, size_t size, int indefinite,
                                   size_t* value_size, size_t* consumed);
#endif
