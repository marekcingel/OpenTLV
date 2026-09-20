#ifndef OPENTLV_FORMAT_INTERNAL_H
#define OPENTLV_FORMAT_INTERNAL_H

#include "tlv/formats/format.h"

/* A reader format is usable when it can parse whole elements or provides both
 * classic tag and length decoders. */
static inline int tlv_reader_format_usable(const tlv_reader_format_t* format) {
    return format && (format->read_element || (format->read_tag && format->read_length));
}

/* A writer format is usable when it can encode whole headers or provides all
 * three classic tag and length callbacks. */
static inline int tlv_writer_format_usable(const tlv_writer_format_t* format) {
    return format && (format->write_header ||
                      (format->write_tag && format->write_length && format->length_size));
}

#endif
