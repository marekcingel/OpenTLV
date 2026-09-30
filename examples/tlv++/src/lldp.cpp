#include "tlv++/tlv.hpp"
#include "tlv++/builtins/lldp/lldp.hpp"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/codec.h"

int main() {
    const uint8_t    wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    tlv_diagnostic_t diagnostic{};
    if (tlv_lldp_validate(wire, sizeof(wire), 16, &diagnostic) != TLV_OK) return 1;
    size_t            count = 0;
    tlv_tree_reader_t reader;
    if (tlv_tree_reader_init(&reader, wire, sizeof(wire), &tlv::lldp_format(), nullptr, 0, 0, 16) !=
        TLV_OK)
        return 1;
    auto result = tlv::visit_tree(reader, [&count](const tlv::element& element, size_t, size_t) {
        if (element.tag.data[0] == 3) {
            uint16_t seconds = 0;
            size_t   size = 0;
            if (tlv_size_to_native(element.value.size, &size) != TLV_OK ||
                tlv_codec_decode(&tlv_lldp_codec_ttl, element.value.data, size, &seconds,
                                 sizeof(seconds)) != TLV_CODEC_OK ||
                seconds != 120)
                return TLV_VISIT_ERROR;
        }
        ++count;
        return TLV_VISIT_CONTINUE;
    });
    return result && count == 4 ? 0 : 1;
}
