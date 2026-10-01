#include "tlv++/tlv.hpp"
#include "tlv++/builtins/lldp/lldp.hpp"
#include "tlv/builtins/lldp/schema.h"
#include "tlv/builtins/lldp/codec.h"

int main() {
    const uint8_t    wire[] = {2, 2, 7, 'c', 4, 2, 7, 'p', 6, 2, 0, 120, 0, 0};
    tlv_diagnostic_t diagnostic{};
    if (tlv_lldp_validate(wire, sizeof(wire), 16, &diagnostic) != TLV_OK) return 1;
    size_t count = 0;
    try {
        for (auto element :
             tlv::lldp::parse(tlv::bytes(reinterpret_cast<const tlv::byte*>(wire), sizeof(wire)))) {
            if (element.tag() == tlv::tag_bytes<3>()) {
                uint16_t seconds = 0;
                auto     value = element.value();
                if (tlv_codec_decode(&tlv_lldp_codec_ttl,
                                     reinterpret_cast<const uint8_t*>(value.data()), value.size(),
                                     &seconds, sizeof(seconds)) != TLV_CODEC_OK ||
                    seconds != 120)
                    return 1;
            }
            ++count;
        }
    } catch (const tlv::parse_error&) {
        return 1;
    }
    return count == 4 ? 0 : 1;
}
