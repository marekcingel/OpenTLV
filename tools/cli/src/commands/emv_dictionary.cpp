#include "commands/emv_dictionary.hpp"
#include <cctype>
#include <cstring>
#include "diagnostics.hpp"
#include "input.hpp"
#include "presentation.hpp"
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/asn1/ber.h"
#endif

using cli::fail;

namespace cli {

#if OPENTLV_PROFILE_EMV

std::string tag_hex_string(const tlv_tag_t& tag) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       result;
    for (size_t i = 0; i < tag.size; ++i) {
        result += digits[tag.data[i] >> 4];
        result += digits[tag.data[i] & 0xF];
    }
    return result;
}

std::string emv_length_range(const tlv_schema_entry_t& entry) {
    std::string text = std::to_string(entry.min_length);
    if (entry.max_length == SIZE_MAX)
        text += "..unbounded";
    else if (entry.max_length != entry.min_length)
        text += ".." + std::to_string(entry.max_length);
    return text;
}

nlohmann::json emv_definition_json(const tlv_tag_t& tag, const tlv_emv_definition_t& definition) {
    nlohmann::json object;
    object["tag"] = tag_hex_string(tag);
    object["known"] = true;
    object["name"] = cli_emv_display_name(definition.name);
    object["symbol"] = definition.name;
    object["type"] = tlv_emv_value_kind_description(definition.value_kind);
    object["constructed"] = tlv_ber_is_constructed(nullptr, &tag) != 0;
    object["min_length"] = (uint64_t)definition.schema->min_length;
    if (definition.schema->max_length != SIZE_MAX)
        object["max_length"] = (uint64_t)definition.schema->max_length;
    object["length_step"] = (uint64_t)definition.length_step;
    return object;
}

std::string lowercase(std::string text) {
    for (size_t i = 0; i < text.size(); ++i) text[i] = (char)tolower((unsigned char)text[i]);
    return text;
}

bool emv_tag_less(const tlv_emv_definition_t* a, const tlv_emv_definition_t* b) {
    const tlv_tag_t& x = a->schema->tag;
    const tlv_tag_t& y = b->schema->tag;
    return tlv_tag_compare(x, y) < 0;
}

int parse_emv_tag(const char* text, std::vector<uint8_t>& bytes, tlv_tag_t& tag) {
    size_t used = 0;
    int    rc = decode_hex(text, TLV_ASN1_TAG_MAX_SIZE, bytes);
    if (rc == 3) return fail(2, "tag is longer than the longest tag a supported format accepts");
    if (rc) return rc;
    if (bytes.empty()) return fail(2, "tag must not be empty");
    if (tlv_reader_format_ber.read_tag(tlv_reader_format_ber.context, bytes.data(), bytes.size(),
                                       &tag, &used) != TLV_OK ||
        used != bytes.size())
        return fail(2, "tag is not a single complete BER tag");
    return 0;
}

#endif

} // namespace cli
