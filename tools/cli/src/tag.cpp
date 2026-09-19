#include "tag.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "diagnostics.hpp"
#include "input.hpp"
#include "presentation.hpp"
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/formats/asn1/ber.h"
#include "tlv/profiles/emv.h"
#endif

using cli::fail;

#if OPENTLV_PROFILE_EMV
namespace {

std::string hex_string(const tlv_tag_t& tag) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       result;
    for (uint8_t i = 0; i < tag.size; ++i) {
        result += digits[tag.data[i] >> 4];
        result += digits[tag.data[i] & 0xF];
    }
    return result;
}

// "6", "1..10" or "0..unbounded" from the dictionary's inclusive length bounds.
std::string length_range(const tlv_schema_entry_t& entry) {
    std::string text = std::to_string(entry.min_length);
    if (entry.max_length == SIZE_MAX)
        text += "..unbounded";
    else if (entry.max_length != entry.min_length)
        text += ".." + std::to_string(entry.max_length);
    return text;
}

// Metadata object shared by `tag` and `tags` --output json.
nlohmann::json definition_json(const tlv_tag_t& tag, const tlv_emv_definition_t& definition) {
    nlohmann::json object;
    object["tag"] = hex_string(tag);
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

bool tag_less(const tlv_emv_definition_t* a, const tlv_emv_definition_t* b) {
    const tlv_tag_t& x = a->schema->tag;
    const tlv_tag_t& y = b->schema->tag;
    return std::lexicographical_compare(x.data, x.data + x.size, y.data, y.data + y.size);
}

// Decodes the argument and requires it to be exactly one complete BER tag.
int parse_tag(const char* text, tlv_tag_t& tag) {
    std::vector<uint8_t> bytes;
    size_t               used = 0;
    int                  rc = cli::decode_hex(text, TLV_TAG_CAPACITY, bytes);
    if (rc == 3) return fail(2, "tag is longer than the supported tag capacity");
    if (rc) return rc;
    if (bytes.empty()) return fail(2, "tag must not be empty");
    if (tlv_reader_format_ber.read_tag(tlv_reader_format_ber.context, bytes.data(), bytes.size(),
                                       &tag, &used) != TLV_OK ||
        used != bytes.size())
        return fail(2, "tag is not a single complete BER tag");
    return 0;
}

} // namespace
#endif

namespace cli {
namespace commands {

int tag(const options& o) {
#if OPENTLV_PROFILE_EMV
    tlv_tag_t parsed;
    int       rc = parse_tag(o.tag, parsed);
    if (rc) return rc;

    const tlv_emv_definition_t* definition = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &parsed);
    const std::string           tag_hex = hex_string(parsed);

    if (!strcmp(o.output, "json")) {
        nlohmann::json document;
        if (definition) document = definition_json(parsed, *definition);
        document["tag"] = tag_hex;
        document["profile"] = o.profile;
        document["known"] = definition != nullptr;
        std::cout << document.dump() << "\n";
    } else if (!definition) {
        std::cout << "Tag:         " << tag_hex << "\n"
                  << "Result:      Unknown tag in the EMV profile (base context)\n";
    } else {
        std::cout << "Tag:         " << tag_hex << "\n"
                  << "Name:        " << cli_emv_display_name(definition->name) << "\n"
                  << "Type:        " << tlv_emv_value_kind_description(definition->value_kind)
                  << "\n"
                  << "Form:        "
                  << (tlv_ber_is_constructed(nullptr, &parsed) ? "Constructed" : "Primitive")
                  << "\n"
                  << "Length:      " << length_range(*definition->schema) << "\n";
        if (definition->length_step != 1)
            std::cout << "Length step: " << definition->length_step << "\n";
    }
    return flush_stdout();
#else
    (void)o;
    return fail(2, "EMV profile is disabled in this build");
#endif
}

int tags(const options& o) {
#if OPENTLV_PROFILE_EMV
    const tlv_schema_t*                      schema = tlv_emv_schema_for(TLV_EMV_CONTEXT_BASE);
    std::vector<const tlv_emv_definition_t*> matches;
    const std::string                        needle = o.search ? lowercase(o.search) : "";
    for (size_t i = 0; schema && i < schema->count; ++i) {
        const tlv_emv_definition_t* definition =
            tlv_emv_find(TLV_EMV_CONTEXT_BASE, &schema->entries[i].tag);
        if (definition &&
            lowercase(cli_emv_display_name(definition->name)).find(needle) != std::string::npos)
            matches.push_back(definition);
    }
    std::sort(matches.begin(), matches.end(), tag_less);

    if (!strcmp(o.output, "json")) {
        nlohmann::json document;
        document["profile"] = o.profile;
        document["tags"] = nlohmann::json::array();
        for (size_t i = 0; i < matches.size(); ++i)
            document["tags"].push_back(definition_json(matches[i]->schema->tag, *matches[i]));
        std::cout << document.dump() << "\n";
    } else {
        for (size_t i = 0; i < matches.size(); ++i)
            std::cout << std::left << std::setw(8) << hex_string(matches[i]->schema->tag)
                      << cli_emv_display_name(matches[i]->name) << "\n";
    }
    return flush_stdout();
#else
    (void)o;
    return fail(2, "EMV profile is disabled in this build");
#endif
}

} // namespace commands
} // namespace cli
