#ifndef OPENTLV_CLI_COMMANDS_EMV_DICTIONARY_HPP
#define OPENTLV_CLI_COMMANDS_EMV_DICTIONARY_HPP
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/emv/emv.h"
#endif

// Small helpers shared by tag_command and tags_command (both look up entries
// in the same EMV base-context dictionary), kept out of either command's own
// file.

namespace cli {

#if OPENTLV_PROFILE_EMV
std::string tag_hex_string(const tlv_tag_t& tag);

// "6", "1..10" or "0..unbounded" from the dictionary's inclusive length bounds.
std::string emv_length_range(const tlv_schema_entry_t& entry);

// Metadata object shared by "tag" and "tags" --output json.
nlohmann::json emv_definition_json(const tlv_tag_t& tag, const tlv_emv_definition_t& definition);

std::string lowercase(std::string text);

bool emv_tag_less(const tlv_emv_definition_t* a, const tlv_emv_definition_t* b);

// Decodes `text` and requires it to be exactly one complete BER tag. The
// parsed tag borrows `bytes`, which must outlive it.
int parse_emv_tag(const char* text, std::vector<uint8_t>& bytes, tlv_tag_t& tag);
#endif

} // namespace cli
#endif
