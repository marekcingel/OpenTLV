#include "commands/tag_command.hpp"
#include <cstring>
#include <iostream>
#include <vector>
#include <nlohmann/json.hpp>
#include "commands/emv_dictionary.hpp"
#include "diagnostics.hpp"
#include "presentation.hpp"
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/asn1/ber.h"
#include "tlv/builtins/emv/emv.h"
#endif

namespace cli {

int tag_command::run() {
    const options& o = options_;
#if OPENTLV_PROFILE_EMV
    std::vector<uint8_t> bytes;
    tlv_tag_t            parsed;
    int                  rc = parse_emv_tag(o.tag, bytes, parsed);
    if (rc) return rc;

    const tlv_emv_definition_t* definition = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &parsed);
    const std::string           tag_hex = tag_hex_string(parsed);

    if (!strcmp(o.output, "json")) {
        nlohmann::json document;
        if (definition) document = emv_definition_json(parsed, *definition);
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
                  << "Length:      " << emv_length_range(*definition->schema) << "\n";
        if (definition->length_step != 1)
            std::cout << "Length step: " << definition->length_step << "\n";
    }
    return flush_stdout();
#else
    (void)o;
    return fail(2, "EMV profile is disabled in this build");
#endif
}

} // namespace cli
