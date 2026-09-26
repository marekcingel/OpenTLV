#include "commands/tags_command.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "commands/emv_dictionary.hpp"
#include "diagnostics.hpp"
#include "presentation.hpp"
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/emv/emv.h"
#endif

namespace cli {

int tags_command::run() {
    const options& o = options_;
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
    std::sort(matches.begin(), matches.end(), emv_tag_less);

    if (!strcmp(o.output, "json")) {
        nlohmann::json document;
        document["profile"] = o.profile;
        document["tags"] = nlohmann::json::array();
        for (size_t i = 0; i < matches.size(); ++i)
            document["tags"].push_back(emv_definition_json(matches[i]->schema->tag, *matches[i]));
        std::cout << document.dump() << "\n";
    } else {
        for (size_t i = 0; i < matches.size(); ++i)
            std::cout << std::left << std::setw(8) << tag_hex_string(matches[i]->schema->tag)
                      << cli_emv_display_name(matches[i]->name) << "\n";
    }
    return flush_stdout();
#else
    (void)o;
    return fail(2, "EMV profile is disabled in this build");
#endif
}

} // namespace cli
