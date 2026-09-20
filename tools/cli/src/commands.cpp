#include "commands.hpp"
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>
#include "console_color.hpp"
#include "decode.hpp"
#include "diagnostics.hpp"
#include "presentation.hpp"
#include "tlv/config.h"
#include "tlv/reader/walker.h"
#include "tlv++/walker.hpp"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/formats/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/formats/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/profiles/der.h"
#endif
#if OPENTLV_PROFILE_EMV
#include "tlv/profiles/emv_schema.h"
#endif

using cli::fail;

namespace {

const tlv_reader_format_t* select_format(const char* name) {
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_reader_format_default;
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    if (!strcmp(name, "fixed-1byte")) return &tlv_reader_format_fixed_1byte;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) return &tlv_reader_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) return &tlv_reader_format_der;
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    if (!strcmp(name, "bluetooth-ltv")) return &tlv_reader_format_bluetooth_ltv;
#endif
    (void)name;
    return NULL;
}

typedef struct output_context {
    const cli::options* options;
    const uint8_t*      data;
    int                 ber;
    cli_presentation_t  presentation;
    // --output json only: elements not yet attached to their parent's nested
    // "elements" array, one per currently open depth (stack.size() == the
    // depth of the next element to be attached), and the finished document's
    // top-level array.
    std::vector<nlohmann::json> json_stack;
    nlohmann::json              json_root = nlohmann::json::array();
} output_context_t;

bool is_json(const cli::options& o) {
    return !strcmp(o.output, "json");
}

// Attaches every element on the json_stack deeper than target_depth to its
// parent's "elements" array (or json_root, for a closing top-level element),
// converting the preorder traversal into a nested document as each
// element's subtree finishes.
void json_flush(output_context_t& out, size_t target_depth) {
    while (out.json_stack.size() > target_depth) {
        nlohmann::json child = std::move(out.json_stack.back());
        out.json_stack.pop_back();
        if (out.json_stack.empty())
            out.json_root.push_back(std::move(child));
        else
            out.json_stack.back()["elements"].push_back(std::move(child));
    }
}

// Prints `length` bytes as uppercase hex ("0A1B..."), restoring std::cout's
// prior formatting state afterward so callers can freely mix this with
// ordinary decimal output.
void print_hex(const uint8_t* data, size_t length) {
    const std::ios::fmtflags saved = std::cout.flags();
    const char               fill = std::cout.fill('0');
    std::cout << std::hex << std::uppercase;
    for (size_t i = 0; i < length; ++i) std::cout << std::setw(2) << (unsigned)data[i];
    std::cout.fill(fill);
    std::cout.flags(saved);
}

// Prints a tag's bytes as hex, wrapped in the CLI's tag accent color when
// enabled. Shared by dump's element output and --pdol.
void print_tag(const tlv_tag_t& tag, bool color) {
    cli::console_color scope(std::cout, color);
    print_hex(tag.data, tag.size);
}

// Same encoding as print_hex, built as a string instead of streamed, for
// --output json's field values (which are never color-wrapped).
std::string hex_string(const uint8_t* data, size_t length) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       result(length * 2, '0');
    for (size_t i = 0; i < length; ++i) {
        result[i * 2] = digits[data[i] >> 4];
        result[i * 2 + 1] = digits[data[i] & 0xF];
    }
    return result;
}

// Adds the "name" and, if requested, "description" EMV dictionary fields to
// a --output json element object, from the same lookup the text renderer uses.
void json_emv(nlohmann::json& object, const cli_presentation_t& presentation,
              const tlv_view_t* view, size_t depth, int describe) {
    const cli_emv_info info = cli_presentation_emv_info(&presentation, view, depth, describe);
    object["name"] = info.known ? info.name : "Unknown EMV tag in this context";
    if (info.has_description) object["description"] = info.description;
}

// Adds the "decoded" or "decode_error" field to a --output json element
// object, or neither for a tag/value kind with no codec.
void json_decode(nlohmann::json& object, const cli_presentation_t& presentation,
                 const tlv_view_t* view, size_t depth) {
    const cli::decode_result result = cli::decode_emv_value(presentation.contexts[depth], view);
    if (result.status == cli::decode_status::ok)
        object["decoded"] = result.text;
    else if (result.status == cli::decode_status::error)
        object["decode_error"] = result.text;
}

tlv_visit_result_t print_element(const tlv_view_t* view, size_t depth, size_t offset,
                                 void* context) {
    output_context_t* out = (output_context_t*)context;
    size_t            i;
    int               indefinite = out->ber && out->data[offset + view->tag.size] == 0x80;
    cli_presentation_visit(&out->presentation, view, depth, indefinite);
    if (!out->options->tree && depth) return TLV_VISIT_CONTINUE;
    if (is_json(*out->options)) {
        nlohmann::json object;
        object["offset"] = offset;
        object["tag"] = hex_string(view->tag.data, view->tag.size);
        object["length"] = (uint64_t)view->value.length;
        if (indefinite) object["indefinite"] = true;
        object["value"] = hex_string(view->value.data, (size_t)view->value.length);
        if (out->options->profile) {
            json_emv(object, out->presentation, view, depth, out->options->describe);
            if (out->options->decode) json_decode(object, out->presentation, view, depth);
        }
        // Attach any elements deeper than this one to their parent first,
        // since their subtrees are now known to be finished.
        json_flush(*out, depth);
        out->json_stack.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (out->options->pretty)
        cli_presentation_prefix(&out->presentation, depth);
    else
        for (i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << "offset=" << offset << " tag=";
    print_tag(view->tag, out->presentation.color != 0);
    std::cout << " length=" << view->value.length;
    if (indefinite) std::cout << " encoding=indefinite";
    std::cout << " value=";
    print_hex(view->value.data, (size_t)view->value.length);
    if (out->options->profile) {
        cli_presentation_emv(&out->presentation, view, depth, out->options->describe);
        if (out->options->decode) {
            const cli::decode_result result =
                cli::decode_emv_value(out->presentation.contexts[depth], view);
            if (result.status == cli::decode_status::ok)
                std::cout << " decoded=\"" << result.text << '"';
            else if (result.status == cli::decode_status::error)
                std::cout << " decode-error=\"" << result.text << '"';
        }
    }
    std::cout << "\n";
    return std::cout ? TLV_VISIT_CONTINUE : TLV_VISIT_ERROR;
}

const char* error_name(tlv_result_t rc) {
    switch (rc) {
#define ERROR_NAME(e)                                                                              \
    case e: return #e
        ERROR_NAME(TLV_OK);
        ERROR_NAME(TLV_ERR_BUFFER_TOO_SHORT);
        ERROR_NAME(TLV_ERR_INVALID_LENGTH);
        ERROR_NAME(TLV_ERR_NULL_ARG);
        ERROR_NAME(TLV_ERR_OUT_OF_MEMORY);
        ERROR_NAME(TLV_ERR_END_OF_BUFFER);
        ERROR_NAME(TLV_ERR_INVALID_TAG);
        ERROR_NAME(TLV_ERR_VISITOR);
        ERROR_NAME(TLV_ERR_LIMIT);
        ERROR_NAME(TLV_ERR_SCHEMA);
        ERROR_NAME(TLV_ERR_SCHEMA_MISSING);
        ERROR_NAME(TLV_ERR_INVALID_ARG);
        ERROR_NAME(TLV_ERR_INVALID_TAG_SIZE);
        ERROR_NAME(TLV_ERR_INVALID_BYTE_ORDER);
        ERROR_NAME(TLV_ERR_OVERFLOW);
#undef ERROR_NAME
        default: return "TLV_ERR_UNKNOWN";
    }
}

/* Reads the tag at the start of an element, including for formats that parse whole elements
 * (whose tag is only known once the element is well-formed). */
bool read_tag_at(const tlv_reader_format_t* format, const uint8_t* data, size_t size,
                 tlv_tag_t* tag, size_t* used) {
    if (format->read_tag) return format->read_tag(format->context, data, size, tag, used) == TLV_OK;
    size_t value_size, trailer_size;
    return format->read_element(format->context, data, size, tag, used, &value_size,
                                &trailer_size) == TLV_OK;
}

/* A DOL length is a single unsigned byte, not a BER length field. No value
 * bytes follow it. Reuse the public BER tag reader without fabricating TLVs. */
tlv_result_t walk_pdol(const uint8_t* data, size_t size, const tlv_reader_format_t* format,
                       output_context_t* output, size_t* error_offset) {
    size_t pos = 0, count = 0;
    while (pos < size) {
        tlv_view_t   entry;
        size_t       used, start = pos;
        unsigned     requested;
        tlv_result_t rc;
        *error_offset = pos;
        if (count == output->options->max_elements) return TLV_ERR_LIMIT;
        rc = format->read_tag(format->context, data + pos, size - pos, &entry.tag, &used);
        if (rc != TLV_OK) return rc;
        if (entry.tag.size > 2) return TLV_ERR_INVALID_TAG_SIZE;
        pos += used;
        *error_offset = pos;
        if (pos == size) return TLV_ERR_BUFFER_TOO_SHORT;
        requested = data[pos++];
        ++count;
        if (strcmp(output->options->command, "dump")) continue;
        /* Annotation uses only the tag, never a requested length as a value view. */
        entry.value.data = NULL;
        entry.value.length = 0;
        if (is_json(*output->options)) {
            nlohmann::json object;
            object["offset"] = start;
            object["tag"] = hex_string(entry.tag.data, entry.tag.size);
            object["requested_length"] = requested;
            if (output->options->profile)
                json_emv(object, output->presentation, &entry, 0, output->options->describe);
            output->json_root.push_back(std::move(object));
            continue;
        }
        std::cout << "offset=" << start << " tag=";
        print_tag(entry.tag, output->presentation.color != 0);
        std::cout << " requested-length=" << requested;
        if (output->options->profile)
            cli_presentation_emv(&output->presentation, &entry, 0, output->options->describe);
        std::cout << "\n";
        if (!std::cout) return TLV_ERR_VISITOR;
    }
    return TLV_OK;
}

} // namespace

namespace cli {
namespace commands {

void formats() {
#if OPENTLV_FORMAT_DEFAULT
    std::cout << "default\n";
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    std::cout << "fixed-1byte\n";
#endif
#if OPENTLV_FORMAT_BER
    std::cout << "ber\n";
#endif
#if OPENTLV_FORMAT_DER
    std::cout << "der\n";
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    std::cout << "bluetooth-ltv\n";
#endif
}

int execute(const options& o, const uint8_t* data, size_t size) {
    const tlv_reader_format_t* format = select_format(o.format);
    tlv_is_constructed_fn      predicate = NULL;
    size_t                     error_offset = 0;
    tlv_result_t               result;
    tlv_tree_visitor_t         visitor;
    output_context_t           output;
    // Set when the diagnostic below reports the separate schema-structure
    // pass (--profile emv on validate) rather than the format/framing walk,
    // so the two stay distinguishable in output.
    bool schema_stage = false;
    // Identity, not the format name string, is the single source of truth for
    // format-specific behavior below (indefinite-length display, --tree
    // support, and DER's own schema-driven walker).
    int is_ber = 0, is_der = 0, structured;

    if (!format) return fail(2, "unknown or disabled format; use otlv formats");
#if OPENTLV_FORMAT_BER
    is_ber = format == &tlv_reader_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    is_der = format == &tlv_reader_format_der;
#endif
    structured = is_ber || is_der;
    if (o.tree && !structured) return fail(2, "--tree supports only BER and DER");

    output.options = &o;
    output.data = data;
    output.ber = is_ber;
    cli_presentation_init(&output.presentation, data, size, o.color, o.pretty);
    visitor = !strcmp(o.command, "dump") ? print_element : NULL;
#if OPENTLV_FORMAT_BER
    if (structured) predicate = tlv_ber_is_constructed;
#endif
    if (o.pdol)
        result = walk_pdol(data, size, format, &output, &error_offset);
    else
#if OPENTLV_FORMAT_DER
        if (is_der) {
        tlv_der_limits_t limits = {o.max_depth, o.max_input, o.max_input, o.max_elements};
        result = tlv_der_walk(data, size, &limits, visitor, &output, &error_offset);
    } else
#endif
    {
        // The C++ walker owns the callback adapter and exposes borrowed entries.
        const auto walked = tlv::walk_tree(
            tlv::bytes(reinterpret_cast<const tlv::byte*>(data), size), *format, predicate,
            o.max_depth, o.max_elements,
            [&output, visitor](const tlv::entry& entry, size_t depth, size_t offset) {
                if (!visitor) return TLV_VISIT_CONTINUE;
                // Presentation shares this view adapter with the unwrapped DER API.
                const tlv_view_t raw = {entry.tag,
                                        {reinterpret_cast<const uint8_t*>(entry.value.data()),
                                         static_cast<tlv_length_t>(entry.value.size())}};
                return visitor(&raw, depth, offset, &output);
            },
            &error_offset);
        result = walked ? TLV_OK : walked.error().code;
    }
#if OPENTLV_PROFILE_EMV
    // Schema structure is checked only once the input has already parsed
    // cleanly, and only for validate: dump's --profile only annotates tags,
    // and --pdol's raw tag/length pairs are not a TLV structure to check.
    if (result == TLV_OK && o.profile && !o.pdol && !strcmp(o.command, "validate")) {
        size_t       schema_offset = error_offset;
        tlv_result_t schema_result =
            tlv_schema_validate(data, size, format, predicate, &tlv_emv_structure_schema,
                                o.max_depth, o.max_elements, &schema_offset);
        if (schema_result != TLV_OK) {
            result = schema_result;
            error_offset = schema_offset;
            schema_stage = true;
        }
    }
#endif
    if (is_json(o)) {
        json_flush(output, 0);
        nlohmann::json document;
        document["elements"] = std::move(output.json_root);
        std::cout << document.dump() << "\n";
    }
    cli_presentation_restore(&output.presentation);
    int rc = flush_stdout();
    if (rc) return rc;
    if (result != TLV_OK) {
        std::cerr << "otlv: " << (schema_stage ? "schema " : "") << error_name(result)
                  << " at byte " << error_offset;
        // TLV_ERR_SCHEMA_MISSING's offset is the end of the parent's value
        // (a scope boundary, not an element) and can coincide with the start
        // of an unrelated sibling in the enclosing scope, so no tag is
        // printed for it. Every other result's offset anchors the actual
        // element, so a tag read there is always accurate.
        tlv_tag_t tag;
        size_t    used;
        if (result != TLV_ERR_SCHEMA_MISSING && error_offset < size &&
            read_tag_at(format, data + error_offset, size - error_offset, &tag, &used))
            std::cerr << " tag=" << hex_string(tag.data, tag.size);
        std::cerr << ": " << tlv_strerror(result) << "\n";
        return result == TLV_ERR_LIMIT || result == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
    }
    return 0;
}

} // namespace commands
} // namespace cli
