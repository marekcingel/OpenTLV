#include "commands.hpp"
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>
#include "console_color.hpp"
#include "decode.hpp"
#include "diagnostic_collect.hpp"
#include "diagnostic_render.hpp"
#include "diagnostics.hpp"
#include "json_model.hpp"
#include "presentation.hpp"
#include "tlv/config.h"
#include "tlv/query/query.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/scanner.h"
#include "tlv/reader/walker.h"
#include "tlv++/reader/walker.hpp"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/builtins/fixed/default.h"
#endif
#if OPENTLV_FORMAT_FIXED
#include "tlv/builtins/fixed/fixed.h"
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/builtins/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der_profile.h"
#endif
#if OPENTLV_PROFILE_EMV
#include "tlv/builtins/emv/emv.h"
#include "tlv/builtins/emv/emv_schema.h"
#endif

using cli::error_name;
using cli::fail;

namespace {

typedef nlohmann::ordered_json ordered_json;

const tlv_reader_format_t* select_format(const cli::options& o) {
    const char* name = o.format;
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_reader_format_default;
#endif
#if OPENTLV_FORMAT_FIXED
    // Configured by --fixed-tag-size/--fixed-length-size/--fixed-byte-order,
    // one tag byte/one length byte/big-endian by default.
    if (!strcmp(name, "fixed")) {
        static tlv_fixed_config_t  config;
        static tlv_reader_format_t format;
        config.tag_size = o.fixed_tag_size;
        config.length_size = o.fixed_length_size;
        config.order = !strcmp(o.fixed_byte_order, "little") ? TLV_BYTE_ORDER_LITTLE_ENDIAN
                                                             : TLV_BYTE_ORDER_BIG_ENDIAN;
        if (tlv_fixed_reader_format_init(&format, &config) != TLV_OK) return NULL;
        return &format;
    }
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
    // Absolute offset of the slice being walked. Visitors receive offsets
    // relative to that slice; recovery walks each intact top-level element
    // as its own slice of `data`.
    size_t                base;
    int                   ber;
    tlv_is_constructed_fn constructed; // BER/DER nesting predicate, NULL for other formats
    cli_presentation_t    presentation;
    // Diagnostic collection, independent of `presentation` (which exists
    // only for display bookkeeping): `predicate` is the same nesting
    // predicate passed to the walk (walk_env::predicate, not necessarily
    // `constructed` above -- BER and DER share one walker predicate but
    // have distinct display ones), and `scope` tracks the path and value
    // boundaries enclosing whichever element was last visited.
    tlv_is_constructed_fn predicate;
    cli::diagnostic_scope scope;
    // --output json only: elements not yet attached to their parent's nested
    // "elements" array, one per currently open depth (stack.size() == the
    // depth of the next element to be attached), and the finished document's
    // top-level array.
    std::vector<nlohmann::json> json_stack;
    nlohmann::json              json_root = nlohmann::json::array();
    // decode only: the same structure for the versioned document, whose
    // constructed elements carry "children".
    std::vector<ordered_json> document_stack;
    ordered_json              document_root = ordered_json::array();
    // query only: the matcher deciding which elements are addressed and how
    // many were.
    tlv_query_matcher_t matcher;
    size_t              matches;
} output_context_t;

bool is_json(const cli::options& o) {
    return !strcmp(o.output, "json");
}

bool is_decode_command(const cli::options& o) {
    return !strcmp(o.command, "decode");
}

bool is_query_command(const cli::options& o) {
    return !strcmp(o.command, "query");
}

// Attaches every element on `stack` deeper than target_depth to its parent's
// `key` array (or `root`, for a closing top-level element), converting the
// preorder traversal into a nested document as each element's subtree
// finishes.
template <class Json>
void flush_stack(std::vector<Json>& stack, Json& root, size_t target_depth, const char* key) {
    while (stack.size() > target_depth) {
        Json child = std::move(stack.back());
        stack.pop_back();
        if (stack.empty())
            root.push_back(std::move(child));
        else
            stack.back()[key].push_back(std::move(child));
    }
}

void json_flush(output_context_t& out, size_t target_depth) {
    flush_stack(out.json_stack, out.json_root, target_depth, "elements");
}

void document_flush(output_context_t& out, size_t target_depth) {
    flush_stack(out.document_stack, out.document_root, target_depth, "children");
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
// a JSON element object, from the same lookup the text renderer uses. A tag
// unknown in its context is labelled only when `label_unknown`; the decode
// document leaves it unnamed.
template <class Json>
void json_emv(Json& object, const cli_presentation_t& presentation, const tlv_view_t* view,
              size_t depth, int describe, bool label_unknown = true) {
    const cli_emv_info info = cli_presentation_emv_info(&presentation, view, depth, describe);
    if (info.known)
        object["name"] = info.name;
    else if (label_unknown)
        object["name"] = "Unknown EMV tag in this context";
    if (info.has_description) object["description"] = info.description;
}

// Adds the "decoded" or "decode_error" field to a JSON element object, or
// neither for a tag/value kind with no codec.
template <class Json>
void json_decode(Json& object, const cli_presentation_t& presentation, const tlv_view_t* view,
                 size_t depth) {
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
    cli::diagnostic_scope_visit(out->scope, out->data, view, depth, out->predicate);
    offset += out->base;
    int indefinite = out->ber && out->data[offset + view->tag.size] == 0x80;
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

// decode's visitor: builds the versioned document (docs/cli/json-schema.md).
// A primitive carries its raw "value"; a constructed element carries its
// "children" instead, plus an explicit "length_mode" for BER.
tlv_visit_result_t decode_element(const tlv_view_t* view, size_t depth, size_t offset,
                                  void* context) {
    output_context_t* out = (output_context_t*)context;
    cli::diagnostic_scope_visit(out->scope, out->data, view, depth, out->predicate);
    offset += out->base;
    const bool indefinite = out->ber && out->data[offset + view->tag.size] == 0x80;
    cli_presentation_visit(&out->presentation, view, depth, indefinite);
    ordered_json object;
    object["tag"] = hex_string(view->tag.data, view->tag.size);
    if (out->options->profile) {
        json_emv(object, out->presentation, view, depth, out->options->describe, false);
        if (out->options->decode) json_decode(object, out->presentation, view, depth);
    }
    if (out->constructed && out->constructed(NULL, &view->tag)) {
        if (out->ber) object["length_mode"] = indefinite ? "indefinite" : "definite";
        object["children"] = ordered_json::array();
    } else {
        object["value"] = hex_string(view->value.data, (size_t)view->value.length);
    }
    document_flush(*out, depth);
    out->document_stack.push_back(std::move(object));
    return TLV_VISIT_CONTINUE;
}

// The query path as text: uppercase hex tags joined by "/", however the user
// spelled it.
std::string query_path(const tlv_query_t& query) {
    std::string path;
    for (size_t i = 0; i < query.count; ++i) {
        if (i) path += '/';
        path += hex_string(tlv_query_step(&query, i).data, tlv_query_step(&query, i).size);
    }
    return path;
}

// query's visitor: prints each element the path addresses. Text output is
// the dump line without nesting, --value prints only the value bytes, and
// --output json collects the elements into one document printed at the end.
tlv_visit_result_t query_element(const tlv_view_t* view, size_t depth, size_t offset,
                                 void* context) {
    output_context_t* out = (output_context_t*)context;
    cli::diagnostic_scope_visit(out->scope, out->data, view, depth, out->predicate);
    if (!tlv_query_matcher_visit(&out->matcher, &view->tag, depth)) return TLV_VISIT_CONTINUE;
    ++out->matches;
    if (is_json(*out->options)) {
        nlohmann::json object;
        object["path"] = query_path(out->options->query);
        object["offset"] = offset;
        object["tag"] = hex_string(view->tag.data, view->tag.size);
        object["length"] = (uint64_t)view->value.length;
        object["value"] = hex_string(view->value.data, (size_t)view->value.length);
        out->json_root.push_back(std::move(object));
        return TLV_VISIT_CONTINUE;
    }
    if (out->options->value_only) {
        print_hex(view->value.data, (size_t)view->value.length);
    } else {
        std::cout << "offset=" << offset << " tag=";
        print_hex(view->tag.data, view->tag.size);
        std::cout << " length=" << view->value.length << " value=";
        print_hex(view->value.data, (size_t)view->value.length);
    }
    std::cout << "\n";
    return std::cout ? TLV_VISIT_CONTINUE : TLV_VISIT_ERROR;
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

// What every walk of the input needs to know about the selected format.
struct walk_env {
    const cli::options*        options;
    const tlv_reader_format_t* format;
    tlv_is_constructed_fn      predicate; // BER nesting predicate for the generic walker
    bool                       is_der;
};

// Walks `slice_size` bytes of `slice`, which starts at absolute offset `base`
// of the input, allowing at most `max_elements` elements. On failure
// *error_offset receives the failing element's absolute offset.
tlv_result_t walk_slice(const walk_env& env, const uint8_t* slice, size_t slice_size, size_t base,
                        size_t max_elements, tlv_tree_visitor_t visitor, void* context,
                        size_t* error_offset) {
    const cli::options& o = *env.options;
    size_t              relative = 0;
    tlv_result_t        result;
#if OPENTLV_FORMAT_DER
    if (env.is_der) {
        tlv_der_limits_t limits = {o.max_depth, o.max_input, o.max_input, max_elements};
        result = tlv_der_walk(slice, slice_size, &limits, visitor, context, &relative);
    } else
#endif
    {
        // The C++ walker owns the callback adapter and exposes borrowed entries.
        const auto walked = tlv::walk_tree(
            tlv::bytes(reinterpret_cast<const tlv::byte*>(slice), slice_size), *env.format,
            env.predicate, o.max_depth, max_elements,
            [visitor, context](const tlv::entry& entry, size_t depth, size_t offset) {
                if (!visitor) return TLV_VISIT_CONTINUE;
                // Presentation shares this view adapter with the unwrapped DER API.
                const tlv_view_t raw = {entry.tag,
                                        {reinterpret_cast<const uint8_t*>(entry.value.data()),
                                         static_cast<tlv_length_t>(entry.value.size())}};
                return visitor(&raw, depth, offset, context);
            },
            &relative);
        result = walked ? TLV_OK : walked.error().code;
    }
    if (result != TLV_OK) *error_offset = base + relative;
    return result;
}

tlv_visit_result_t count_element(const tlv_view_t*, size_t, size_t, void* context) {
    ++*static_cast<size_t*>(context);
    return TLV_VISIT_CONTINUE;
}

// validate has no display visitor of its own (a NULL visitor validates
// only); this one exists solely to keep output.scope current, so a failure
// the walk doesn't itself annotate (a value that overruns its own
// container, not the whole buffer) can still be reported with the path and
// boundary enclosing it.
tlv_visit_result_t track_scope_element(const tlv_view_t* view, size_t depth, size_t,
                                       void* context) {
    output_context_t* out = (output_context_t*)context;
    cli::diagnostic_scope_visit(out->scope, out->data, view, depth, out->predicate);
    return TLV_VISIT_CONTINUE;
}

// A byte range --recover skipped, and the first error that made it unreadable.
struct skipped_range {
    size_t       offset;
    size_t       length;
    tlv_result_t error;
    size_t       error_offset;
};

// Prints a text-mode "skipped" line inline, where the range sits in the input.
void print_skipped(const skipped_range& range) {
    std::cout << "skipped offset=" << range.offset << " length=" << range.length
              << " error=" << error_name(range.error) << " error-offset=" << range.error_offset
              << "\n";
}

// Recovery scan over the top-level elements. Each element that reads cleanly
// and whose whole subtree validates is walked (and printed) like normal
// input; where one does not, tlv_scan() looks for the next offset a plausible
// element starts at, and the bytes in between are recorded as skipped.
// Resource limits are not damage and still fail the run.
tlv_result_t walk_recovering(const walk_env& env, const uint8_t* data, size_t size,
                             output_context_t& out, tlv_tree_visitor_t visitor,
                             std::vector<skipped_range>& skipped, size_t* error_offset) {
    const cli::options& o = *env.options;
    const bool          inline_text = visitor == print_element && !is_json(o);
    size_t              pos = 0, budget = o.max_elements;
    bool                skipping = false;
    skipped_range       current = {0, 0, TLV_OK, 0};

    auto close_range = [&](size_t end) {
        current.length = end - current.offset;
        skipped.push_back(current);
        if (inline_text) print_skipped(current);
        skipping = false;
    };
    while (pos < size) {
        tlv_view_t   entry;
        size_t       consumed = 0, fault = pos, count = 0;
        tlv_result_t rc = tlv_read(data + pos, size - pos, env.format, &entry, &consumed);
        if (rc == TLV_OK)
            rc = walk_slice(env, data + pos, consumed, pos, budget, count_element, &count, &fault);
        if (rc == TLV_ERR_LIMIT || rc == TLV_ERR_OUT_OF_MEMORY) {
            *error_offset = fault;
            return rc;
        }
        if (rc == TLV_OK) {
            if (skipping) close_range(pos);
            out.base = pos;
            rc = walk_slice(env, data + pos, consumed, pos, budget, visitor, &out, &fault);
            if (rc != TLV_OK) {
                *error_offset = fault;
                return rc;
            }
            budget -= count;
            pos += consumed;
            continue;
        }
        if (!skipping) {
            skipping = true;
            current.offset = pos;
            current.error = rc;
            current.error_offset = fault;
        }
        tlv_view_t next;
        size_t     next_offset, next_size;
        if (tlv_scan(data, size, pos + 1, env.format, NULL, &next, &next_offset, &next_size) !=
            TLV_OK)
            break;
        pos = next_offset;
    }
    if (skipping) close_range(size);
    return TLV_OK;
}

#if OPENTLV_PROFILE_EMV
// The dictionary check's state: the first element whose length the EMV
// dictionary, in that element's context, does not permit, plus enough
// detail -- independent of `presentation`, which exists only for display
// bookkeeping -- to report it richly: the path enclosing it, the permitted
// length versus the actual one, and the dictionary field name.
struct dictionary_check {
    cli_presentation_t       presentation;
    const uint8_t*           data;
    tlv_is_constructed_fn    predicate;
    cli::diagnostic_scope    scope;
    tlv_result_t             result;
    size_t                   offset;
    std::string              expected;
    std::string              actual;
    const char*              field_name;
    tlv_diagnostic_context_t field_context;
};

tlv_visit_result_t check_dictionary_element(const tlv_view_t* view, size_t depth, size_t offset,
                                            void* context) {
    dictionary_check* check = (dictionary_check*)context;
    cli::diagnostic_scope_visit(check->scope, check->data, view, depth, check->predicate);
    cli_presentation_visit(&check->presentation, view, depth, 0);
    const tlv_emv_definition_t* definition =
        tlv_emv_find((tlv_emv_context_t)check->presentation.contexts[depth], &view->tag);
    // A tag without a dictionary entry in its context is preserved unchecked.
    if (!definition) return TLV_VISIT_CONTINUE;
    const size_t       value_length = (size_t)view->value.length;
    const tlv_result_t rc = tlv_emv_validate_length(definition, value_length);
    if (rc == TLV_OK) return TLV_VISIT_CONTINUE;
    check->result = rc;
    check->offset = offset;
    std::ostringstream expected;
    expected << definition->schema->min_length << ".." << definition->schema->max_length;
    if (definition->length_step > 1) expected << " (step " << definition->length_step << ")";
    check->expected = expected.str();
    check->actual = std::to_string(value_length);
    check->field_name = definition->name; // borrowed from the immutable dictionary tables
    return TLV_VISIT_STOP;
}
#endif

// The "skipped" array shared by dump's and decode's JSON documents.
template <class Json> Json skipped_json(const std::vector<skipped_range>& skipped) {
    Json array = Json::array();
    for (const skipped_range& range : skipped) {
        Json object;
        object["offset"] = range.offset;
        object["length"] = range.length;
        object["error"] = error_name(range.error);
        object["error_offset"] = range.error_offset;
        object["message"] = tlv_strerror(range.error);
        array.push_back(std::move(object));
    }
    return array;
}

} // namespace

namespace cli {
namespace commands {

void formats() {
#if OPENTLV_FORMAT_DEFAULT
    std::cout << "default\n";
#endif
#if OPENTLV_FORMAT_FIXED
    std::cout << "fixed\n";
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
    const tlv_reader_format_t* format = select_format(o);
    tlv_is_constructed_fn      predicate = NULL;
    size_t                     error_offset = 0;
    tlv_result_t               result;
    tlv_tree_visitor_t         visitor;
    output_context_t           output;
    std::vector<skipped_range> skipped;
    // Names the separate EMV pass ("schema", "dictionary") the diagnostic
    // below reports, as opposed to the format/framing walk, so the two stay
    // distinguishable in output.
    const char* stage = "";
    // Filled by the schema check below when it finds a violation, for the
    // richer rendering format_schema_diagnostic() gives it.
    tlv_schema_diagnostic_t schema_diag;
    bool                    has_schema_diag = false;
    // Identity, not the format name string, is the single source of truth for
    // format-specific behavior below (indefinite-length display, --tree
    // support, and DER's own schema-driven walker).
    int                    is_ber = 0, is_der = 0, structured;
    const bool             decoding = is_decode_command(o);
    const bool             querying = is_query_command(o);
    cli::diagnostic_format diag_format;
    cli::parse_diagnostic_format(o.diagnostics, &diag_format);

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
    output.base = 0;
    output.ber = is_ber;
    output.constructed = NULL;
    cli_presentation_init(&output.presentation, data, size, o.color, o.pretty);
    output.presentation.contexts[0] = o.emv_context;
    output.matches = 0;
    if (querying && tlv_query_matcher_init(&output.matcher, &o.query) != TLV_OK)
        return fail(2, "invalid query");
    visitor = querying                     ? query_element
              : decoding                   ? decode_element
              : !strcmp(o.command, "dump") ? print_element
                                           : track_scope_element;
#if OPENTLV_FORMAT_BER
    if (structured) predicate = tlv_ber_is_constructed;
    if (is_ber) output.constructed = tlv_ber_is_constructed;
#endif
#if OPENTLV_FORMAT_DER
    if (is_der) output.constructed = tlv_der_is_constructed;
#endif
    output.predicate = predicate;
    cli::diagnostic_scope_init(output.scope, size);
    const walk_env env = {&o, format, predicate, is_der != 0};
    if (o.pdol)
        result = walk_pdol(data, size, format, &output, &error_offset);
    else if (o.recover)
        result = walk_recovering(env, data, size, output, visitor, skipped, &error_offset);
    else
        result = walk_slice(env, data, size, 0, o.max_elements, visitor, &output, &error_offset);
#if OPENTLV_PROFILE_EMV
    // Declared here, not inside the block below, so the final diagnostic
    // report can still read it even when only the schema check ran (in
    // which case `check.result` stays TLV_OK and is simply never used).
    dictionary_check check;
    memset(&check.presentation, 0, sizeof check.presentation);
    check.data = data;
    check.predicate = predicate;
    cli::diagnostic_scope_init(check.scope, size);
    check.result = TLV_OK;
    check.offset = 0;
    check.field_name = nullptr;
    // EMV checks run only once the input has already parsed cleanly, and only
    // for validate: dump's --profile only annotates tags, and --pdol's raw
    // tag/length pairs are not a TLV structure to check.
    if (result == TLV_OK && o.profile && !o.pdol && !strcmp(o.command, "validate")) {
        if (o.emv_check & emv_check_structure) {
            tlv_schema_diagnostic_t        diag;
            tlv_schema_diagnostic_report_t report = {&diag, 1, 0};
            size_t                         schema_offset = error_offset;
            tlv_result_t                   schema_result = tlv_schema_validate_all_diag(
                data, size, format, predicate, &tlv_emv_structure_schema, o.max_depth,
                o.max_elements, TLV_SCHEMA_UNKNOWN_BY_SCHEMA, &report, &schema_offset);
            // tlv_schema_validate_all_diag() only reports the generic
            // TLV_ERR_SCHEMA itself and leaves *error_offset alone for a
            // violation (multiple can exist); the specific code and offset
            // tlv_schema_validate() would have returned live on the first
            // recorded diagnostic instead.
            if (report.count) {
                schema_result = diag.diagnostic.code;
                if (diag.diagnostic.has_offset) schema_offset = diag.diagnostic.offset;
            }
            if (schema_result != TLV_OK) {
                result = schema_result;
                error_offset = schema_offset;
                stage = "schema ";
                if (report.count) {
                    schema_diag = diag;
                    has_schema_diag = true;
                }
            }
        }
        if (result == TLV_OK && (o.emv_check & emv_check_dictionary)) {
            check.presentation.data = data;
            check.presentation.ends[0] = size;
            check.presentation.contexts[0] = o.emv_context;
            result = walk_slice(env, data, size, 0, o.max_elements, check_dictionary_element,
                                &check, &error_offset);
            if (result == TLV_OK && check.result != TLV_OK) {
                result = check.result;
                error_offset = check.offset;
                stage = "dictionary ";
            }
        }
    }
#endif
    const bool incomplete = !skipped.empty();
    if (decoding) {
        // A failed export prints nothing: a partial document would look like
        // a complete one. Recovery reports what it skipped in the document.
        if (result == TLV_OK) {
            document_flush(output, 0);
            ordered_json document;
            document["schema"] = json_model::schema_name;
            document["version"] = (int)json_model::schema_version;
            document["format"] = o.format;
            document["elements"] = std::move(output.document_root);
            if (o.recover) {
                document["complete"] = !incomplete;
                document["skipped"] = skipped_json<ordered_json>(skipped);
            }
            std::cout << document.dump() << "\n";
        }
    } else if (querying) {
        if (result == TLV_OK && is_json(o)) {
            nlohmann::json document;
            document["matches"] = std::move(output.json_root);
            std::cout << document.dump() << "\n";
        }
    } else if (is_json(o)) {
        json_flush(output, 0);
        nlohmann::json document;
        document["elements"] = std::move(output.json_root);
        if (o.recover) {
            document["complete"] = !incomplete;
            document["skipped"] = skipped_json<nlohmann::json>(skipped);
        }
        std::cout << document.dump() << "\n";
    }
    cli_presentation_restore(&output.presentation);
    int rc = flush_stdout();
    if (rc) return rc;
    if (result != TLV_OK) {
        std::string rendered;
        // TLV_ERR_SCHEMA_MISSING's offset (from tlv_schema_validate_all_diag(),
        // above) anchors the enclosing element's own tag, and its tag is the
        // absent one -- both borrowed from the schema/diagnostic itself, so
        // both are reliable; a re-read at the offset is only needed, and only
        // safe, for every other result, whose offset anchors an actual element.
        std::string stage_name(stage);
        if (!stage_name.empty() && stage_name.back() == ' ') stage_name.pop_back();
        tlv_tag_t   tag;
        size_t      used;
        std::string tag_hex;
        if (result != TLV_ERR_SCHEMA_MISSING && error_offset < size &&
            read_tag_at(format, data + error_offset, size - error_offset, &tag, &used))
            tag_hex = hex_string(tag.data, tag.size);
        const char* tag_hex_ptr = tag_hex.empty() ? nullptr : tag_hex.c_str();

        if (has_schema_diag) {
            rendered = cli::format_schema_diagnostic(schema_diag, diag_format);
        }
#if OPENTLV_PROFILE_EMV
        else if (stage_name == "dictionary" && check.result == result) {
            tlv::diagnostic diag = tlv::make_diagnostic(result, TLV_DIAGNOSTIC_SEVERITY_ERROR);
            tlv_diagnostic_set_offset(&diag, error_offset);
            if (check.scope.path.length) tlv_diagnostic_set_path(&diag, &check.scope.path);
            if (!check.expected.empty()) diag.expected = check.expected.c_str();
            if (!check.actual.empty()) diag.actual = check.actual.c_str();
            if (check.field_name)
                tlv_diagnostic_add_context(&diag, &check.field_context, "dictionary", "field",
                                           check.field_name);
            rendered = cli::format_diagnostic(diag, diag_format, "dictionary", tag_hex_ptr);
        }
#endif
        else {
            // A wire-level error the walk already found at `error_offset`
            // has no tlv_reader_diagnostic_t of its own (neither
            // tlv_walk_tree() nor tlv_der_walk() produce one); re-deriving
            // it, bounded to its enclosing scope, adds the failing step and
            // declared-length-versus-available detail when it can be
            // reproduced exactly. Not attempted for --pdol, whose flat
            // tag/length pairs the reader-diagnostic model doesn't describe,
            // nor for DER: tlv_der_walk()'s own error_offset is not always a
            // tlv_read()-style element start the way tlv_walk_tree()'s is
            // (it comes from DER's own recursive validator), so re-reading
            // one element there could coincidentally reproduce the same
            // result code at the wrong field instead of failing the way
            // TLV_ERR_LIMIT/TLV_ERR_VISITOR do.
            tlv_reader_diagnostic_t reader_diag;
            bool                    derived =
                !o.pdol && !is_der &&
                cli::diagnostic_scope_derive_reader_diagnostic(output.scope, format, data, size,
                                                               error_offset, result, &reader_diag);
            if (derived) {
                if (output.scope.path.length)
                    tlv_diagnostic_set_path(&reader_diag.diagnostic, &output.scope.path);
                rendered = cli::format_reader_diagnostic(reader_diag, diag_format);
            } else {
                tlv::diagnostic diag = tlv::make_diagnostic(result, TLV_DIAGNOSTIC_SEVERITY_ERROR);
                tlv_diagnostic_set_offset(&diag, error_offset);
                rendered =
                    cli::format_diagnostic(diag, diag_format, stage_name.c_str(), tag_hex_ptr);
            }
        }
        if (diag_format == cli::diagnostic_format::json)
            std::cerr << rendered << "\n";
        else
            std::cerr << "otlv: " << rendered << "\n";
        return result == TLV_ERR_LIMIT || result == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
    }
    if (querying && !output.matches) {
        std::cerr << "otlv: no match for query " << query_path(o.query) << "\n";
        return 5;
    }
    if (incomplete) {
        size_t bytes = 0;
        // Every skipped range starts as its own top-level element (see
        // walk_recovering()), so this scope's path stays empty; a range
        // whose recorded failure is actually nested in that element's
        // subtree (not the top-level read itself) simply won't reproduce
        // through the derivation below and falls back to the plain form.
        // Never attempted for DER; see the same rationale where the final
        // wire-error case above excludes it.
        cli::diagnostic_scope range_scope;
        cli::diagnostic_scope_init(range_scope, size);
        for (const skipped_range& range : skipped) {
            tlv_reader_diagnostic_t reader_diag;
            std::string             rendered;
            if (!is_der && cli::diagnostic_scope_derive_reader_diagnostic(
                               range_scope, format, data, size, range.error_offset, range.error,
                               &reader_diag)) {
                reader_diag.diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_WARNING;
                rendered = cli::format_reader_diagnostic(reader_diag, diag_format);
            } else {
                tlv::diagnostic diag =
                    tlv::make_diagnostic(range.error, TLV_DIAGNOSTIC_SEVERITY_WARNING);
                tlv_diagnostic_set_offset(&diag, range.error_offset);
                rendered = cli::format_diagnostic(diag, diag_format, "", nullptr);
            }
            if (diag_format == cli::diagnostic_format::json) {
                nlohmann::json wrapper = nlohmann::json::parse(rendered);
                wrapper["skipped_offset"] = range.offset;
                wrapper["skipped_length"] = range.length;
                std::cerr << wrapper.dump() << "\n";
            } else {
                std::cerr << "otlv: skipped " << range.length << " byte(s) at offset "
                          << range.offset << ": " << rendered << "\n";
            }
            bytes += range.length;
        }
        std::cerr << "otlv: output is incomplete: recovery skipped " << skipped.size()
                  << " range(s), " << bytes << " byte(s) in total\n";
        return 4;
    }
    return 0;
}

} // namespace commands
} // namespace cli
