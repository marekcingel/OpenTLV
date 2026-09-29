#include "commands/walk_command.hpp"
#include <cstring>
#include <iostream>
#include <utility>
#include <nlohmann/json.hpp>
#include "commands/support.hpp"
#include "diagnostic_collect.hpp"
#include "diagnostic_render.hpp"
#include "diagnostics.hpp"
#include "tlv/config.h"
#include "bluetooth.hpp"
#if OPENTLV_BLUETOOTH
#include "tlv/builtins/bluetooth/ad_data.h"
#endif
#include "tlv/reader/reader.h"
#include "tlv/reader/scanner.h"
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/builtins/asn1/der_validation.h"
#endif

using cli::fail;

namespace {

tlv_visit_result_t count_element(const tlv_element_t*, size_t, size_t, void* context) {
    ++*static_cast<size_t*>(context);
    return TLV_VISIT_CONTINUE;
}

// Prints a text-mode "skipped" line inline, where the range sits in the input.
void print_skipped(const cli::skipped_range& range) {
    std::cout << "skipped offset=" << range.offset << " length=" << range.length
              << " error=" << cli::error_name(range.error) << " error-offset=" << range.error_offset
              << "\n";
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

} // namespace

namespace cli {

walk_command::walk_command(const options& o, std::vector<uint8_t> data)
    : options_(o), base_(0), ber_(0), presentation_(), format_(NULL), is_der_(false), scope_(),
      matcher_(), matches_(0), result_(TLV_OK), error_offset_(0), stage_(""), schema_diag_(),
      has_schema_diag_(false), data_(std::move(data)) {}

tlv_visit_result_t walk_command::visit_trampoline(const tlv_element_t* element, std::size_t depth,
                                                  std::size_t offset, void* context) {
    return static_cast<walk_command*>(context)->visit_element(element, depth, offset);
}

tlv_visit_result_t walk_command::visit_element(const tlv_element_t* element, std::size_t depth,
                                               std::size_t) {
    // validate has no display visitor of its own; this one exists solely to
    // keep the diagnostic scope current, so a failure the walk doesn't itself
    // annotate (a value that overruns its own container, not the whole
    // buffer) can still be reported with the path and boundary enclosing it.
    diagnostic_scope_visit(scope_, data(), element, depth, format_->is_constructed);
    return TLV_VISIT_CONTINUE;
}

int walk_command::prepare() {
    return 0;
}

void walk_command::run_module_checks() {}

void walk_command::render_output() {}

int walk_command::after_success() {
    return 0;
}

void walk_command::json_flush(std::size_t target_depth) {
    flush_stack(json_stack_, json_root_, target_depth, "elements");
}

void walk_command::document_flush(std::size_t target_depth) {
    flush_stack(document_stack_, document_root_, target_depth, "children");
}

bool walk_command::prints_pdol_annotations() const {
    return false;
}

bool walk_command::prints_skipped_inline() const {
    return false;
}

std::string walk_command::render_failure_diagnostic(diagnostic_format  diag_format,
                                                    const char*        tag_hex_ptr,
                                                    const std::string& stage_name) {
    if (has_schema_diag_) return format_schema_diagnostic(schema_diag_, diag_format);
    if (reader_diag_.diagnostic.code == result_) {
        if (scope_.path.length) tlv_diagnostic_set_path(&reader_diag_.diagnostic, &scope_.path);
        return format_reader_diagnostic(reader_diag_, diag_format);
    }
    tlv::diagnostic diag = tlv::make_diagnostic(result_, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    tlv_diagnostic_set_offset(&diag, error_offset_);
    return format_diagnostic(diag, diag_format, stage_name.c_str(), tag_hex_ptr);
}

// A DOL length is a single unsigned byte, not a BER length field. No value
// bytes follow it. Reuse the public BER tag reader without fabricating TLVs.
tlv_result_t walk_command::walk_pdol(std::size_t* error_offset) {
    size_t pos = 0, count = 0;
    while (pos < size()) {
        tlv_element_t element;
        size_t        used, start = pos;
        unsigned      requested;
        tlv_result_t  rc;
        *error_offset = pos;
        if (count == options_.max_elements) return TLV_ERR_LIMIT;
        rc = tlv_ber_read_identifier(data() + pos, size() - pos, &element.tag, &used);
        if (rc != TLV_OK) return rc;
        if (element.tag.size > 2) return TLV_ERR_INVALID_TAG_SIZE;
        pos += used;
        *error_offset = pos;
        if (pos == size()) return TLV_ERR_BUFFER_TOO_SHORT;
        requested = data()[pos++];
        ++count;
        if (!prints_pdol_annotations()) continue;
        // Annotation uses only the tag, never a requested length as a value element.
        element.value.data = NULL;
        element.value.size = 0;
        if (is_json(options_)) {
            nlohmann::json object;
            object["offset"] = start;
            object["tag"] = hex_string(element.tag.data, element.tag.size);
            object["requested_length"] = requested;
            if (options_.module) json_emv(object, presentation_, &element, 0, options_.describe);
            json_root_.push_back(std::move(object));
            continue;
        }
        std::cout << "offset=" << start << " tag=";
        print_tag(element.tag, presentation_.color != 0);
        std::cout << " requested-length=" << requested;
        if (options_.module) cli_presentation_emv(&presentation_, &element, 0, options_.describe);
        std::cout << "\n";
        if (!std::cout) return TLV_ERR_VISITOR;
    }
    return TLV_OK;
}

// Recovery scan over the top-level elements. Each element that reads cleanly
// and whose whole subtree validates is walked (and printed) like normal
// input; where one does not, tlv_scan() looks for the next offset a
// plausible element starts at, and the bytes in between are recorded as
// skipped. Resource limits are not damage and still fail the run.
tlv_result_t walk_command::walk_recovering(std::size_t* error_offset) {
    const walk_env env = {&options_, format_, is_der_};
    const bool     inline_text = prints_skipped_inline();
    size_t         pos = 0, budget = options_.max_elements;
    bool           skipping = false;
    skipped_range  current{};

    auto close_range = [&](size_t end) {
        current.length = end - current.offset;
        skipped_.push_back(current);
        if (inline_text) print_skipped(current);
        skipping = false;
    };
    while (pos < size()) {
        tlv_element_t           element;
        size_t                  consumed = 0, fault = pos, count = 0;
        tlv_reader_diagnostic_t attempt{};
        tlv_result_t            rc =
            tlv_read_diag(data() + pos, size() - pos, format_, &element, &consumed, &attempt);
        if (rc != TLV_OK) {
            if (attempt.diagnostic.has_offset) attempt.diagnostic.offset += pos;
            if (attempt.has_tag_offset) attempt.tag_offset += pos;
            if (attempt.has_length_offset) attempt.length_offset += pos;
            if (attempt.has_value_offset) attempt.value_offset += pos;
            if (attempt.has_enclosing_end) attempt.enclosing_end += pos;
        }
        if (rc == TLV_OK) {
            rc = walk_slice(env, data() + pos, consumed, pos, budget, count_element, &count, &fault,
                            &attempt);
            if ((rc == TLV_ERR_LIMIT || rc == TLV_ERR_OUT_OF_MEMORY) && fault == pos) {
                reader_diag_.has_tag = 1;
                reader_diag_.tag = element.tag;
            }
        }
        if (rc == TLV_ERR_LIMIT || rc == TLV_ERR_OUT_OF_MEMORY) {
            *error_offset = fault;
            return rc;
        }
        if (rc == TLV_OK) {
            if (skipping) close_range(pos);
            base_ = pos;
            rc = walk_slice(env, data() + pos, consumed, pos, budget, visit_trampoline, this,
                            &fault);
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
            current.diagnostic = attempt;
        }
        tlv_element_t next;
        size_t        next_offset, next_size;
        if (tlv_scan(data(), size(), pos + 1, format_, NULL, &next, &next_offset, &next_size) !=
            TLV_OK)
            break;
        pos = next_offset;
    }
    if (skipping) close_range(size());
    return TLV_OK;
}

int walk_command::run() {
    const tlv_format_t* format = select_format(options_);
    std::size_t         error_offset = 0;
    tlv_result_t        result;
    int                 is_ber = 0, is_der = 0, structured;
    diagnostic_format   diag_format;
    parse_diagnostic_format(options_.diagnostics, &diag_format);
    stage_ = "";
    has_schema_diag_ = false;

    if (!format) return fail(2, "unknown or disabled format; use otlv formats");
#if OPENTLV_FORMAT_BER
    is_ber = format == &tlv_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    is_der = format == &tlv_format_der;
#endif
    structured = format->is_constructed != NULL;
    if (options_.tree && !structured)
        return fail(2, "--tree requires a format with a constructed indicator");

    format_ = format;
    is_der_ = is_der != 0;
    base_ = 0;
    ber_ = is_ber;
    cli_presentation_init(&presentation_, data(), size(), options_.color, options_.pretty);
    presentation_.contexts[0] = options_.emv_context;
    matches_ = 0;

    const int prepared = prepare();
    if (prepared) return prepared;

    diagnostic_scope_init(scope_, size());
    const walk_env env = {&options_, format_, is_der_};
    std::size_t    significant = size();
    result = TLV_OK;
#if OPENTLV_BLUETOOTH
    if (bluetooth_module(options_))
        result = tlv_bluetooth_ad_data_validate(data(), size(), &significant, &error_offset);
#endif
    if (result != TLV_OK) {
        stage_ = "container ";
        // The container API reports an offset only. For a framing failure,
        // ask the public walker for its full raw identifier/field diagnostic.
        // Padding errors remain container diagnostics, not fake LTV elements.
        if (result != TLV_ERR_INVALID_VALUE) {
            std::size_t ignored = 0;
            walk_slice(env, data(), size(), 0, options_.max_elements, nullptr, nullptr, &ignored,
                       &reader_diag_);
        }
    } else if (options_.pdol)
        result = walk_pdol(&error_offset);
    else if (options_.recover)
        result = walk_recovering(&error_offset);
    else
        result = walk_slice(env, data(), significant, 0, options_.max_elements, visit_trampoline,
                            this, &error_offset, &reader_diag_);
    result_ = result;
    error_offset_ = error_offset;

    if (result_ == TLV_OK && options_.module && !options_.pdol) run_module_checks();

    render_output();

    cli_presentation_restore(&presentation_);
    int rc = flush_stdout();
    if (rc) return rc;
    if (result_ != TLV_OK) {
        std::string stage_name(stage_);
        if (!stage_name.empty() && stage_name.back() == ' ') stage_name.pop_back();
        std::string tag_hex;
        if (reader_diag_.has_tag)
            tag_hex = hex_string(reader_diag_.tag.data, reader_diag_.tag.size);
        const char* tag_hex_ptr = tag_hex.empty() ? nullptr : tag_hex.c_str();

        const std::string rendered =
            render_failure_diagnostic(diag_format, tag_hex_ptr, stage_name);
        if (diag_format == diagnostic_format::json)
            std::cerr << rendered << "\n";
        else
            std::cerr << "otlv: " << rendered << "\n";
        return result_ == TLV_ERR_LIMIT || result_ == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
    }
    const int extra = after_success();
    if (extra) return extra;
    if (!skipped_.empty()) {
        size_t bytes = 0;
        // Every skipped range starts as its own top-level element (see
        // walk_recovering()), so this scope's path stays empty; a range
        // whose recorded failure is actually nested in that element's
        // subtree (not the top-level read itself) simply won't reproduce
        // through the derivation below and falls back to the plain form.
        // Never attempted for DER; see the same rationale where the final
        // wire-error case above excludes it.
        for (const skipped_range& range : skipped_) {
            tlv_reader_diagnostic_t reader_diag;
            std::string             rendered;
            if (range.diagnostic.diagnostic.code == range.error) {
                reader_diag = range.diagnostic;
                reader_diag.diagnostic.severity = TLV_DIAGNOSTIC_SEVERITY_WARNING;
                rendered = format_reader_diagnostic(reader_diag, diag_format);
            } else {
                tlv::diagnostic diag =
                    tlv::make_diagnostic(range.error, TLV_DIAGNOSTIC_SEVERITY_WARNING);
                tlv_diagnostic_set_offset(&diag, range.error_offset);
                rendered = format_diagnostic(diag, diag_format, "", nullptr);
            }
            if (diag_format == diagnostic_format::json) {
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
        std::cerr << "otlv: output is incomplete: recovery skipped " << skipped_.size()
                  << " range(s), " << bytes << " byte(s) in total\n";
        return 4;
    }
    return 0;
}

} // namespace cli
