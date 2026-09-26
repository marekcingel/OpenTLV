#ifndef OPENTLV_CLI_COMMANDS_WALK_COMMAND_HPP
#define OPENTLV_CLI_COMMANDS_WALK_COMMAND_HPP
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "command.hpp"
#include "commands/support.hpp"
#include "diagnostic_collect.hpp"
#include "diagnostic_render.hpp"
#include "options.hpp"
#include "presentation.hpp"
#include "tlv/query/query.h"
#include "tlv/reader/walker.h"
#include "tlv/schema/schema.h"

namespace cli {

// Shared skeleton for "dump", "validate", "decode" and "query", which all
// walk the same TLV tree with the selected format under --pdol/--recover.
// Owns the decoded input and the walk/diagnostic state a visitor needs (what
// used to be threaded through as a separate output_context_t and a
// hand-picked free-function pointer); subclasses (one per file alongside
// this one) override the small set of hooks that actually differ between
// the four commands.
class walk_command : public command {
public:
    walk_command(const options& o, std::vector<uint8_t> data);
    int run() override;

protected:
    // Called for each element the walk visits, in preorder. The base
    // implementation only keeps the diagnostic scope current (used as-is by
    // "validate", which has no display of its own).
    virtual tlv_visit_result_t visit_element(const tlv_view_t* view, std::size_t depth,
                                             std::size_t offset);

    // Called once, before the walk starts. The base implementation does
    // nothing; "query" uses it to initialize its path matcher, returning a
    // nonzero exit code (and printing its own diagnostic) to abort early.
    virtual int prepare();

    // "validate --profile emv" only: runs the EMV structure/dictionary
    // checks once the format walk itself succeeded (called from run() only
    // when result_ == TLV_OK, options_.profile and !options_.pdol). May
    // update result_/error_offset_/stage_ and either has_schema_diag_ with
    // schema_diag_, or stage_ alone, for render_failure_diagnostic() below.
    // The base implementation does nothing.
    virtual void run_emv_checks();

    // Called once the walk (and, for "validate", the EMV checks) are done,
    // regardless of the outcome: prints the command's own output. Most
    // overrides only print on result_ == TLV_OK, except "dump" --output
    // json, which (like the original implementation) prints whatever
    // elements were collected even after a failure. The base implementation
    // does nothing (used as-is by "validate", which never prints on success).
    virtual void render_output();

    // Called only once result_ == TLV_OK is confirmed (after the failure
    // diagnostic has already been handled): returns a nonzero exit code to
    // override the default of 0. "query" uses this for its exit code 5 (no
    // element matched).
    virtual int after_success();

    // Renders the diagnostic for a failed run (result_ != TLV_OK). The base
    // implementation covers a schema violation (has_schema_diag_) and the
    // generic wire-level/result-code cases; "validate" overrides it to also
    // cover its own EMV dictionary check violation.
    virtual std::string render_failure_diagnostic(diagnostic_format  diag_format,
                                                  const char*        tag_hex_ptr,
                                                  const std::string& stage_name);

    // --pdol only: whether to print each DOL tag/requested-length pair as
    // it's read ("dump"), versus reading it silently to validate its shape
    // ("validate").
    virtual bool prints_pdol_annotations() const;

    // --recover only: whether a skipped range is also reported inline, as
    // dump's normal text output is printed ("dump", text output only).
    virtual bool prints_skipped_inline() const;

    void json_flush(std::size_t target_depth);
    void document_flush(std::size_t target_depth);

    const uint8_t* data() const {
        return data_.data();
    }
    std::size_t size() const {
        return data_.size();
    }

    options                    options_;
    std::size_t                base_;
    int                        ber_;
    tlv_is_constructed_fn      constructed_;
    cli_presentation_t         presentation_;
    tlv_is_constructed_fn      predicate_;
    const tlv_reader_format_t* format_;
    bool                       is_der_;
    diagnostic_scope           scope_;
    // --output json only: elements not yet attached to their parent's nested
    // "elements" array, one per currently open depth, and the finished
    // document's top-level array.
    std::vector<nlohmann::json> json_stack_;
    nlohmann::json              json_root_ = nlohmann::json::array();
    // "decode" only: the same structure for the versioned document, whose
    // constructed elements carry "children".
    std::vector<nlohmann::ordered_json> document_stack_;
    nlohmann::ordered_json              document_root_ = nlohmann::ordered_json::array();
    // "query" only: the matcher deciding which elements are addressed and how
    // many were.
    tlv_query_matcher_t matcher_;
    std::size_t         matches_;

    tlv_result_t               result_;
    std::size_t                error_offset_;
    std::vector<skipped_range> skipped_;
    // Names the separate EMV pass ("schema ", "dictionary ") a failure came
    // from, as opposed to the format/framing walk.
    const char*             stage_;
    tlv_schema_diagnostic_t schema_diag_;
    bool                    has_schema_diag_;

private:
    static tlv_visit_result_t visit_trampoline(const tlv_view_t* view, std::size_t depth,
                                               std::size_t offset, void* context);
    // --pdol: raw DOL tag/one-byte-length pairs (BER only), not full TLV.
    tlv_result_t walk_pdol(std::size_t* error_offset);
    // --recover: scans past damaged top-level elements instead of failing.
    tlv_result_t walk_recovering(std::size_t* error_offset);

    std::vector<uint8_t> data_;
};

} // namespace cli
#endif
