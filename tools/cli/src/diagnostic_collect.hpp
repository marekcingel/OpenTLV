#ifndef OPENTLV_CLI_DIAGNOSTIC_COLLECT_HPP
#define OPENTLV_CLI_DIAGNOSTIC_COLLECT_HPP
#include <cstddef>
#include <cstdint>
#include "tlv/diagnostic.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"

// Collects the detail behind a walk's diagnostic (the path enclosing it, and
// enough of a reader diagnostic to describe it) independently of how that
// detail is later presented. diagnostic_render.hpp owns formatting only;
// this file owns figuring out what there is to format.

namespace cli {

// The tags and value boundaries enclosing whichever element a walk's visitor
// was last called for. Independent of cli_presentation_t, which exists only
// for display bookkeeping (indentation, EMV context inheritance) and must
// not be reused here. One instance is shared by every visitor of a single
// walk.
struct diagnostic_scope {
    tlv_diagnostic_path_t path;
    // end[d]: offset one past the value of the scope open at depth d;
    // end[0] is the whole input size.
    size_t end[TLV_WALK_MAX_DEPTH + 1];
};

// Resets `scope` to an empty path within an input of `size` bytes.
void diagnostic_scope_init(diagnostic_scope& scope, size_t size);

// Updates `scope` for the element just visited at `depth`, before doing
// anything else with it, so that a later failure deeper in the same walk can
// be reported with the tags and value boundary enclosing it. Mirrors the
// pop-then-push pattern in docs/guides/diagnostics.md#hierarchical-paths.
// `base` is the start of the whole input buffer, used to compute a
// constructed value's absolute end from its borrowed pointer; `constructed`
// is the same nesting predicate passed to the walk, or `nullptr`.
void diagnostic_scope_visit(diagnostic_scope& scope, const uint8_t* base, const tlv_view_t* view,
                            std::size_t depth, tlv_is_constructed_fn constructed);

// Re-derives a full tlv_reader_diagnostic_t for a wire-level failure a walk
// already detected at `error_offset`, bounded to `scope`'s enclosing value
// (not necessarily the whole buffer), and shifts every offset it reports
// back to being absolute in `data`. `scope` is not, itself, updated for the
// failing element (which the walk's visitor was never called for).
//
// Returns false, leaving `*out` unchanged, unless the re-derived call
// reproduces `expected_code` exactly: a walker/resource-level failure
// (TLV_ERR_LIMIT, TLV_ERR_VISITOR, TLV_ERR_OUT_OF_MEMORY) has no
// corresponding single-element read, and a format's own extra validation
// (such as DER's canonical-form rules) may not surface through a plain read
// the same way a full walk does. Callers should fall back to a plainer
// rendering when this returns false.
bool diagnostic_scope_derive_reader_diagnostic(const diagnostic_scope&    scope,
                                               const tlv_reader_format_t* format,
                                               const uint8_t* data, std::size_t size,
                                               std::size_t error_offset, tlv_result_t expected_code,
                                               tlv_reader_diagnostic_t* out);

} // namespace cli
#endif
