// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_GENERATOR_HPP
#define OPENTLV_TLVPP_GENERATOR_HPP
#include "tlv/generator.h"
#include "tlv++/format.hpp"
/** @file
 * @brief C++ facade for the canonical deterministic wire generator.
 */
namespace tlv {
/** @brief Borrowed candidate descriptor; constructed tags use the Format classifier. */
using generator_candidate = tlv_generator_candidate_t;
/** @brief Generator configuration with the limits and lifetime contract of the C API. */
using generator_options = tlv_generator_options_t;
/** @brief Build a generator candidate from a borrowed semantic Tag.
 * @param[in] tag Identifier whose bytes must outlive generation.
 * @param[in] minimum Inclusive minimum Value size in bytes.
 * @param[in] maximum Inclusive maximum Value size in bytes.
 * @return A candidate descriptor; generation validates its interval.
 */
inline generator_candidate make_generator_candidate(tlv::tag tag, size_t minimum, size_t maximum) {
    return {detail::semantic_access::get(tag), minimum, maximum};
}
/** @brief Compute scratch storage required by the native generator.
 * @param[in] options Immutable generator configuration.
 * @return Required bytes, or the canonical validation/overflow error.
 */
inline expected<size_t, error> generator_workspace_size(const generator_options& options) {
    size_t size = 0;
    auto   rc = tlv_generator_workspace_size(&options, &size);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return size;
}
/** @brief Generate one reproducible wire case without retaining caller storage.
 * @param[in] format Borrowed readable and writable Format.
 * @param[in] options Immutable configuration; borrowed candidates must outlive the call.
 * @param[out] output Destination, at least options.max_case_size bytes.
 * @param[in,out] workspace Disjoint scratch storage of generator_workspace_size() bytes.
 * @return Complete wire byte count, or the canonical generator error.
 * @warning On failure destination and workspace bytes may have changed.
 */
inline expected<size_t, error> generate(tlv::format format, const generator_options& options,
                                        span<byte> output, span<byte> workspace) {
    size_t size = 0;
    auto   rc = tlv_generate(&detail::format_access::get(format), &options,
                             reinterpret_cast<uint8_t*>(output.data()), output.size(),
                             reinterpret_cast<uint8_t*>(workspace.data()), workspace.size(), &size);
    if (rc != TLV_OK) return unexpected<error>(error::from_c(rc));
    return size;
}
} // namespace tlv
#endif
