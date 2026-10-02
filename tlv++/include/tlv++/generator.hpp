// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_GENERATOR_HPP
#define OPENTLV_TLVPP_GENERATOR_HPP
#include "tlv/generator.h"
#include "tlv++/format.hpp"
#include <vector>
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
/**
 * @brief Reusable C++ generator with owned scratch storage and owned case results.
 *
 * All validation and generation delegate to the native C generator. Configuration
 * is copied; Format descriptor/context, candidate table and identifier bytes are
 * borrowed and must remain alive and unchanged for the generator's lifetime.
 * Use value initialization (`generator_options options{}`) before setting limits
 * and candidates. The configured case_index is ignored by generate(case_index).
 * Scratch storage is allocated lazily and reused. Separate results own their bytes
 * and remain valid after subsequent calls or destruction of the generator.
 * Concurrent calls on the same instance require external synchronization.
 */
class generator {
public:
    /**
     * @brief Copy configuration and borrow a readable, writable Format.
     * @param[in] format Immutable borrowed Format; use native::borrow_format() for C descriptors.
     * @param[in] options Limits, seed and borrowed candidate domain, validated on generation.
     * @note Construction performs no allocation or generation.
     */
    generator(tlv::format format, const generator_options& options)
        : format_(format), options_(options) {}

    /**
     * @brief Generate an independently reproducible case into owned bytes.
     * @param[in] case_index Random-access case index; zero is valid.
     * @return Complete wire bytes, or the canonical C validation/generation error.
     * @throws std::bad_alloc If C++ storage allocation fails.
     * @throws std::length_error If required storage exceeds vector's maximum size.
     * @note Call order does not affect output. Failed calls expose no partial result
     * and do not invalidate previous results. C++ ownership may allocate; the native
     * generator remains allocation-free. No Schema or Codec validity is inferred.
     */
    TLV_NODISCARD expected<std::vector<byte>, error> generate(uint64_t case_index) {
        auto options = options_;
        options.case_index = case_index;
        if (!format_.readable() || !format_.writable())
            return unexpected<error>(error::from_c(TLV_ERR_NULL_ARG));
        auto required = generator_workspace_size(options);
        if (!required) return unexpected<error>(required.error());
        workspace_.resize(*required);
        std::vector<byte> output(options.max_case_size);
        auto result = tlv::generate(format_, options, span<byte>{output.data(), output.size()},
                                    span<byte>{workspace_.data(), workspace_.size()});
        if (!result) return unexpected<error>(result.error());
        output.resize(*result);
        return output;
    }

private:
    tlv::format       format_;
    generator_options options_;
    std::vector<byte> workspace_;
};
} // namespace tlv
#endif
