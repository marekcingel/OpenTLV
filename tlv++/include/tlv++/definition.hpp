#ifndef OPENTLV_TLVPP_DEFINITION_HPP
#define OPENTLV_TLVPP_DEFINITION_HPP
#include "tlv++/types.hpp"
#include "tlv/definition.h"

/** @file definition.hpp
 * @brief Borrowed generic identifier metadata and canonical registry lookup.
 */
namespace tlv {
/** @brief Identifier and optional borrowed name, without Schema or Codec policy. */
using definition = tlv_definition_t;

/** @brief Registry view; caller retains entries, identifier bytes and names. */
class definition_registry {
public:
    /** @brief Borrow an immutable registry table.
     * @param entries Definitions whose storage must outlive this view and lookup results.
     */
    explicit definition_registry(span<const definition> entries)
        : raw_{entries.data(), entries.size()} {}
    /** @brief Look up the first matching identifier through the C engine.
     * @param tag Canonical identifier, borrowed for this call.
     * @return Borrowed table entry, or nullptr when no entry matches.
     */
    TLV_NODISCARD const definition* find(tag_t tag) const {
        return tlv_definition_find(&raw_, &tag);
    }

private:
    tlv_definition_registry_t raw_;
};
} // namespace tlv
#endif
