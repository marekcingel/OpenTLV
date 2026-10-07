// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#ifndef OPENTLV_TLVPP_VISITOR_HPP
#define OPENTLV_TLVPP_VISITOR_HPP
#include "tlv/reader/visitor.h"
/** @file
 * @brief Synchronous C++ traversal control.
 */
namespace tlv {
/** @brief Synchronous visitor decision; stopping succeeds without consuming another element. */
enum class visit_control {
    next = TLV_VISIT_CONTINUE, /**< Continue traversal. */
    stop = TLV_VISIT_STOP,     /**< Stop successfully. */
    error = TLV_VISIT_ERROR    /**< Abort with a visitor failure. */
};
} // namespace tlv
#endif
