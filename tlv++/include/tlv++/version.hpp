// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TLVPP_VERSION_HPP
#define OPENTLV_TLVPP_VERSION_HPP
#include "tlv/version.h"
/** @file
 * @brief Version of the linked canonical library.
 */
namespace tlv {
/** @brief Borrow the immutable program-lifetime version string of the linked library. */
inline const char* version() noexcept {
    return tlv_version_string();
}
} // namespace tlv
#endif
