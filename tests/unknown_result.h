// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TEST_UNKNOWN_RESULT_H
#define OPENTLV_TEST_UNKNOWN_RESULT_H
#include "tlv/error.h"

// Unassigned but inside the C++ enum range (0..31). Both Codec and Query tests
// assert tlv_strerror(unknown_result) == "unknown error" to detect reassignment.
// The static assertion below checks only the lower bound, not unassignedness.
constexpr tlv_result_t unknown_result = static_cast<tlv_result_t>(22);
static_assert(TLV_ERR_TRUNCATED < unknown_result, "Choose a new unassigned test result");
#endif
