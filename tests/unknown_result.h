// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_TEST_UNKNOWN_RESULT_H
#define OPENTLV_TEST_UNKNOWN_RESULT_H
#include "tlv/error.h"

// Unassigned but inside the C++ enum range (0..31). Tests also check tlv_strerror.
constexpr tlv_result_t unknown_result = static_cast<tlv_result_t>(21);
static_assert(TLV_ERR_CALLBACK < unknown_result, "Choose a new unassigned test result");
#endif
