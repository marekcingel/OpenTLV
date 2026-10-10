// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Standalone cross-revision C/C++ Reader comparison; see scripts/reader_api_comparison.py.
#include "tlv++/reader/reader.hpp"
#include "tlv++/formats/fixed_format.hpp"
#include "tlv++/builtins/asn1/ber.hpp"
#include "tlv/reader/reader.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using clock_type = std::chrono::steady_clock;
#ifdef OPENTLV_LEGACY_FACADE
using fixed_format = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;
#else
using fixed_format = tlv::fixed_format<1, 1>;
#endif

template <class Format>
__attribute__((noinline)) unsigned long long run_cpp(const char* work, const tlv::bytes input,
                                                     size_t count) {
    tlv::reader<Format> reader(input, std::strcmp(work, "incremental") == 0
                                          ? tlv::input_mode::incremental
                                          : tlv::input_mode::final);
    unsigned long long  checksum = 0;
    if (std::strcmp(work, "range") == 0) {
        for (const auto element : reader) {
            checksum += element.value().size() + static_cast<unsigned>(element.value()[0]);
        }
    } else {
        const bool failing =
            std::strcmp(work, "failed") == 0 || std::strcmp(work, "incremental") == 0;
        const auto expected =
            std::strcmp(work, "incremental") == 0 ? TLV_NEED_MORE_DATA : TLV_ERR_TRUNCATED;
        for (size_t i = 0; i < count; ++i) {
            auto result = reader.next();
            if (failing) {
                const auto code =
                    result ? TLV_OK : static_cast<tlv_result_t>(result.error().status());
                if (code != expected) std::abort();
                checksum += static_cast<unsigned>(code);
            } else {
                if (!result) std::abort();
                checksum += result->value().size() + static_cast<unsigned>(result->value()[0]);
            }
        }
    }
    return checksum;
}

__attribute__((noinline)) unsigned long long run_c(const char* work, const tlv::bytes input,
                                                   size_t count, const tlv_format_t* format,
                                                   bool diagnostic) {
    tlv_reader_t reader;
    if ((std::strcmp(work, "incremental") == 0
             ? tlv_reader_init_incremental(&reader, reinterpret_cast<const uint8_t*>(input.data()),
                                           input.size(), format)
             : tlv_reader_init(&reader, reinterpret_cast<const uint8_t*>(input.data()),
                               input.size(), format)) != TLV_OK)
        std::abort();
    tlv_element_t           element;
    tlv_reader_diagnostic_t detail;
    unsigned long long      checksum = 0;
    const bool failing = std::strcmp(work, "failed") == 0 || std::strcmp(work, "incremental") == 0;
    const auto expected =
        std::strcmp(work, "incremental") == 0 ? TLV_NEED_MORE_DATA : TLV_ERR_TRUNCATED;
    for (size_t i = 0; i < count; ++i) {
        const auto rc = diagnostic ? tlv_reader_next_diag(&reader, &element, &detail)
                                   : tlv_reader_next(&reader, &element);
        if (failing) {
            if (rc != expected) std::abort();
            checksum += static_cast<unsigned>(rc);
        } else {
            if (rc != TLV_OK) std::abort();
            checksum += element.value.size + element.value.data[0];
        }
    }
    return checksum;
}

int main(int argc, char** argv) {
    if (argc != 5) return 2;
    const char* work = argv[1];
    if (std::strcmp(work, "next") != 0 && std::strcmp(work, "range") != 0 &&
        std::strcmp(work, "failed") != 0 && std::strcmp(work, "incremental") != 0)
        return 2;
    if (std::strcmp(argv[2], "ber") != 0 && std::strcmp(argv[2], "fixed") != 0) return 2;
    const bool  ber = std::strcmp(argv[2], "ber") == 0;
    const char* api = argv[3];
    if (std::strcmp(api, "cpp") != 0 && std::strcmp(api, "c") != 0 &&
        std::strcmp(api, "c_diag") != 0)
        return 2;
    if (std::strcmp(work, "range") == 0 && std::strcmp(api, "cpp") != 0) return 2;
    const size_t count = std::strtoull(argv[4], nullptr, 10);
    if (!count || count > static_cast<size_t>(-1) / 3) return 2;
    const bool failing = std::strcmp(work, "failed") == 0 || std::strcmp(work, "incremental") == 0;
    std::vector<tlv::byte> wire(failing ? 2 : 3 * count);
    if (failing) {
        wire[0] = tlv::byte(4);
        wire[1] = tlv::byte(1);
    } else {
        for (size_t i = 0; i < count; ++i) {
            wire[3 * i] = tlv::byte(4);
            wire[3 * i + 1] = tlv::byte(1);
            wire[3 * i + 2] = tlv::byte(i & 255u);
        }
    }
    const tlv::bytes         input(wire.data(), wire.size());
    const tlv_fixed_format_t config = {
        {1}, {1, TLV_BYTE_ORDER_BIG_ENDIAN}, TLV_ELEMENT_ORDER_TLV, TLV_LENGTH_SCOPE_VALUE};
    tlv_format_t fixed;
    if (tlv_fixed_format_init(&fixed, &config) != TLV_OK) return 3;
    const auto         start = clock_type::now();
    unsigned long long sum;
    if (std::strcmp(api, "cpp") == 0)
        sum = ber ? run_cpp<tlv::ber::format>(work, input, count)
                  : run_cpp<fixed_format>(work, input, count);
    else
        sum = run_c(work, input, count, ber ? &tlv_format_ber : &fixed,
                    std::strcmp(api, "c_diag") == 0);
    const double ns = std::chrono::duration<double, std::nano>(clock_type::now() - start).count();
    unsigned long long expected_sum = 0;
    if (failing) {
        const auto expected =
            std::strcmp(work, "incremental") == 0 ? TLV_NEED_MORE_DATA : TLV_ERR_TRUNCATED;
        expected_sum = static_cast<unsigned>(expected) * static_cast<unsigned long long>(count);
    } else {
        expected_sum = count;
        for (size_t i = 0; i < count; ++i) expected_sum += i & 255u;
    }
    if (sum != expected_sum) return 4;
    std::printf("%.3f,%llu,%zu,%zu\n", ns, sum, sizeof(tlv::error),
                sizeof(tlv::expected<tlv::element_view, tlv::error>));
}
