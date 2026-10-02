// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// C++11, namespace entry points and allocation guarantees, without GoogleTest.
#include "tlv++/tlv.hpp"
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
bool   observe_allocations = false;
size_t allocations = 0;
struct leaf {
    size_t* calls;
    void    operator()(tlv::writer_builder& writer) const {
        ++*calls;
        const uint8_t value[] = {42};
        writer.write(tlv::tag_bytes<4>(), value);
    }
};
} // namespace
void* operator new(size_t size) {
    if (observe_allocations) ++allocations;
    if (auto* result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void* operator new[](size_t size) {
    return ::operator new(size);
}
void operator delete(void* pointer) noexcept {
    std::free(pointer);
}
void operator delete[](void* pointer) noexcept {
    std::free(pointer);
}
#if __cplusplus >= 201402L
void operator delete(void* pointer, size_t) noexcept {
    std::free(pointer);
}
void operator delete[](void* pointer, size_t) noexcept {
    std::free(pointer);
}
#endif

#define CHECK_DOMAIN(domain, first, second)                                                        \
    {                                                                                              \
        tlv::byte output[16]{}, generic[16]{}, explicit_output[16]{};                              \
        size_t    calls = 0;                                                                       \
        auto      encoded = tlv::domain::encode<16, 1>(output, leaf{&calls});                      \
        auto      equivalent = tlv::encode<tlv::domain::format, 16, 1>(generic, leaf{&calls});     \
        tlv::writer_storage<16, 1> storage;                                                        \
        auto explicit_result = tlv::domain::encode(explicit_output, storage.view(), leaf{&calls}); \
        if (!encoded || !equivalent || !explicit_result || calls != 3 || *encoded != 3 ||          \
            *equivalent != 3 || *explicit_result != 3)                                             \
            return __LINE__;                                                                       \
        const uint8_t expected[] = {first, second, 42};                                            \
        if (std::memcmp(output, expected, 3) || std::memcmp(output, generic, 3) ||                 \
            std::memcmp(output, explicit_output, 3))                                               \
            return __LINE__;                                                                       \
        size_t count = 0;                                                                          \
        for (auto element : tlv::domain::parse({output, *encoded})) {                              \
            if (element.tag() != tlv::tag_bytes<4>() || element.value().size() != 1 ||             \
                element.value().data() != output + 2)                                              \
                return __LINE__;                                                                   \
            ++count;                                                                               \
        }                                                                                          \
        if (count != 1) return __LINE__;                                                           \
        tlv::reader<tlv::domain::format> cursor({output, *encoded});                               \
        if (!cursor.next()) return __LINE__;                                                       \
        auto short_output =                                                                        \
            tlv::domain::encode<16, 1>(tlv::span<tlv::byte>{output, 2}, leaf{&calls});             \
        auto generic_failure = tlv::encode<tlv::domain::format, 16, 1>(                            \
            tlv::span<tlv::byte>{generic, 2}, leaf{&calls});                                       \
        if (short_output || generic_failure ||                                                     \
            short_output.error().code != generic_failure.error().code)                             \
            return __LINE__;                                                                       \
    }

int main() {
    observe_allocations = true;
    using custom_format = tlv::fixed_format<1, 1, TLV_BYTE_ORDER_BIG_ENDIAN>;
    using custom_field = tlv::field<tlv::tag_constant<4>, uint8_t>;
    tlv::byte generic_output[3]{};
    size_t    generic_calls = 0;
    auto generic_result = tlv::encode<custom_format, 16, 1>(generic_output, leaf{&generic_calls});
    if (!generic_result || *generic_result != 3 || generic_calls != 1) return 5;
    for (auto element : tlv::parse<custom_format>({generic_output, *generic_result})) {
        auto number = element.decode<custom_field>();
        if (!number || *number != 42) return 6;
    }
#if OPENTLV_FORMAT_BER
    CHECK_DOMAIN(ber, 4, 1)
    const uint8_t truth[] = {0xFF};
    auto boolean = tlv::asn1::boolean_codec::decode({reinterpret_cast<const tlv::byte*>(truth), 1});
    if (!boolean || !*boolean) return 1;
#endif
#if OPENTLV_FORMAT_DER
    CHECK_DOMAIN(der, 4, 1)
#endif
#if OPENTLV_FORMAT_CER
    CHECK_DOMAIN(cer, 4, 1)
#endif
#if OPENTLV_EMV
    CHECK_DOMAIN(emv, 4, 1)
    const uint8_t amount[] = {0, 0, 0, 0, 0x12, 0x34};
    auto number = tlv::emv::amount_codec::decode({reinterpret_cast<const tlv::byte*>(amount), 6});
    if (!number || *number != 1234) return 2;
#endif
#if OPENTLV_BLUETOOTH
    CHECK_DOMAIN(bluetooth, 2, 4)
    const uint8_t service[] = {0x0F, 0x18, 42};
    auto          value = tlv::bluetooth::service_data16_codec::decode(
        {reinterpret_cast<const tlv::byte*>(service), 3});
    if (!value || value->uuid != 0x180F ||
        value->payload.data() != reinterpret_cast<const tlv::byte*>(service + 2))
        return 3;
#endif
#if OPENTLV_LLDP
    CHECK_DOMAIN(lldp, 8, 1)
#endif
#if OPENTLV_DHCP
    CHECK_DOMAIN(dhcp, 4, 1)
#endif
#if OPENTLV_NFC
    CHECK_DOMAIN(nfc, 4, 1)
#endif
    observe_allocations = false;
    return allocations ? 4 : 0;
}
