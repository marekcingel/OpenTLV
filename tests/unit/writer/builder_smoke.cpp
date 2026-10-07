// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// C++11 and allocation checks independent of GoogleTest's language requirements.
#include "tlv++/writer/builder.hpp"
#include "custom_cpp_format.hpp"
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
bool   observe_allocations = false;
size_t allocation_count = 0;
struct moving_format : custom_cpp_format {
    moving_format() {
        trailer = 0xEE;
    }
    moving_format(moving_format&& other) : custom_cpp_format(other) {
        other.trailer = 0;
    }
    moving_format(const moving_format&) = delete;
};

template <typename T, typename = void> struct writable : std::false_type {};
template <typename...> struct test_void {
    using type = void;
};
template <typename T>
struct writable<T, typename test_void<decltype(std::declval<tlv::writer_builder&>().write(
                       tlv::tag_bytes<1>(), std::declval<const T&>()))>::type> : std::true_type {};
static_assert(!writable<unsigned>::value, "Numeric representation must be explicit");
static_assert(!writable<const char*>::value, "Do not allocate a string from a raw pointer");
static_assert(!writable<std::array<unsigned, 2>>::value, "Do not serialize host objects");
static_assert(writable<std::array<uint8_t, 2>>::value, "Byte arrays must be supported");
static_assert(!std::is_copy_constructible<tlv::writer_builder>::value, "No shared frame copies");
} // namespace

void* operator new(size_t size) {
    if (observe_allocations) ++allocation_count;
    if (void* result = std::malloc(size ? size : 1)) return result;
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

int main() {
    tlv::byte         output[32]{};
    const std::string text("string longer than small string optimization storage");
    observe_allocations = true;
    tlv::expected<void, tlv::error> success;
    auto                            copied = success;
    auto                            moved = std::move(copied);
    copied = success;
    moved = std::move(copied);
    if (!moved) return 8;
    auto result = tlv::encode<moving_format, 32, 2>(
        output,
        [](tlv::writer_builder& writer) {
            writer.constructed<0xE1>([](tlv::writer_builder& parent) {
                const uint8_t value[] = {42};
                parent.write<1>(value);
            });
        },
        moving_format{});
    if (!result || *result != 7) return 1;
    const uint8_t expected[] = {0xE1, 4, 1, 1, 42, 0xEE, 0xEE};
    if (std::memcmp(output, expected, sizeof(expected))) return 2;
    auto failure = tlv::encode<moving_format, 0, 1>(
        output,
        [](tlv::writer_builder& writer) {
            writer.constructed<0xE1>([](tlv::writer_builder& parent) { parent.write<1>(""); });
        },
        moving_format{});
    if (failure || failure.error().status() != tlv::errc::buffer_too_short) return 3;
    if (!failure.error().message()) return 4;
    auto overflow = tlv::encode<moving_format>(
        output, [&](tlv::writer_builder& writer) { writer.write<1>(text); }, moving_format{});
    if (overflow || overflow.error().status() != tlv::errc::buffer_too_short) return 5;
    tlv::writer<moving_format> sequential(output, sizeof(output), moving_format{});
    if (!sequential.write<1>("A")) return 6;
    observe_allocations = false;
    return allocation_count == 0 ? 0 : 7;
}
