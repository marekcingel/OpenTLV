// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/config.h"
#include "tlv/document/document.h"
#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>
#if OPENTLV_FORMAT_BER
#include "tlv/builtins/asn1/ber.h"
#endif

using Builder = std::unique_ptr<tlv_document_builder_t, decltype(&tlv_document_builder_free)>;

namespace {
using Bytes = std::vector<uint8_t>;

struct QueryCollection {
    std::vector<tlv_node_t*>  nodes;
    tlv_visit_result_t        command = TLV_VISIT_CONTINUE;
    static tlv_visit_result_t collect(tlv_node_t* node, void* context) {
        auto& self = *static_cast<QueryCollection*>(context);
        self.nodes.push_back(node);
        return self.command;
    }
};

// One-byte tags and lengths; 6F, A5 and A6 hold nested elements.
//   6F { 84 (AA BB), A5 { 50 (41 42) } }, 50 (FF)
const Bytes sample = {0x6F, 0x0A, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04,
                      0x50, 0x02, 0x41, 0x42, 0x50, 0x01, 0xFF};

int is_constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5 || tag->data[0] == 0xA6);
}

tlv_format_t constructed_format() {
    tlv_format_t result = controlled::format;
    result.is_constructed = is_constructed;
    return result;
}
const tlv_format_t controlled_constructed_format = constructed_format();

tlv_document_options_t options() {
    tlv_document_options_t result;
    EXPECT_EQ(TLV_OK, tlv_document_options_init(&result, &controlled_constructed_format));
    return result;
}

// Owns a document for the duration of a test.
struct Doc {
    tlv_document_t* handle = nullptr;
    Doc() = default;
    Doc(const Doc&) = delete;
    Doc& operator=(const Doc&) = delete;
    Doc(Doc&& other) noexcept : handle(other.handle) {
        other.handle = nullptr;
    }
    ~Doc() {
        tlv_document_free(handle);
    }
    tlv_document_t* get() const {
        return handle;
    }
};

Doc parse(const Bytes& data, const tlv_document_options_t& opts = options(),
          size_t* offset = nullptr) {
    Doc doc;
    EXPECT_EQ(TLV_OK, tlv_document_parse(data.data(), data.size(), &opts, &doc.handle, offset));
    return doc;
}

Bytes encode(const tlv_document_t* doc) {
    size_t size = 0;
    EXPECT_EQ(TLV_OK, tlv_document_encoded_size(doc, &size));
    Bytes  out(size);
    size_t written = 0;
    EXPECT_EQ(TLV_OK, tlv_document_encode(doc, out.data(), out.size(), &written));
    EXPECT_EQ(size, written);
    return out;
}

tlv_node_t* find(const tlv_document_t* doc, const char* path) {
    tlv_query_t query;
    EXPECT_EQ(TLV_OK, tlv_query_parse(path, &query, nullptr));
    return tlv_document_find_path(doc, &query);
}

Bytes value_of(const tlv_node_t* node) {
    const uint8_t* data = tlv_node_value_data(node);
    return Bytes(data, data + tlv_node_value_size(node));
}

bool tag_is(const tlv_node_t* node, uint8_t byte) {
    tlv_tag_t tag = tlv_node_tag(node);
    return tag.size == 1 && tag.data[0] == byte;
}

// Counts allocations, can fail the nth one and tracks what is still allocated.
struct Arena {
    size_t          allocations = 0;
    size_t          fail_at = SIZE_MAX;
    std::set<void*> live;
    static void*    allocate(void* context, size_t size) {
        Arena* arena = static_cast<Arena*>(context);
        if (arena->allocations++ == arena->fail_at) return nullptr;
        void* memory = ::operator new(size);
        arena->live.insert(memory);
        return memory;
    }
    static void release(void* context, void* memory) {
        Arena* arena = static_cast<Arena*>(context);
        EXPECT_EQ(1u, arena->live.erase(memory));
        ::operator delete(memory);
    }
    tlv_allocator_t allocator() {
        tlv_allocator_t result = {this, allocate, release};
        return result;
    }
};
} // namespace

TEST(Unit_Tlv_Document, ParsesNestedStructureAndKeepsOrder) {
    Doc doc = parse(sample);
    EXPECT_EQ(5u, tlv_document_count(doc.get()));

    tlv_node_t* outer = tlv_document_first(doc.get());
    ASSERT_NE(nullptr, outer);
    EXPECT_TRUE(tag_is(outer, 0x6F));
    EXPECT_TRUE(tlv_node_is_constructed(outer));
    EXPECT_EQ(nullptr, tlv_node_value_data(outer));
    EXPECT_EQ(0u, tlv_node_value_size(outer));
    EXPECT_EQ(nullptr, tlv_node_parent(outer));

    tlv_node_t* primitive = tlv_node_first_child(outer);
    ASSERT_NE(nullptr, primitive);
    EXPECT_TRUE(tag_is(primitive, 0x84));
    EXPECT_FALSE(tlv_node_is_constructed(primitive));
    EXPECT_EQ((Bytes{0xAA, 0xBB}), value_of(primitive));
    EXPECT_EQ(outer, tlv_node_parent(primitive));

    tlv_node_t* inner = tlv_node_next(primitive);
    ASSERT_NE(nullptr, inner);
    EXPECT_TRUE(tag_is(inner, 0xA5));
    EXPECT_EQ(nullptr, tlv_node_next(inner));
    EXPECT_EQ((Bytes{0x41, 0x42}), value_of(tlv_node_first_child(inner)));

    tlv_node_t* last = tlv_node_next(outer);
    ASSERT_NE(nullptr, last);
    EXPECT_TRUE(tag_is(last, 0x50));
    EXPECT_EQ((Bytes{0xFF}), value_of(last));
    EXPECT_EQ(nullptr, tlv_node_next(last));
}

TEST(Unit_Tlv_Document, SourceLocationsOwnScalarsAndInvalidateOnlyAffectedNodes) {
    auto opts = options();
    EXPECT_EQ(0, opts.retain_source_locations);
    auto plain = parse(sample, opts);
    EXPECT_FALSE(tlv_node_source_location(tlv_document_first(plain.get())).has_offset);
    EXPECT_FALSE(tlv_node_source_location(nullptr).has_header_size);
    opts.retain_source_locations = 1;
    auto input = sample;
    auto doc = parse(input, opts);
    input.assign(input.size(), 0); // No location depends on the original bytes.
    auto root = tlv_document_first(doc.get());
    auto nested = find(doc.get(), "6F/A5");
    auto leaf = find(doc.get(), "6F/A5/50");
    auto sibling = tlv_node_next(root);
    auto location = tlv_node_source_location(root);
    EXPECT_TRUE(location.has_offset);
    EXPECT_EQ(0u, location.offset);
    EXPECT_TRUE(location.has_header_size);
    EXPECT_EQ(2u, location.header_size);
    EXPECT_EQ(8u, tlv_node_source_location(leaf).offset);
    EXPECT_EQ(12u, tlv_node_source_location(sibling).offset);
    const uint8_t invalid[] = {0x50, 2};
    EXPECT_NE(TLV_OK, tlv_node_set_value(nested, invalid, sizeof invalid));
    EXPECT_TRUE(tlv_node_source_location(root).has_offset);
    EXPECT_TRUE(tlv_node_source_location(nested).has_offset);
    EXPECT_EQ(8u, tlv_node_source_location(leaf).offset);
    const uint8_t replacement[] = {1, 2, 3};
    ASSERT_EQ(TLV_OK, tlv_node_set_value(leaf, replacement, sizeof replacement));
    EXPECT_FALSE(tlv_node_source_location(leaf).has_offset);
    EXPECT_FALSE(tlv_node_source_location(nested).has_header_size);
    EXPECT_FALSE(tlv_node_source_location(root).has_offset);
    EXPECT_EQ(2u, tlv_node_source_location(tlv_node_first_child(root)).offset);
    EXPECT_EQ(12u, tlv_node_source_location(sibling).offset);
    // Encoding shifts this sibling, but does not rewrite its original coordinate.
    EXPECT_NE(sample, encode(doc.get()));
    EXPECT_EQ(12u, tlv_node_source_location(sibling).offset);
}

TEST(Unit_Tlv_Document, InsertEraseAndReplacementDoNotInventSourceLocations) {
    auto opts = options();
    opts.retain_source_locations = 1;
    for (int operation = 0; operation != 3; ++operation) {
        SCOPED_TRACE(operation);
        auto          doc = parse(sample, opts);
        auto          root = tlv_document_first(doc.get());
        auto          nested = find(doc.get(), "6F/A5");
        auto          sibling = tlv_node_next(root);
        const uint8_t wire[] = {0x50, 0};
        if (operation == 0) {
            const uint8_t tag = 0xA6;
            tlv_node_t*   inserted = nullptr;
            ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), nested, nullptr, tlv_tag(&tag, 1),
                                                  wire, sizeof wire, &inserted));
            EXPECT_FALSE(tlv_node_source_location(inserted).has_offset);
            EXPECT_FALSE(tlv_node_source_location(tlv_node_first_child(inserted)).has_offset);
            EXPECT_EQ(8u, tlv_node_source_location(tlv_node_first_child(nested)).offset);
        } else if (operation == 1) {
            tlv_node_erase(tlv_node_first_child(nested));
        } else {
            ASSERT_EQ(TLV_OK, tlv_node_set_value(nested, wire, sizeof wire));
            EXPECT_FALSE(tlv_node_source_location(tlv_node_first_child(nested)).has_offset);
        }
        EXPECT_FALSE(tlv_node_source_location(nested).has_offset);
        EXPECT_FALSE(tlv_node_source_location(root).has_header_size);
        EXPECT_EQ(12u, tlv_node_source_location(sibling).offset);
    }
}

TEST(Unit_Tlv_Document, FailedAllocationPreservesSourceLocations) {
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    opts.retain_source_locations = 1;
    {
        auto doc = parse(sample, opts);
        auto leaf = find(doc.get(), "6F/A5/50");
        arena.fail_at = arena.allocations;
        const uint8_t value = 3;
        EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, tlv_node_set_value(leaf, &value, 1));
        EXPECT_EQ(8u, tlv_node_source_location(leaf).offset);
        EXPECT_TRUE(tlv_node_source_location(tlv_document_first(doc.get())).has_offset);
    }
    EXPECT_TRUE(arena.live.empty());
}

TEST(Unit_Tlv_Document, EmptyInputGivesEmptyDocument) {
    Doc doc = parse(Bytes());
    EXPECT_EQ(0u, tlv_document_count(doc.get()));
    EXPECT_EQ(nullptr, tlv_document_first(doc.get()));
    EXPECT_TRUE(encode(doc.get()).empty());

    size_t written = 99;
    EXPECT_EQ(TLV_OK, tlv_document_encode(doc.get(), nullptr, 0, &written));
    EXPECT_EQ(0u, written);
}

TEST(Unit_Tlv_Document, EmptyConstructedElementRoundTrips) {
    const Bytes wire = {0xA5, 0x00, 0x50, 0x00};
    Doc         doc = parse(wire);
    EXPECT_EQ(2u, tlv_document_count(doc.get()));
    tlv_node_t* container = tlv_document_first(doc.get());
    EXPECT_TRUE(tlv_node_is_constructed(container));
    EXPECT_EQ(nullptr, tlv_node_first_child(container));
    EXPECT_EQ(wire, encode(doc.get()));
}

TEST(Unit_Tlv_Document, UnmodifiedDocumentEncodesToTheInput) {
    Doc doc = parse(sample);
    EXPECT_EQ(sample, encode(doc.get()));
}

TEST(Unit_Tlv_Document, DoesNotReferToTheInputBuffer) {
    Bytes input = sample;
    Doc   doc = parse(input);
    input.assign(input.size(), 0);
    EXPECT_EQ(sample, encode(doc.get()));
}

TEST(Unit_Tlv_Document, OpaqueValuesWhenNoPredicate) {
    tlv_document_options_t opts = options();
    tlv_format_t           opaque_format = controlled_constructed_format;
    opaque_format.is_constructed = nullptr;
    opts.format = &opaque_format;
    Doc doc = parse(sample, opts);
    EXPECT_EQ(2u, tlv_document_count(doc.get()));
    tlv_node_t* outer = tlv_document_first(doc.get());
    EXPECT_FALSE(tlv_node_is_constructed(outer));
    EXPECT_EQ(10u, tlv_node_value_size(outer));
    EXPECT_EQ(sample, encode(doc.get()));
}

TEST(Unit_Tlv_Document, FindsByTagAndPath) {
    const Bytes wire = {0x50, 0x01, 0x01, 0x6F, 0x03, 0x84, 0x01, 0x02, 0x50,
                        0x01, 0x03, 0x6F, 0x05, 0xA5, 0x03, 0x50, 0x01, 0x04};
    Doc         doc = parse(wire);

    tlv_node_t* first = tlv_document_find(doc.get(), nullptr, TLV_TAG(0x50));
    ASSERT_NE(nullptr, first);
    EXPECT_EQ((Bytes{0x01}), value_of(first));
    EXPECT_EQ((Bytes{0x03}), value_of(tlv_node_next_same_tag(first)));
    EXPECT_EQ(nullptr, tlv_node_next_same_tag(tlv_node_next_same_tag(first)));
    EXPECT_EQ(nullptr, tlv_document_find(doc.get(), nullptr, TLV_TAG(0x51)));
    EXPECT_EQ(nullptr, tlv_document_find(doc.get(), nullptr, TLV_TAG(0x50, 0x01)));

    tlv_node_t* container = tlv_document_find(doc.get(), nullptr, TLV_TAG(0x6F));
    ASSERT_NE(nullptr, container);
    EXPECT_TRUE(tag_is(tlv_document_find(doc.get(), container, TLV_TAG(0x84)), 0x84));
    EXPECT_EQ(nullptr, tlv_document_find(doc.get(), container, TLV_TAG(0xA5)));

    // The first 6F has no A5; the search continues with the second.
    tlv_node_t* deep = find(doc.get(), "6F/A5/50");
    ASSERT_NE(nullptr, deep);
    EXPECT_EQ((Bytes{0x04}), value_of(deep));
    EXPECT_EQ(nullptr, find(doc.get(), "6F/A5/51"));
    EXPECT_EQ(nullptr, find(doc.get(), "50/50"));
    EXPECT_EQ(first, find(doc.get(), "50"));

    tlv_query_t empty = {};
    EXPECT_EQ(nullptr, tlv_document_find_path(doc.get(), &empty));
    EXPECT_EQ(nullptr, tlv_document_find_path(doc.get(), nullptr));
    EXPECT_EQ(nullptr, tlv_document_find_path(nullptr, &empty));
}

TEST(Unit_Tlv_Document, SetValueOnPrimitiveUpdatesEnclosingLengths) {
    Doc         doc = parse(sample);
    tlv_node_t* leaf = find(doc.get(), "6F/A5/50");
    const Bytes replacement = {0x41, 0x42, 0x43};
    ASSERT_EQ(TLV_OK, tlv_node_set_value(leaf, replacement.data(), replacement.size()));
    EXPECT_EQ((Bytes{0x6F, 0x0B, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x05, 0x50, 0x03, 0x41, 0x42, 0x43,
                     0x50, 0x01, 0xFF}),
              encode(doc.get()));
    EXPECT_EQ(5u, tlv_document_count(doc.get()));

    ASSERT_EQ(TLV_OK, tlv_node_set_value(leaf, nullptr, 0));
    EXPECT_EQ(0u, tlv_node_value_size(leaf));
    EXPECT_EQ((Bytes{0x6F, 0x08, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x02, 0x50, 0x00, 0x50, 0x01, 0xFF}),
              encode(doc.get()));

    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_node_set_value(nullptr, replacement.data(), 1));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_node_set_value(leaf, nullptr, 1));
}

TEST(Unit_Tlv_Document, SetValueOnConstructedReplacesChildren) {
    Doc         doc = parse(sample);
    tlv_node_t* container = find(doc.get(), "6F/A5");
    const Bytes contents = {0x50, 0x01, 0x07, 0x50, 0x01, 0x08};
    ASSERT_EQ(TLV_OK, tlv_node_set_value(container, contents.data(), contents.size()));
    EXPECT_EQ(6u, tlv_document_count(doc.get()));
    EXPECT_EQ((Bytes{0x6F, 0x0C, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x06, 0x50, 0x01, 0x07, 0x50, 0x01,
                     0x08, 0x50, 0x01, 0xFF}),
              encode(doc.get()));

    const Bytes before = encode(doc.get());
    const Bytes malformed = {0x50, 0x05, 0x01};
    size_t      count = tlv_document_count(doc.get());
    EXPECT_NE(TLV_OK, tlv_node_set_value(container, malformed.data(), malformed.size()));
    EXPECT_EQ(count, tlv_document_count(doc.get()));
    EXPECT_EQ(before, encode(doc.get()));

    ASSERT_EQ(TLV_OK, tlv_node_set_value(container, nullptr, 0));
    EXPECT_EQ(nullptr, tlv_node_first_child(container));
    EXPECT_EQ(4u, tlv_document_count(doc.get()));
}

TEST(Unit_Tlv_Document, InsertAppendsPrependsAndNests) {
    Doc         doc = parse(sample);
    tlv_node_t* top = tlv_document_first(doc.get());
    tlv_node_t* appended = nullptr;
    const Bytes payload = {0x01, 0x02};
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x51),
                                          payload.data(), payload.size(), &appended));
    EXPECT_EQ(payload, value_of(appended));
    ASSERT_EQ(TLV_OK,
              tlv_document_insert(doc.get(), nullptr, top, TLV_TAG(0x52), nullptr, 0, nullptr));
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), top, nullptr, TLV_TAG(0x53), payload.data(), 1,
                                          nullptr));
    EXPECT_EQ((Bytes{0x52, 0x00, 0x6F, 0x0D, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50, 0x02,
                     0x41, 0x42, 0x53, 0x01, 0x01, 0x50, 0x01, 0xFF, 0x51, 0x02, 0x01, 0x02}),
              encode(doc.get()));
    EXPECT_EQ(8u, tlv_document_count(doc.get()));

    // A constructed tag parses its value, so the inserted tree is navigable.
    const Bytes nested = {0x50, 0x01, 0x09};
    tlv_node_t* inserted = nullptr;
    tlv_node_t* first_child = tlv_node_first_child(top);
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), top, first_child, TLV_TAG(0xA6), nested.data(),
                                          nested.size(), &inserted));
    EXPECT_TRUE(tlv_node_is_constructed(inserted));
    EXPECT_EQ((Bytes{0x09}), value_of(tlv_node_first_child(inserted)));
    EXPECT_EQ(inserted, tlv_node_first_child(top));
    EXPECT_EQ(top, tlv_node_parent(inserted));
    EXPECT_EQ(10u, tlv_document_count(doc.get()));
}

TEST(Unit_Tlv_Document, InsertRejectsInvalidPlacementAndTags) {
    Doc         doc = parse(sample);
    Doc         other = parse(sample);
    tlv_node_t* top = tlv_document_first(doc.get());
    tlv_node_t* leaf = find(doc.get(), "6F/84");
    const Bytes wire = encode(doc.get());
    const Bytes payload = {0x01};

    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_insert(doc.get(), leaf, nullptr, TLV_TAG(0x50),
                                                       payload.data(), 1, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_document_insert(doc.get(), tlv_document_first(other.get()), nullptr,
                                  TLV_TAG(0x50), payload.data(), 1, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_insert(doc.get(), nullptr, leaf, TLV_TAG(0x50),
                                                       payload.data(), 1, nullptr));
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_document_insert(doc.get(), top, top, TLV_TAG(0x50), payload.data(), 1, nullptr));
    // The one-byte format cannot write a two-byte tag or an empty tag.
    EXPECT_NE(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x50, 0x51),
                                          payload.data(), 1, nullptr));
    EXPECT_NE(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, tlv_tag(nullptr, 0),
                                          payload.data(), 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x50), nullptr, 1, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_insert(doc.get(), nullptr, nullptr,
                                                    tlv_tag(nullptr, 1), nullptr, 0, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_insert(nullptr, nullptr, nullptr, TLV_TAG(0x50), nullptr, 0, nullptr));
    // A malformed nested value is rejected without leaving anything behind.
    const Bytes malformed = {0x50, 0x09};
    EXPECT_NE(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0xA6),
                                          malformed.data(), malformed.size(), nullptr));

    EXPECT_EQ(5u, tlv_document_count(doc.get()));
    EXPECT_EQ(wire, encode(doc.get()));
}

TEST(Unit_Tlv_Document, EraseRemovesSubtreeAndRelinks) {
    Doc         doc = parse(sample);
    tlv_node_t* inner = find(doc.get(), "6F/A5");
    tlv_node_erase(inner);
    EXPECT_EQ(3u, tlv_document_count(doc.get()));
    EXPECT_EQ((Bytes{0x6F, 0x04, 0x84, 0x02, 0xAA, 0xBB, 0x50, 0x01, 0xFF}), encode(doc.get()));

    tlv_node_erase(find(doc.get(), "6F/84"));
    EXPECT_EQ(nullptr, tlv_node_first_child(tlv_document_first(doc.get())));
    EXPECT_EQ((Bytes{0x6F, 0x00, 0x50, 0x01, 0xFF}), encode(doc.get()));

    tlv_node_erase(tlv_document_first(doc.get()));
    EXPECT_EQ((Bytes{0x50, 0x01, 0xFF}), encode(doc.get()));
    tlv_node_erase(tlv_document_first(doc.get()));
    EXPECT_EQ(0u, tlv_document_count(doc.get()));
    EXPECT_EQ(nullptr, tlv_document_first(doc.get()));
    tlv_node_erase(nullptr);
}

TEST(Unit_Tlv_Document, EraseMiddleSiblingKeepsNeighboursLinked) {
    const Bytes wire = {0x50, 0x00, 0x51, 0x00, 0x52, 0x00};
    Doc         doc = parse(wire);
    tlv_node_t* middle = tlv_node_next(tlv_document_first(doc.get()));
    tlv_node_erase(middle);
    tlv_node_t* first = tlv_document_first(doc.get());
    tlv_node_t* last = tlv_node_next(first);
    EXPECT_TRUE(tag_is(last, 0x52));
    EXPECT_EQ(nullptr, tlv_node_next(last));
    EXPECT_EQ((Bytes{0x50, 0x00, 0x52, 0x00}), encode(doc.get()));
    // Appending after erasing the tail reaches the right place.
    tlv_node_erase(last);
    ASSERT_EQ(TLV_OK,
              tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x53), nullptr, 0, nullptr));
    EXPECT_EQ((Bytes{0x50, 0x00, 0x53, 0x00}), encode(doc.get()));
}

TEST(Unit_Tlv_Document, EncodesASingleNode) {
    Doc         doc = parse(sample);
    tlv_node_t* inner = find(doc.get(), "6F/A5");
    size_t      size = 0;
    ASSERT_EQ(TLV_OK, tlv_node_encoded_size(inner, &size));
    EXPECT_EQ(6u, size);
    Bytes  out(size);
    size_t written = 0;
    ASSERT_EQ(TLV_OK, tlv_node_encode(inner, out.data(), out.size(), &written));
    EXPECT_EQ((Bytes{0xA5, 0x04, 0x50, 0x02, 0x41, 0x42}), out);

    written = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_node_encode(inner, out.data(), 3, &written));
    EXPECT_EQ(6u, written);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_node_encode(nullptr, out.data(), out.size(), &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_node_encoded_size(inner, nullptr));
}

TEST(Unit_Tlv_Document, EncodeReportsRequiredSizeAndLeavesBufferUntouched) {
    Doc    doc = parse(sample);
    Bytes  small(4, 0xEE);
    size_t written = 0;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_document_encode(doc.get(), small.data(), small.size(), &written));
    EXPECT_EQ(sample.size(), written);
    EXPECT_EQ(Bytes(4, 0xEE), small);

    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_document_encode(doc.get(), nullptr, 0, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_encode(doc.get(), nullptr, 4, &written));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_encode(doc.get(), small.data(), 4, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_encode(nullptr, small.data(), 4, &written));

    Bytes exact(sample.size() + 3, 0xEE);
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), exact.data(), exact.size(), &written));
    EXPECT_EQ(sample.size(), written);
    EXPECT_EQ(0xEE, exact.back());
}

TEST(Unit_Tlv_Document, EncodeReportsValuesTheFormatCannotRepresent) {
    Doc         doc = parse(sample);
    tlv_node_t* leaf = find(doc.get(), "6F/A5/50");
    const Bytes big(300, 0x11);
    ASSERT_EQ(TLV_OK, tlv_node_set_value(leaf, big.data(), big.size()));
    size_t size = 77;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH, tlv_document_encoded_size(doc.get(), &size));
    EXPECT_EQ(77u, size);
    Bytes  out(1024);
    size_t written = 77;
    EXPECT_EQ(TLV_ERR_INVALID_LENGTH,
              tlv_document_encode(doc.get(), out.data(), out.size(), &written));
    EXPECT_EQ(77u, written);
    // Repairing the value repairs the document.
    ASSERT_EQ(TLV_OK, tlv_node_set_value(leaf, big.data(), 2));
    EXPECT_EQ(TLV_OK, tlv_document_encoded_size(doc.get(), &size));
}

TEST(Unit_Tlv_Document, EnforcesDepthAndElementLimits) {
    // 6F { A5 { A6 { 50 } } }
    const Bytes            deep = {0x6F, 0x08, 0xA5, 0x06, 0xA6, 0x04, 0x50, 0x02, 0x01, 0x02};
    tlv_document_options_t opts = options();
    Doc                    ok;
    opts.max_depth = 3;
    EXPECT_EQ(TLV_OK, tlv_document_parse(deep.data(), deep.size(), &opts, &ok.handle, nullptr));

    size_t offset = 0;
    Doc    rejected;
    opts.max_depth = 2;
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_document_parse(deep.data(), deep.size(), &opts, &rejected.handle, &offset));
    EXPECT_EQ(nullptr, rejected.handle);
    EXPECT_EQ(6u, offset);

    opts.max_depth = 3;
    opts.max_elements = 3;
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_document_parse(deep.data(), deep.size(), &opts, &rejected.handle, nullptr));
    opts.max_elements = 4;
    EXPECT_EQ(TLV_OK,
              tlv_document_parse(deep.data(), deep.size(), &opts, &rejected.handle, nullptr));
    tlv_document_free(rejected.handle);
    rejected.handle = nullptr;

    // Inserting and replacing honour the same limits, and replacing does not double count.
    tlv_document_t* full = nullptr;
    opts.max_elements = 4;
    ASSERT_EQ(TLV_OK, tlv_document_parse(deep.data(), deep.size(), &opts, &full, nullptr));
    Doc guard;
    guard.handle = full;
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_document_insert(full, nullptr, nullptr, TLV_TAG(0x50), nullptr, 0, nullptr));
    tlv_node_t* container = find(full, "6F/A5");
    const Bytes replacement = {0x50, 0x01, 0x01, 0x50, 0x01, 0x02};
    EXPECT_EQ(TLV_OK, tlv_node_set_value(container, replacement.data(), replacement.size()));
    EXPECT_EQ(4u, tlv_document_count(full));
    const Bytes too_many = {0x50, 0x00, 0x50, 0x00, 0x50, 0x00};
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_node_set_value(container, too_many.data(), too_many.size()));
    EXPECT_EQ(4u, tlv_document_count(full));

    // A replacement that nests deeper than the limit is rejected and changes nothing.
    tlv_document_options_t roomy = options();
    roomy.max_depth = 3;
    Doc         deep_doc = parse(deep, roomy);
    const Bytes too_deep = {0xA6, 0x04, 0xA5, 0x02, 0xA5, 0x00};
    const Bytes before = encode(deep_doc.get());
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_node_set_value(find(deep_doc.get(), "6F/A5"), too_deep.data(), too_deep.size()));
    EXPECT_EQ(before, encode(deep_doc.get()));

    roomy.max_depth = 0;
    Doc shallow;
    ASSERT_EQ(TLV_OK, tlv_document_create(&roomy, &shallow.handle));
    const Bytes level_one = {0xA5, 0x00};
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_document_insert(shallow.get(), nullptr, nullptr, TLV_TAG(0x6F),
                                                 level_one.data(), level_one.size(), nullptr));
    EXPECT_EQ(TLV_OK, tlv_document_insert(shallow.get(), nullptr, nullptr, TLV_TAG(0x6F), nullptr,
                                          0, nullptr));
    EXPECT_EQ(1u, tlv_document_count(shallow.get()));
}

TEST(Unit_Tlv_Document, ReportsAbsoluteOffsetOfMalformedNestedInput) {
    // The nested 50 claims five bytes but only one follows.
    const Bytes            wire = {0x50, 0x00, 0x6F, 0x04, 0x84, 0x00, 0x50, 0x05};
    tlv_document_options_t opts = options();
    tlv_document_t*        doc = nullptr;
    size_t                 offset = 0;
    EXPECT_NE(TLV_OK, tlv_document_parse(wire.data(), wire.size(), &opts, &doc, &offset));
    EXPECT_EQ(nullptr, doc);
    EXPECT_EQ(6u, offset);

    const Bytes truncated = {0x50, 0x05, 0x01};
    offset = 99;
    EXPECT_NE(TLV_OK, tlv_document_parse(truncated.data(), truncated.size(), &opts, &doc, &offset));
    EXPECT_EQ(0u, offset);
}

TEST(Unit_Tlv_Document, RejectsInvalidArguments) {
    tlv_document_options_t opts = options();
    tlv_document_t*        doc = reinterpret_cast<tlv_document_t*>(1);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_parse(nullptr, 1, &opts, &doc, nullptr));
    EXPECT_EQ(nullptr, doc);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_parse(sample.data(), sample.size(), nullptr, &doc, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_parse(sample.data(), sample.size(), &opts, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_create(&opts, nullptr));

    tlv_document_options_t broken = opts;
    broken.format = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_create(&broken, &doc));
    tlv_format_t write_only = controlled::format;
    write_only.decode = nullptr;
    broken = opts;
    broken.format = &write_only;
    ASSERT_EQ(TLV_OK, tlv_document_create(&broken, &doc));
    tlv_document_free(doc);
    tlv_format_t read_only = controlled::format;
    read_only.encode = nullptr;
    read_only.measure = nullptr;
    broken = opts;
    broken.format = &read_only;
    ASSERT_EQ(TLV_OK, tlv_document_create(&broken, &doc));
    tlv_document_free(doc);
    broken = opts;
    broken.max_depth = TLV_TREE_DEFAULT_DEPTH + 1;
    EXPECT_EQ(TLV_OK, tlv_document_create(&broken, &doc));
    tlv_document_free(doc);
    doc = nullptr;
    tlv_allocator_t incomplete = {nullptr, nullptr, nullptr};
    broken = opts;
    broken.allocator = &incomplete;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_create(&broken, &doc));

    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_options_init(nullptr, &controlled::format));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_options_init(&opts, nullptr));

    tlv_document_free(nullptr);
    EXPECT_EQ(0u, tlv_document_count(nullptr));
    EXPECT_EQ(nullptr, tlv_document_first(nullptr));
    EXPECT_EQ(nullptr, tlv_node_first_child(nullptr));
    EXPECT_EQ(nullptr, tlv_node_next(nullptr));
    EXPECT_EQ(nullptr, tlv_node_parent(nullptr));
    EXPECT_EQ(nullptr, tlv_node_next_same_tag(nullptr));
    EXPECT_EQ(nullptr, tlv_document_find(nullptr, nullptr, TLV_TAG(0x50)));
    EXPECT_EQ(0u, tlv_node_tag(nullptr).size);
    EXPECT_FALSE(tlv_node_is_constructed(nullptr));
    EXPECT_EQ(nullptr, tlv_node_value_data(nullptr));
    EXPECT_EQ(0u, tlv_node_value_size(nullptr));
}

TEST(Unit_Tlv_Document, UsesTheCallerAllocatorAndReleasesEverything) {
    Arena                  arena;
    tlv_allocator_t        allocator = arena.allocator();
    tlv_document_options_t opts = options();
    opts.allocator = &allocator;
    {
        Doc doc = parse(sample, opts);
        EXPECT_FALSE(arena.live.empty());
        const Bytes contents = {0x50, 0x01, 0x07};
        ASSERT_EQ(TLV_OK,
                  tlv_node_set_value(find(doc.get(), "6F/A5"), contents.data(), contents.size()));
        ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x51),
                                              contents.data(), contents.size(), nullptr));
        tlv_node_erase(find(doc.get(), "6F/84"));
        EXPECT_EQ(5u, tlv_document_count(doc.get()));
        encode(doc.get());
    }
    EXPECT_TRUE(arena.live.empty());
}

TEST(Unit_Tlv_Document, ParseAllocationFailuresLeaveNothingBehind) {
    bool succeeded = false;
    for (size_t fail_at = 0; fail_at < 64 && !succeeded; ++fail_at) {
        Arena                  arena;
        tlv_allocator_t        allocator = arena.allocator();
        tlv_document_options_t opts = options();
        opts.allocator = &allocator;
        arena.fail_at = fail_at;
        tlv_document_t* doc = nullptr;
        tlv_result_t    rc = tlv_document_parse(sample.data(), sample.size(), &opts, &doc, nullptr);
        if (rc == TLV_OK) {
            succeeded = true;
            tlv_document_free(doc);
        } else {
            EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc) << fail_at;
            EXPECT_EQ(nullptr, doc);
        }
        EXPECT_TRUE(arena.live.empty()) << fail_at;
    }
    EXPECT_TRUE(succeeded);
}

TEST(Unit_Tlv_Document, ModificationFailuresChangeNothing) {
    Arena                  arena;
    tlv_allocator_t        allocator = arena.allocator();
    tlv_document_options_t opts = options();
    opts.allocator = &allocator;
    Doc         doc = parse(sample, opts);
    const Bytes before = encode(doc.get());
    const Bytes contents = {0x50, 0x01, 0x07, 0x50, 0x02, 0x01, 0x02};

    bool set_done = false, insert_done = false;
    for (size_t offset = 0; offset < 16 && !(set_done && insert_done); ++offset) {
        if (!set_done) {
            arena.fail_at = arena.allocations + offset;
            tlv_result_t rc =
                tlv_node_set_value(find(doc.get(), "6F/A5"), contents.data(), contents.size());
            arena.fail_at = SIZE_MAX;
            set_done = rc == TLV_OK;
            if (!set_done) {
                EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc);
                EXPECT_EQ(before, encode(doc.get()));
                EXPECT_EQ(5u, tlv_document_count(doc.get()));
            }
        }
        if (!insert_done) {
            const size_t count = tlv_document_count(doc.get());
            arena.fail_at = arena.allocations + offset;
            tlv_result_t rc = tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0xA6),
                                                  contents.data(), contents.size(), nullptr);
            arena.fail_at = SIZE_MAX;
            insert_done = rc == TLV_OK;
            if (!insert_done) {
                EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc);
                EXPECT_EQ(count, tlv_document_count(doc.get()));
            }
        }
    }
    EXPECT_TRUE(set_done);
    EXPECT_TRUE(insert_done);
}

TEST(Unit_Tlv_Document, EncodingFailsCleanlyWhenTheTemporaryBufferCannotBeAllocated) {
    Arena                  arena;
    tlv_allocator_t        allocator = arena.allocator();
    tlv_document_options_t opts = options();
    opts.allocator = &allocator;
    Doc    doc = parse(sample, opts);
    Bytes  out(sample.size());
    size_t written = 0;
    arena.fail_at = arena.allocations;
    EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY,
              tlv_document_encode(doc.get(), out.data(), out.size(), &written));
    arena.fail_at = SIZE_MAX;
    EXPECT_EQ(TLV_OK, tlv_document_encode(doc.get(), out.data(), out.size(), &written));
    EXPECT_EQ(sample, out);
}

TEST(Unit_Tlv_Document, BuildsADocumentFromScratch) {
    tlv_document_options_t opts = options();
    Doc                    doc;
    ASSERT_EQ(TLV_OK, tlv_document_create(&opts, &doc.handle));
    tlv_node_t* container = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), nullptr, nullptr, TLV_TAG(0x6F), nullptr, 0,
                                          &container));
    EXPECT_TRUE(tlv_node_is_constructed(container));
    const Bytes payload = {0xDE, 0xAD};
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), container, nullptr, TLV_TAG(0x50),
                                          payload.data(), 2, nullptr));
    EXPECT_EQ((Bytes{0x6F, 0x04, 0x50, 0x02, 0xDE, 0xAD}), encode(doc.get()));
}

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_Document, WorksWithTheBerFormatAndNormalisesLengths) {
    // SEQUENCE with a padded long-form length, holding an INTEGER and a nested SEQUENCE.
    const Bytes            wire = {0x30, 0x81, 0x07, 0x02, 0x01, 0x05, 0x30, 0x02, 0x04, 0x00};
    tlv_document_options_t opts;
    ASSERT_EQ(TLV_OK, tlv_document_options_init(&opts, &tlv_format_ber));
    Doc doc = parse(wire, opts);
    EXPECT_EQ(4u, tlv_document_count(doc.get()));
    // The writer spells the length minimally.
    EXPECT_EQ((Bytes{0x30, 0x07, 0x02, 0x01, 0x05, 0x30, 0x02, 0x04, 0x00}), encode(doc.get()));

    const Bytes integer = {0x01, 0x00};
    ASSERT_EQ(TLV_OK, tlv_node_set_value(find(doc.get(), "30/02"), integer.data(), integer.size()));
    const Bytes long_value(200, 0x5A);
    ASSERT_EQ(TLV_OK, tlv_document_insert(doc.get(), find(doc.get(), "30"), nullptr, TLV_TAG(0x04),
                                          long_value.data(), long_value.size(), nullptr));
    const Bytes encoded = encode(doc.get());
    // Reparsing the output gives the same tree and the same bytes.
    Doc again = parse(encoded, opts);
    EXPECT_EQ(5u, tlv_document_count(again.get()));
    EXPECT_EQ(encoded, encode(again.get()));
    EXPECT_EQ(long_value, value_of(find(again.get(), "30/04")));
}
#endif

TEST(Unit_Tlv_Document, RuntimeDepthBeyondDefaultParsesEncodesEditsAndFrees) {
    constexpr size_t depth = TLV_TREE_DEFAULT_DEPTH + 32;
    Bytes            wire;
    for (size_t i = 0; i <= depth; ++i) {
        wire.push_back(0x6F);
        wire.push_back(static_cast<uint8_t>(2 * (depth - i)));
    }
    auto opts = options();
    opts.max_depth = depth;
    Arena arena;
    auto  allocator = arena.allocator();
    opts.allocator = &allocator;
    {
        auto doc = parse(wire, opts);
        ASSERT_NE(nullptr, doc.get());
        EXPECT_EQ(depth + 1, tlv_document_count(doc.get()));
        size_t size = 0;
        ASSERT_EQ(TLV_OK, tlv_document_encoded_size(doc.get(), &size));
        Bytes encoded(size);
        ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), encoded.data(), encoded.size(), &size));
        EXPECT_EQ(wire, encoded);
        auto* root = tlv_document_first(doc.get());
        ASSERT_EQ(TLV_OK, tlv_node_set_value(root, wire.data() + 2, wire.size() - 2));
        EXPECT_EQ(depth + 1, tlv_document_count(doc.get()));
        tlv_node_erase(root);
        EXPECT_EQ(0u, tlv_document_count(doc.get()));
    }
    EXPECT_TRUE(arena.live.empty());
}

TEST(Unit_Tlv_Document, IterativeEncodingReleasesEveryTemporaryAllocationOnFailure) {
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    auto doc = parse(sample, opts);
    ASSERT_NE(nullptr, doc.get());
    const auto retained = arena.live;
    size_t     measured = 99;
    arena.fail_at = arena.allocations;
    EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, tlv_document_encoded_size(doc.get(), &measured));
    EXPECT_EQ(99u, measured);
    EXPECT_EQ(retained, arena.live);
    arena.fail_at = SIZE_MAX;
    bool completed = false;
    for (size_t failure = 0; failure < 64 && !completed; ++failure) {
        Bytes  output(sample.size());
        size_t written = 0;
        arena.fail_at = arena.allocations + failure;
        auto rc = tlv_document_encode(doc.get(), output.data(), output.size(), &written);
        arena.fail_at = SIZE_MAX;
        EXPECT_EQ(retained, arena.live);
        if (rc == TLV_OK) {
            EXPECT_EQ(sample, output);
            EXPECT_EQ(sample.size(), written);
            completed = true;
        } else {
            EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc);
        }
    }
    EXPECT_TRUE(completed);
}

TEST(Unit_Tlv_DocumentBuilder, IncrementalInputOwnsPublishedDataAndTransfersOnlyAtFinalEnd) {
    auto opts = options();
    opts.retain_source_locations = 1;
    Bytes             window = {0x50, 1, 0xAB};
    tlv_tree_frame_t  frames[4];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, window.data(), window.size(),
                                                       opts.format, frames, 4, 4, 20));
    tlv_document_builder_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, nullptr, &raw));
    Builder builder(raw, tlv_document_builder_free);
    Doc     doc;
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    EXPECT_EQ(nullptr, doc.handle);
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    window.assign(window.size(), 0);
    // A partial constructed root must not publish or duplicate any nodes.
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, sample.data(), 3, 3, 0));
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    EXPECT_EQ(nullptr, doc.handle);
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, sample.data(), sample.size(), 0, 1));
    size_t offset = 999;
    ASSERT_EQ(TLV_OK, tlv_document_builder_consume(raw, &doc.handle, &offset, nullptr));
    EXPECT_EQ(999u, offset);
    builder.reset();
    Bytes expected = {0x50, 1, 0xAB};
    expected.insert(expected.end(), sample.begin(), sample.end());
    EXPECT_EQ(expected, encode(doc.get()));
    EXPECT_EQ(6u, tlv_document_count(doc.get()));
    EXPECT_EQ(Bytes({0xAB}), value_of(tlv_document_first(doc.get())));
    EXPECT_EQ(0u, tlv_node_source_location(tlv_document_first(doc.get())).offset);
    EXPECT_TRUE(tlv_node_source_location(tlv_document_first(doc.get())).has_offset);
    EXPECT_EQ(3u, tlv_node_source_location(tlv_node_next(tlv_document_first(doc.get()))).offset);
    EXPECT_EQ(11u, tlv_node_source_location(find(doc.get(), "6F/A5/50")).offset);
}

TEST(Unit_Tlv_DocumentBuilder, QuerySelectedSubtreeNormalizesDepthAndLeavesNextSiblingUnread) {
    auto opts = options();
    opts.retain_source_locations = 1;
    opts.max_depth = 1;
    opts.max_elements = 2;
    tlv_tree_frame_t  frames[4];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, sample.data(), sample.size(), opts.format,
                                           frames, 4, 4, 20));
    tlv_query_t         query;
    tlv_query_matcher_t matcher;
    ASSERT_EQ(TLV_OK, tlv_query_parse("6F/A5", &query, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_matcher_init(&matcher, &query));
    tlv_tree_item_t item;
    do {
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    } while (!tlv_query_matcher_visit(&matcher, &item.element.tag, item.depth));
    tlv_document_builder_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, &item, &raw));
    Builder builder(raw, tlv_document_builder_free);
    Doc     doc;
    ASSERT_EQ(TLV_OK, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    EXPECT_EQ(Bytes({0xA5, 4, 0x50, 2, 0x41, 0x42}), encode(doc.get()));
    EXPECT_EQ(nullptr, tlv_node_parent(tlv_document_first(doc.get())));
    EXPECT_EQ(6u, tlv_node_source_location(tlv_document_first(doc.get())).offset);
    EXPECT_EQ(8u, tlv_node_source_location(find(doc.get(), "A5/50")).offset);
    EXPECT_EQ(12u, tlv_tree_reader_offset(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(12u, item.offset);
    EXPECT_EQ(0u, item.depth);
    tlv_document_t* repeated = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_builder_consume(raw, &repeated, nullptr, nullptr));
    EXPECT_EQ(nullptr, repeated);
    // The result remains mutable through the existing API.
    const uint8_t replacement = 7;
    ASSERT_EQ(TLV_OK, tlv_node_set_value(find(doc.get(), "A5/50"), &replacement, 1));
    EXPECT_EQ(Bytes({0xA5, 3, 0x50, 1, 7}), encode(doc.get()));
}

TEST(Unit_Tlv_DocumentBuilder, PrimitiveAndEmptyConstructedRootsDoNotReadMalformedSibling) {
    for (uint8_t tag : {0x50, 0xA5}) {
        const Bytes       wire = {tag, 0, 0x51};
        auto              opts = options();
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire.data(), wire.size(), opts.format,
                                               nullptr, 0, 0, 10));
        tlv_tree_item_t root;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &root));
        tlv_document_builder_t* raw = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, &root, &raw));
        Builder builder(raw, tlv_document_builder_free);
        Doc     doc;
        ASSERT_EQ(TLV_OK, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
        EXPECT_EQ(Bytes({tag, 0}), encode(doc.get()));
        EXPECT_EQ(2u, tlv_tree_reader_offset(&reader));
        EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_tree_reader_next(&reader, &root));
    }
}

TEST(Unit_Tlv_DocumentBuilder, PreservesReaderDiagnosticsAfterWindowReplacement) {
    auto              opts = options();
    const Bytes       first = {0x50, 0};
    const Bytes       bad = {0x6F, 3, 0x50, 2, 0xAB};
    tlv_tree_frame_t  frames[2];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, first.data(), first.size(),
                                                       opts.format, frames, 2, 2, 10));
    tlv_document_builder_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, nullptr, &raw));
    Builder builder(raw, tlv_document_builder_free);
    Doc     doc;
    ASSERT_EQ(TLV_NEED_MORE_DATA, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, bad.data(), bad.size(), first.size(), 1));
    tlv_reader_diagnostic_t actual;
    tlv_reader_diagnostic_init(&actual);
    size_t offset = 999;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_document_builder_consume(raw, &doc.handle, &offset, &actual));
    EXPECT_EQ(nullptr, doc.handle);
    EXPECT_EQ(4u, offset);
    tlv_reader_diagnostic_t expected;
    tlv_reader_diagnostic_init(&expected);
    tlv_tree_item_t item;
    ASSERT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_tree_reader_next_diag(&reader, &item, &expected));
    EXPECT_EQ(expected.diagnostic.code, actual.diagnostic.code);
    EXPECT_EQ(expected.diagnostic.offset, actual.diagnostic.offset);
    EXPECT_EQ(expected.operation, actual.operation);
    EXPECT_EQ(expected.value_offset, actual.value_offset);
    EXPECT_EQ(expected.declared_length, actual.declared_length);
    EXPECT_EQ(expected.enclosing_end, actual.enclosing_end);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
}

TEST(Unit_Tlv_DocumentBuilder, AllocationFailureAndCancellationReleaseAllOwnedMemory) {
    bool succeeded = false;
    for (size_t fail_at = 0; fail_at < 32 && !succeeded; ++fail_at) {
        Arena arena;
        auto  allocator = arena.allocator();
        auto  opts = options();
        opts.allocator = &allocator;
        arena.fail_at = fail_at;
        tlv_tree_frame_t  frames[4];
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, sample.data(), sample.size(), opts.format,
                                               frames, 4, 4, 20));
        tlv_document_builder_t* builder = nullptr;
        auto                    rc = tlv_document_builder_create(&opts, &reader, nullptr, &builder);
        tlv_document_t*         doc = nullptr;
        if (rc == TLV_OK) rc = tlv_document_builder_consume(builder, &doc, nullptr, nullptr);
        if (rc == TLV_OK) {
            succeeded = true;
            arena.fail_at = SIZE_MAX;
            EXPECT_EQ(sample, encode(doc));
        } else {
            EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc);
            EXPECT_EQ(nullptr, doc);
        }
        tlv_document_free(doc);
        tlv_document_builder_free(builder);
        EXPECT_TRUE(arena.live.empty()) << fail_at;
    }
    EXPECT_TRUE(succeeded);
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    tlv_tree_frame_t  frames[4];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, sample.data(), sample.size(),
                                                       opts.format, frames, 4, 4, 20));
    tlv_document_builder_t* builder = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, nullptr, &builder));
    Doc doc;
    ASSERT_EQ(TLV_NEED_MORE_DATA,
              tlv_document_builder_consume(builder, &doc.handle, nullptr, nullptr));
    tlv_document_builder_free(builder);
    EXPECT_EQ(nullptr, doc.handle);
    EXPECT_TRUE(arena.live.empty());
}

TEST(Unit_Tlv_DocumentBuilder, EnforcesDocumentAndReaderLimitsSeparately) {
    for (int limit = 0; limit < 4; ++limit) {
        auto opts = options();
        if (limit == 0) opts.max_elements = 2;
        if (limit == 1) opts.max_depth = 0;
        tlv_tree_frame_t  frames[4];
        tlv_tree_reader_t reader;
        ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, sample.data(), sample.size(), opts.format,
                                               frames, 4, limit == 2 ? 0 : 4, limit == 3 ? 1 : 20));
        tlv_document_builder_t* raw = nullptr;
        ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, nullptr, &raw));
        Builder builder(raw, tlv_document_builder_free);
        Doc     doc;
        EXPECT_EQ(TLV_ERR_LIMIT, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
        EXPECT_EQ(nullptr, doc.handle);
    }
}

TEST(Unit_Tlv_DocumentBuilder, EmptyFinalStreamAndArgumentValidation) {
    auto              opts = options();
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, nullptr, 0, opts.format, nullptr, 0, 0, 0));
    tlv_document_builder_t* raw = nullptr;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_builder_create(&opts, &reader, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_builder_create(nullptr, &reader, nullptr, &raw));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_builder_create(&opts, nullptr, nullptr, &raw));
    auto other = controlled_constructed_format;
    auto wrong = opts;
    wrong.format = &other;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_builder_create(&wrong, &reader, nullptr, &raw));
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, nullptr, &raw));
    Builder builder(raw, tlv_document_builder_free);
    Doc     doc;
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_builder_consume(raw, nullptr, nullptr, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_builder_consume(nullptr, &doc.handle, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    EXPECT_EQ(0u, tlv_document_count(doc.get()));
    tlv_document_builder_free(nullptr);

    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, sample.data(), sample.size(), opts.format,
                                           nullptr, 0, 0, 10));
    tlv_tree_item_t root;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &root));
    tlv_document_builder_t* rejected = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_builder_create(&opts, &reader, nullptr, &rejected));
    opts.max_elements = 0;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_document_builder_create(&opts, &reader, &root, &rejected));
    EXPECT_EQ(nullptr, rejected);
}

TEST(Unit_Tlv_DocumentBuilder, NodeCreationUsesCanonicalConstructedClassification) {
    static size_t calls;
    calls = 0;
    auto format = controlled_constructed_format;
    format.is_constructed = [](const void*, const tlv_tag_t* tag) {
        ++calls;
        return is_constructed(nullptr, tag);
    };
    auto opts = options();
    opts.format = &format;
    Doc doc;
    ASSERT_EQ(TLV_OK,
              tlv_document_parse(sample.data(), sample.size(), &opts, &doc.handle, nullptr));
    EXPECT_EQ(tlv_document_count(doc.get()), calls);
}

#if OPENTLV_FORMAT_BER
TEST(Unit_Tlv_DocumentBuilder, SelectedIndefiniteSubtreeStopsAfterTrailers) {
    const Bytes wire = {0xE1, 0x80, 0xE2, 0x80, 0x04, 1, 0xAA, 0, 0, 0, 0, 0x04, 0};
    auto        opts = options();
    opts.format = &tlv_format_ber;
    tlv_tree_frame_t  frames[4];
    tlv_tree_reader_t reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init(&reader, wire.data(), wire.size(), opts.format, frames,
                                           4, 4, 20));
    tlv_tree_item_t item;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    tlv_document_builder_t* raw = nullptr;
    ASSERT_EQ(TLV_OK, tlv_document_builder_create(&opts, &reader, &item, &raw));
    Builder builder(raw, tlv_document_builder_free);
    Doc     doc;
    ASSERT_EQ(TLV_OK, tlv_document_builder_consume(raw, &doc.handle, nullptr, nullptr));
    EXPECT_EQ(Bytes({0xE2, 3, 0x04, 1, 0xAA}), encode(doc.get()));
    // Builder consumes its selected END, leaving enclosing closure for the caller.
    EXPECT_EQ(9u, tlv_tree_reader_offset(&reader));
    tlv_tree_event_t end{};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next_event(&reader, &end));
    EXPECT_EQ(TLV_TREE_END, end.kind);
    EXPECT_EQ(0u, end.depth);
    EXPECT_EQ(9u, end.offset);
    EXPECT_EQ(11u, tlv_tree_reader_offset(&reader));
    ASSERT_EQ(TLV_OK, tlv_tree_reader_next(&reader, &item));
    EXPECT_EQ(11u, item.offset);
    EXPECT_EQ(0u, item.depth);
}
#endif

namespace {
tlv_result_t document_content_measure(const void* context, const tlv_element_t* element,
                                      tlv_encoding_t* sizes, tlv_format_error_t* error) {
    if (element->value.size && !element->value.data) return TLV_ERR_NULL_ARG;
    const auto rc = tlv_fields_measure(context, element, sizes, error);
    if (rc != TLV_OK) return rc;
    const bool extra = element->value.size && element->value.data[0] == 0x50;
    sizes->header += extra ? 1 : 0;
    sizes->trailer = 1;
    sizes->total += extra ? 2 : 1;
    return TLV_OK;
}
tlv_result_t document_content_encode(const void* context, const tlv_element_t* element,
                                     uint8_t* data, size_t capacity, size_t* written,
                                     tlv_format_error_t* error) {
    const size_t extra = element->value.size && element->value.data[0] == 0x50 ? 1 : 0;
    if (extra) data[0] = 0xFE;
    size_t     used = 0;
    const auto rc =
        tlv_fields_encode(context, element, data + extra, capacity - extra - 1, &used, error);
    if (rc != TLV_OK) return rc;
    data[extra + used] = 0xEE;
    *written = extra + used + 1;
    return TLV_OK;
}
const tlv_format_t content_destination = {&controlled::format_layout, nullptr,
                                          document_content_measure, document_content_encode,
                                          is_constructed};
} // namespace

TEST(Unit_Tlv_Document, SameTreeUsesRuntimeContentDependentDestinationWithoutChangingSource) {
    const Bytes original{0x6F, 3, 0x50, 1, 1, 0x50, 0};
    auto        doc = parse(original);
    const Bytes expected{0xFE, 0x6F, 4, 0x50, 1, 1, 0xEE, 0xEE, 0x50, 0, 0xEE};
    size_t      size = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encoded_size_as(doc.get(), &content_destination, &size));
    EXPECT_EQ(expected.size(), size);
    Bytes  output(size, 0xCC);
    size_t written = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_document_encode_as(doc.get(), &content_destination,
                                                               output.data(), size - 1, &written));
    EXPECT_EQ(size, written);
    EXPECT_EQ(Bytes(size, 0xCC), output);
    ASSERT_EQ(TLV_OK, tlv_document_encode_as(doc.get(), &content_destination, output.data(),
                                             output.size(), &written));
    EXPECT_EQ(expected, output);
    EXPECT_EQ(original, encode(doc.get()));
    const auto* root = tlv_document_first(doc.get());
    ASSERT_EQ(TLV_OK, tlv_node_encoded_size_as(root, &content_destination, &size));
    EXPECT_EQ(8u, size);
    output.resize(size);
    ASSERT_EQ(TLV_OK, tlv_node_encode_as(root, &content_destination, output.data(), output.size(),
                                         &written));
    EXPECT_EQ(Bytes(expected.begin(), expected.begin() + 8), output);
    size = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG,
              tlv_document_encoded_size_as(doc.get(), &controlled::format, &size));
    EXPECT_EQ(99u, size);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_encoded_size_as(doc.get(), nullptr, &size));
}

TEST(Unit_Tlv_Document, DefaultFormatMeasurementReceivesPrimitiveAndConstructedContent) {
    auto runtime = content_destination;
    runtime.decode = controlled_constructed_format.decode;
    auto opts = options();
    opts.format = &runtime;
    auto doc = parse(Bytes{0x6F, 3, 0x50, 1, 1}, opts);
    EXPECT_EQ((Bytes{0xFE, 0x6F, 4, 0x50, 1, 1, 0xEE, 0xEE}), encode(doc.get()));
}

TEST(Unit_Tlv_Document, CallbackBufferErrorDoesNotTriggerAllocationRetryOrChangeOutputs) {
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    auto       doc = parse(sample, opts);
    const auto retained = arena.live;
    auto       failing = controlled_constructed_format;
    failing.encode = [](const void*, const tlv_element_t*, uint8_t*, size_t, size_t*,
                        tlv_format_error_t*) { return TLV_ERR_BUFFER_TOO_SHORT; };
    size_t size = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, tlv_document_encoded_size_as(doc.get(), &failing, &size));
    EXPECT_EQ(99u, size);
    Bytes output(100, 0xCC);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_document_encode_as(doc.get(), &failing, output.data(), output.size(), &size));
    EXPECT_EQ(99u, size);
    EXPECT_EQ(Bytes(100, 0xCC), output);
    EXPECT_EQ(retained, arena.live);
    failing.measure = [](const void*, const tlv_element_t*, tlv_encoding_t*, tlv_format_error_t*) {
        return TLV_ERR_INVALID_VALUE;
    };
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, tlv_document_encoded_size_as(doc.get(), &failing, &size));
    EXPECT_EQ(99u, size);
    EXPECT_EQ(retained, arena.live);
}

TEST(Unit_Tlv_Document, SharedWorkspaceAllocationsDoNotGrowWithConstructedSiblingCount) {
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    Bytes input;
    for (size_t i = 0; i < 40; ++i) input.insert(input.end(), {0x6F, 2, 0x50, 0});
    auto       doc = parse(input, opts);
    const auto retained = arena.live;
    const auto before = arena.allocations;
    Bytes      output(input.size());
    size_t     written = 0;
    ASSERT_EQ(TLV_OK, tlv_document_encode(doc.get(), output.data(), output.size(), &written));
    EXPECT_EQ(input, output);
    EXPECT_LE(arena.allocations - before, 3u); // frames, staged output, shared scratch
    EXPECT_EQ(retained, arena.live);
}

TEST(Unit_Tlv_Document, WorkspaceGrowthAndAllocationFailuresPreserveOwnedTree) {
    Arena arena;
    auto  allocator = arena.allocator();
    auto  opts = options();
    opts.allocator = &allocator;
    Bytes input;
    for (size_t i = 0; i < 200; ++i) input.insert(input.end(), {0x6F, 2, 0x50, 0});
    auto       doc = parse(input, opts);
    const auto retained = arena.live;
    bool       completed = false;
    for (size_t failure = 0; failure < 32 && !completed; ++failure) {
        arena.fail_at = arena.allocations + failure;
        Bytes      output(input.size(), 0xCC);
        size_t     written = 99;
        const auto rc = tlv_document_encode(doc.get(), output.data(), output.size(), &written);
        arena.fail_at = SIZE_MAX;
        EXPECT_EQ(retained, arena.live);
        if (rc == TLV_OK) {
            EXPECT_EQ(input, output);
            completed = true;
        } else {
            EXPECT_EQ(TLV_ERR_OUT_OF_MEMORY, rc);
            EXPECT_EQ(99u, written);
            EXPECT_EQ(Bytes(input.size(), 0xCC), output);
        }
    }
    EXPECT_TRUE(completed);
}

TEST(Unit_Tlv_Document, QueryVisitsAllMatchesAndHonorsCallbackCommands) {
    auto document = parse(Bytes{0x6F, 2, 0x84, 0, 0x6F, 6, 0xA5, 4, 0x50, 0, 0x50, 0});
    auto query = tlv_query_t{};
    ASSERT_EQ(TLV_OK, tlv_query_parse("6F/A5/50", &query, nullptr));
    QueryCollection collection;
    EXPECT_EQ(TLV_OK, tlv_document_query_visit(document.get(), &query, QueryCollection::collect,
                                               &collection));
    ASSERT_EQ(2u, collection.nodes.size());
    EXPECT_EQ(collection.nodes[0], tlv_document_find_path(document.get(), &query));
    EXPECT_EQ(collection.nodes[1], tlv_node_next(collection.nodes[0]));
    collection.nodes.clear();
    collection.command = TLV_VISIT_STOP;
    EXPECT_EQ(TLV_OK, tlv_document_query_visit(document.get(), &query, QueryCollection::collect,
                                               &collection));
    EXPECT_EQ(1u, collection.nodes.size());
    collection.command = TLV_VISIT_ERROR;
    EXPECT_EQ(TLV_ERR_VISITOR, tlv_document_query_visit(document.get(), &query,
                                                        QueryCollection::collect, &collection));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_document_query_visit(nullptr, &query, QueryCollection::collect, &collection));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_document_query_visit(document.get(), &query, nullptr, nullptr));
    query = tlv_query_t{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_document_query_visit(document.get(), &query,
                                                            QueryCollection::collect, &collection));
}
