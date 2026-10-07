// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv++/native.hpp"

#include "controlled_format.h"
#include "tlv++/document/document.hpp"

#include <gtest/gtest.h>

#include <vector>
#include <type_traits>

static_assert(
    std::is_same<decltype(std::declval<const tlv::document&>().first()), tlv::const_node>::value,
    "A const Document must not expose mutable Nodes");
static_assert(!std::is_convertible<tlv::const_node, tlv::node>::value,
              "Read-only handles must not recover mutation");
static_assert(
    std::is_same<decltype(std::declval<tlv::const_node>().first_child()), tlv::const_node>::value,
    "Read-only traversal must stay read-only");

namespace {

using Bytes = std::vector<tlv::byte>;

Bytes make(std::initializer_list<int> values) {
    Bytes out;
    for (int value : values) out.push_back(static_cast<tlv::byte>(value));
    return out;
}

tlv::bytes view(const Bytes& data) {
    return tlv::bytes(data.data(), data.size());
}

// 6F, A5 and A6 hold nested elements.
int is_constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5 || tag->data[0] == 0xA6);
}

tlv::document_format format() {
    tlv_format_t constructed_format = controlled::format;
    constructed_format.is_constructed = is_constructed;
    return tlv::document_format(tlv::native::borrow_format(constructed_format));
}

// 6F { 84 (AA BB), A5 { 50 (41 42) } }, 50 (FF)
const Bytes sample = make(
    {0x6F, 0x0A, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50, 0x02, 0x41, 0x42, 0x50, 0x01, 0xFF});

TEST(Unit_Tlvpp_Document, SelectedBuilderUsesPublishedRootAndResumesReader) {
    auto             config = format();
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader(view(sample), config.view(), {frames, 2}, 2, 10);
    auto             query = tlv::query::parse("6F/A5");
    ASSERT_TRUE(query);
    tlv::query_matcher matcher(*query);
    for (;;) {
        auto item = reader.next();
        ASSERT_TRUE(item);
        if (!matcher.matches(item->element.tag(), item->depth)) continue;
        auto builder = tlv::document_builder::current_subtree(reader, 64, 65536, true);
        ASSERT_TRUE(builder);
        auto moved = std::move(*builder);
        auto doc = moved.consume();
        ASSERT_TRUE(doc);
        auto output = doc->encode();
        ASSERT_TRUE(output);
        EXPECT_EQ(make({0xA5, 4, 0x50, 2, 0x41, 0x42}), *output);
        EXPECT_TRUE(doc->first().source_location().has_offset);
        EXPECT_EQ(6u, doc->first().source_location().offset);
        EXPECT_FALSE(moved.consume());
        break;
    }
    auto sibling = reader.next();
    ASSERT_TRUE(sibling);
    EXPECT_EQ(12u, sibling->offset);
}

TEST(Unit_Tlvpp_Document, ParseRetainsSourceLocationsOnlyWhenRequested) {
    auto config = format();
    auto plain = tlv::document::parse(view(sample), config);
    ASSERT_TRUE(plain);
    EXPECT_FALSE(plain->first().source_location().has_offset);
    config.retain_source_locations = true;
    auto doc = tlv::document::parse(view(sample), config);
    ASSERT_TRUE(doc);
    auto root = doc->first();
    EXPECT_TRUE(root.source_location().has_offset);
    EXPECT_EQ(0u, root.source_location().offset);
    EXPECT_EQ(2u, root.source_location().header_size);
    auto child = root.first_child();
    EXPECT_EQ(2u, child.source_location().offset);
    ASSERT_TRUE(child.set({}));
    EXPECT_FALSE(child.source_location().has_offset);
    EXPECT_FALSE(root.source_location().has_offset);
    EXPECT_EQ(12u, root.next().source_location().offset);
    EXPECT_FALSE(tlv::node().source_location().has_offset);
}

TEST(Unit_Tlvpp_Document, SelectionInvalidatedByCursorAndBuilderOperations) {
    for (int operation = 0; operation < 9; ++operation) {
        SCOPED_TRACE(operation);
        auto             config = format();
        tlv::tree_frame  frames[2]{};
        tlv::tree_reader reader(view(sample), config.view(), {frames, 2}, 2, 10);
        EXPECT_FALSE(tlv::document_builder::current_subtree(reader));
        ASSERT_TRUE(reader.next());
        auto stop = [](const tlv::element_view&, size_t, size_t) { return TLV_VISIT_STOP; };
        switch (operation) {
            case 0: ASSERT_TRUE(reader.skip_subtree()); break;
            case 1: ASSERT_TRUE(reader.set_input(view(sample), 0, tlv::input_mode::final)); break;
            case 2:
                EXPECT_FALSE(
                    reader.set_input(view(sample), sample.size() + 1, tlv::input_mode::final));
                break;
            case 3: ASSERT_TRUE(reader.visit(stop)); break;
            case 4: ASSERT_TRUE(reader.validate()); break;
            case 5: {
                auto query = tlv::query::parse("6F/84");
                ASSERT_TRUE(query);
                tlv::query_matcher matcher(*query);
                ASSERT_TRUE(matcher.visit(reader, stop));
                break;
            }
            case 6: {
                auto builder = tlv::document_builder::current_subtree(reader);
                ASSERT_TRUE(builder);
                ASSERT_TRUE(builder->consume());
                break;
            }
            case 7: {
                auto builder = tlv::document_builder::create(reader);
                (void)builder;
                break;
            }
            case 8:
                while (reader.next()) {
                }
                break;
        }
        auto rejected = tlv::document_builder::current_subtree(reader);
        ASSERT_FALSE(rejected);
        EXPECT_EQ(TLV_ERR_INVALID_ARG, rejected.error().code);
    }
}

TEST(Unit_Tlvpp_Document, SelectionUsesLatestPullAndIgnoresCallerItemChanges) {
    auto             config = format();
    tlv::tree_frame  frames[2]{};
    tlv::tree_reader reader(view(sample), config.view(), {frames, 2}, 2, 10);
    auto             old = reader.next();
    ASSERT_TRUE(old);
    auto latest = reader.next();
    ASSERT_TRUE(latest);
    *latest = *old;
    auto builder = tlv::document_builder::current_subtree(reader);
    ASSERT_TRUE(builder);
    auto doc = builder->consume();
    ASSERT_TRUE(doc);
    auto encoded = doc->encode();
    ASSERT_TRUE(encoded);
    EXPECT_EQ(make({0x84, 2, 0xAA, 0xBB}), *encoded);
}

TEST(Unit_Tlvpp_Document, WholeStreamBuilderResumesAfterInputReplacement) {
    auto             config = format();
    const auto       data = make({0x50, 1, 42});
    tlv::tree_frame  frames[1]{};
    tlv::tree_reader reader(tlv::bytes(data.data(), 1), config.view(), {frames, 1}, 1, 5,
                            tlv::input_mode::incremental);
    auto             builder = tlv::document_builder::create(reader);
    ASSERT_TRUE(builder);
    auto incomplete = builder->consume();
    ASSERT_FALSE(incomplete);
    ASSERT_TRUE(reader.set_input(view(data), 0, tlv::input_mode::final));
    auto doc = builder->consume();
    ASSERT_TRUE(doc);
    EXPECT_EQ(data, *doc->encode());
}

} // namespace

TEST(Unit_Tlvpp_Document, ParsesInspectsAndEncodesAgain) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    EXPECT_EQ(5u, doc.size());
    EXPECT_FALSE(doc.empty());

    tlv::node outer = doc.find(tlv::tag_bytes<0x6F>());
    ASSERT_TRUE(static_cast<bool>(outer));
    EXPECT_TRUE(outer.is_constructed());
    EXPECT_EQ(doc.first(), outer);

    std::vector<int> child_tags;
    for (tlv::node child : outer.children()) {
        child_tags.push_back(static_cast<int>(child.tag().data()[0]));
    }
    EXPECT_EQ((std::vector<int>{0x84, 0xA5}), child_tags);

    tlv::node primitive = outer.find(tlv::tag_bytes<0x84>());
    ASSERT_TRUE(static_cast<bool>(primitive));
    EXPECT_EQ(2u, primitive.value().size());
    EXPECT_EQ(outer, primitive.parent());
    EXPECT_FALSE(outer.find(tlv::tag_bytes<0x99>()));

    auto path = tlv::query::parse("6F/A5/50");
    ASSERT_TRUE(path.has_value());
    tlv::node leaf = doc.find(*path);
    ASSERT_TRUE(static_cast<bool>(leaf));
    EXPECT_EQ(2u, leaf.value().size());

    auto encoded = doc.encode();
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(sample, *encoded);
    EXPECT_EQ(sample.size(), *doc.encoded_size());
}

TEST(Unit_Tlvpp_Document, SetInsertAndEraseAsInTheIssueExample) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node entry = doc.find(tlv::tag_bytes<0x50>());
    ASSERT_TRUE(static_cast<bool>(entry));
    const Bytes replacement = make({1, 2, 3});
    ASSERT_TRUE(entry.set(view(replacement)).has_value());

    const Bytes payload = make({0xDE, 0xAD});
    auto        inserted = doc.insert(tlv::tag_bytes<0x51>(), view(payload));
    ASSERT_TRUE(inserted.has_value());
    EXPECT_EQ(2u, inserted->value().size());

    EXPECT_TRUE(doc.erase(tlv::tag_bytes<0x6F>()));
    EXPECT_FALSE(doc.erase(tlv::tag_bytes<0x6F>()));

    auto encoded = doc.encode();
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(make({0x50, 0x03, 1, 2, 3, 0x51, 0x02, 0xDE, 0xAD}), *encoded);
    EXPECT_EQ(2u, doc.size());
}

TEST(Unit_Tlvpp_Document, InsertsIntoConstructedElementsBeforeASibling) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node   outer = doc.first();
    const Bytes payload = make({0x01});
    auto inserted = doc.insert(tlv::tag_bytes<0x53>(), view(payload), outer, outer.first_child());
    ASSERT_TRUE(inserted.has_value());
    EXPECT_EQ(outer.first_child(), *inserted);
    EXPECT_EQ(make({0x6F, 0x0D, 0x53, 0x01, 0x01, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50, 0x02,
                    0x41, 0x42, 0x50, 0x01, 0xFF}),
              *doc.encode());

    // A primitive parent is refused and nothing changes.
    auto refused = doc.insert(tlv::tag_bytes<0x50>(), view(payload), outer.first_child());
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(TLV_ERR_INVALID_ARG, refused.error().code);
    EXPECT_EQ(6u, doc.size());
}

TEST(Unit_Tlvpp_Document, ReportsErrorsAndKeepsTheDocumentUnchanged) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    tlv::document doc = std::move(*parsed);

    tlv::node   inner = doc.find(*tlv::query::parse("6F/A5"));
    const Bytes malformed = make({0x50, 0x09});
    auto        result = inner.set(view(malformed));
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(TLV_OK, result.error().code);
    EXPECT_EQ(sample, *doc.encode());

    size_t offset = 0;
    auto   broken = tlv::document::parse(view(make({0x50, 0x00, 0x50, 0x05})), format(), &offset);
    ASSERT_FALSE(broken.has_value());
    EXPECT_EQ(2u, offset);

    tlv::document_format limited = format();
    limited.max_elements = 2;
    auto limited_parse = tlv::document::parse(view(sample), limited);
    ASSERT_FALSE(limited_parse.has_value());
    EXPECT_EQ(TLV_ERR_LIMIT, limited_parse.error().code);
}

TEST(Unit_Tlvpp_Document, MovedDocumentKeepsHandlesValid) {
    auto created = tlv::document::create(format());
    ASSERT_TRUE(created.has_value());
    tlv::document doc = std::move(*created);
    EXPECT_TRUE(doc.empty());

    auto container = doc.insert(tlv::tag_bytes<0x6F>(), tlv::bytes());
    ASSERT_TRUE(container.has_value());
    const Bytes payload = make({0x0A});
    ASSERT_TRUE(doc.insert(tlv::tag_bytes<0x50>(), view(payload), *container).has_value());

    tlv::document moved(std::move(doc));
    EXPECT_EQ(1u, container->first_child().value().size());
    EXPECT_EQ(make({0x6F, 0x03, 0x50, 0x01, 0x0A}), *moved.encode());

    // A single node can be encoded on its own, and an erased handle turns empty.
    EXPECT_EQ(make({0x50, 0x01, 0x0A}), *container->first_child().encode());
    tlv::node child = container->first_child();
    child.erase();
    EXPECT_FALSE(static_cast<bool>(child));
    EXPECT_EQ(make({0x6F, 0x00}), *moved.encode());
}

TEST(Unit_Tlvpp_Document, CreatesWithoutDecoderAndChecksItOnlyForParsing) {
    const auto original = format();
    auto       descriptor = tlv::native::descriptor(original.view());
    descriptor.decode = nullptr;
    tlv::document_format write_only(tlv::native::borrow_format(descriptor));
    auto                 created = tlv::document::create(write_only);
    ASSERT_TRUE(created.has_value());
    auto parsed = tlv::document::parse(view(sample), write_only);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(TLV_ERR_NULL_ARG, parsed.error().code);
}

TEST(Unit_Tlvpp_Document, ExplicitDestinationPreservesTreeAndSubtreeBoundaries) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed.has_value());
    auto& doc = *parsed;
    auto  destination = controlled::format;
    auto  layout = controlled::format_layout;
    layout.element_order = TLV_ELEMENT_ORDER_LTV;
    destination.context = &layout;
    destination.is_constructed = is_constructed;
    auto output = doc.encode(tlv::native::borrow_format(destination));
    ASSERT_TRUE(output.has_value());
    EXPECT_EQ(make({10, 0x6F, 2, 0x84, 0xAA, 0xBB, 4, 0xA5, 2, 0x50, 0x41, 0x42, 1, 0x50, 0xFF}),
              *output);
    auto size = doc.encoded_size(tlv::native::borrow_format(destination));
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(output->size(), *size);
    auto subtree = doc.first().encode(tlv::native::borrow_format(destination));
    ASSERT_TRUE(subtree.has_value());
    EXPECT_EQ(Bytes(output->begin(), output->begin() + 12), *subtree);
    auto subtree_size = doc.first().encoded_size(tlv::native::borrow_format(destination));
    ASSERT_TRUE(subtree_size.has_value());
    EXPECT_EQ(subtree->size(), *subtree_size);
    auto original = doc.encode();
    ASSERT_TRUE(original.has_value());
    EXPECT_EQ(sample, *original);
}

TEST(Unit_Tlvpp_Document, NaturalRangesAndChildInsertion) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed);
    auto&            doc = *parsed;
    std::vector<int> tags;
    for (auto node : doc) tags.push_back(static_cast<int>(node.tag().data()[0]));
    EXPECT_EQ((std::vector<int>{0x6F, 0x50}), tags);
    EXPECT_EQ(2, std::distance(doc.begin(), doc.end()));
    EXPECT_TRUE(doc.first().next().children().empty());
    EXPECT_FALSE(doc.first().parent());
    EXPECT_TRUE(tlv::node().children().empty());
    auto outer = doc.first();
    auto iterator = outer.children().begin();
    auto copy = iterator++;
    EXPECT_EQ(outer.first_child(), *copy);
    EXPECT_EQ(outer.find(tlv::tag_bytes<0xA5>()), *iterator);
    const auto payload = make({0x11});
    auto       inserted = outer.insert(tlv::tag_bytes<0x53>(), view(payload), *iterator);
    ASSERT_TRUE(inserted);
    EXPECT_EQ(outer, inserted->parent());
    EXPECT_EQ(*inserted, copy->next());
    EXPECT_EQ(make({0x6F, 0x0D, 0x84, 0x02, 0xAA, 0xBB, 0x53, 0x01, 0x11, 0xA5, 0x04, 0x50, 0x02,
                    0x41, 0x42, 0x50, 0x01, 0xFF}),
              *doc.encode());
    auto empty = tlv::document::create(format());
    ASSERT_TRUE(empty);
    EXPECT_EQ(empty->begin(), empty->end());
}

TEST(Unit_Tlvpp_Document, ErasureInvalidatesCopiesDescendantsAndIteratorsOnly) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed);
    auto& doc = *parsed;
    auto  outer = doc.first();
    auto  copy = outer;
    auto  child = outer.first_child();
    auto  leaf = outer.find(tlv::tag_bytes<0xA5>()).first_child();
    auto  sibling = outer.next();
    auto  iterator = doc.begin();
    outer.erase();
    EXPECT_FALSE(copy);
    EXPECT_FALSE(child);
    EXPECT_FALSE(leaf);
    EXPECT_EQ(doc.end(), iterator);
    EXPECT_TRUE(sibling);
    EXPECT_EQ(sibling, doc.first());
    EXPECT_TRUE(copy.children().empty());
    EXPECT_TRUE(copy.tag().empty());
    EXPECT_EQ(0u, copy.value().size());
    EXPECT_FALSE(copy.parent());
    EXPECT_FALSE(copy.find(tlv::tag_bytes<0x50>()));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, copy.set(tlv::bytes()).error().code);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, copy.encode().error().code);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, copy.encoded_size().error().code);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              copy.encode(tlv::native::borrow_format(controlled::format)).error().code);
    copy.erase();
    EXPECT_EQ(make({0x50, 0x01, 0xFF}), *doc.encode());
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              doc.insert(tlv::tag_bytes<0x50>(), tlv::bytes(), child).error().code);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              doc.insert(tlv::tag_bytes<0x50>(), tlv::bytes(), tlv::node(), copy).error().code);
}

TEST(Unit_Tlvpp_Document, ReplacementPreservesParentCopiesAndFailedEditsPreserveChildren) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed);
    auto&      doc = *parsed;
    auto       outer = doc.first();
    auto       outer_copy = outer;
    auto       child = outer.first_child();
    auto       nested = outer.find(tlv::tag_bytes<0xA5>()).first_child();
    auto       sibling = outer.next();
    const auto malformed = make({0x50, 0x09});
    EXPECT_FALSE(outer.set(view(malformed)));
    EXPECT_TRUE(child);
    EXPECT_TRUE(nested);
    EXPECT_EQ(sample, *doc.encode());
    const auto replacement = make({0x51, 0x01, 0x22});
    ASSERT_TRUE(outer.set(view(replacement)));
    EXPECT_TRUE(outer_copy);
    EXPECT_TRUE(sibling);
    EXPECT_FALSE(child);
    EXPECT_FALSE(nested);
    EXPECT_EQ(tlv::tag_bytes<0x51>(), outer_copy.first_child().tag());
    EXPECT_EQ(make({0x6F, 0x03, 0x51, 0x01, 0x22, 0x50, 0x01, 0xFF}), *doc.encode());
    auto foreign = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(foreign);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              doc.insert(tlv::tag_bytes<0x50>(), tlv::bytes(), foreign->first()).error().code);
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              outer.insert(tlv::tag_bytes<0x50>(), tlv::bytes(), foreign->first().first_child())
                  .error()
                  .code);
    // Repeated allocation must never revive handles to an erased node.
    for (int i = 0; i < 16; ++i) {
        auto inserted = outer.insert(tlv::tag_bytes<0x52>(), tlv::bytes());
        ASSERT_TRUE(inserted);
        inserted->erase();
        EXPECT_FALSE(child);
    }
}

TEST(Unit_Tlvpp_Document, DestructionAndMoveAssignmentInvalidateOnlyPreviousOwner) {
    tlv::node       retained;
    tlv::node_range retained_range;
    {
        auto parsed = tlv::document::parse(view(sample), format());
        ASSERT_TRUE(parsed);
        retained = parsed->first();
        retained_range = retained.children();
    }
    EXPECT_FALSE(retained);
    EXPECT_TRUE(retained_range.empty());
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              retained.insert(tlv::tag_bytes<0x50>(), tlv::bytes()).error().code);
    auto source = tlv::document::parse(view(sample), format());
    auto destination = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(source);
    ASSERT_TRUE(destination);
    auto incoming = source->first();
    auto outgoing = destination->first();
    *destination = std::move(*source);
    EXPECT_TRUE(incoming);
    EXPECT_FALSE(outgoing);
    EXPECT_EQ(incoming, destination->first());
    EXPECT_EQ(sample, *destination->encode());
}

TEST(Unit_Tlvpp_Document, PrimitiveEditsAndChildErasurePreserveUnrelatedHandles) {
    auto parsed = tlv::document::parse(view(sample), format());
    ASSERT_TRUE(parsed);
    auto       outer = parsed->first();
    auto       primitive = outer.first_child();
    auto       copy = primitive;
    auto       sibling = primitive.next();
    auto       sibling_leaf = sibling.first_child();
    const auto replacement = make({0xCC});
    ASSERT_TRUE(primitive.set(view(replacement)));
    ASSERT_TRUE(copy);
    EXPECT_EQ(1u, copy.value().size());
    EXPECT_EQ(tlv::byte(0xCC), copy.value().data()[0]);
    primitive.erase();
    EXPECT_FALSE(copy);
    EXPECT_TRUE(outer);
    EXPECT_TRUE(sibling);
    EXPECT_TRUE(sibling_leaf);
    EXPECT_EQ(sibling, outer.first_child());
    auto other = outer.insert(tlv::tag_bytes<0xA5>(), tlv::bytes());
    ASSERT_TRUE(other);
    EXPECT_EQ(*other, sibling.next_same_tag());
    EXPECT_EQ(make({0x6F, 0x08, 0xA5, 0x04, 0x50, 0x02, 0x41, 0x42, 0xA5, 0x00, 0x50, 0x01, 0xFF}),
              *parsed->encode());
}
