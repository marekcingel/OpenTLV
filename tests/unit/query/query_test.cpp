// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "controlled_format.h"
#include "tlv/query/query.h"
#include <gtest/gtest.h>
#include <string>

TEST(Unit_Tlv_Query, LocationsDistinguishSyntaxEvidenceAndEmptyEof) {
    tlv_query_t      query{};
    tlv_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse_n("GG", 2, &query, &diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_ARG, diagnostic.code);
    EXPECT_EQ(TLV_LOCATION_EXPRESSION, diagnostic.location.domain);
    EXPECT_EQ(TLV_LOCATION_SPAN, diagnostic.location.kind);
    EXPECT_EQ(0u, diagnostic.location.begin);
    EXPECT_EQ(1u, diagnostic.location.end);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse_n("01/", 3, &query, &diagnostic));
    EXPECT_EQ(3u, diagnostic.location.begin);
    EXPECT_EQ(3u, diagnostic.location.end);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse_n("01/", 3, &query, nullptr));
}
#include "../../../tlv/src/query/v1_internal.h"
#include <vector>

namespace {
// One-byte tags and lengths. 6F, A5 and A6 are constructed, which matches the
// BER bytes of the same data.
//   0: 6F { 84, A5 { 50 } }          8: 50 (41 42)
//  12: 50 (FF)
//  15: 6F { A5 { 50, 50 } }         19, 22: 50
//  25: 6F { A6 { A5 { 50 } } }      A5 is one level too deep.
const std::vector<uint8_t> data = {0x6F, 0x0A, 0x84, 0x02, 0xAA, 0xBB, 0xA5, 0x04, 0x50,
                                   0x02, 0x41, 0x42, 0x50, 0x01, 0xFF, 0x6F, 0x08, 0xA5,
                                   0x06, 0x50, 0x01, 0x01, 0x50, 0x01, 0x02, 0x6F, 0x07,
                                   0xA6, 0x05, 0xA5, 0x03, 0x50, 0x01, 0x09};

int is_constructed(const void*, const tlv_tag_t* tag) {
    return tag->size == 1 && (tag->data[0] == 0x6F || tag->data[0] == 0xA5 || tag->data[0] == 0xA6);
}

struct Match {
    size_t offset;
    size_t depth;
    size_t value_size;
    bool   operator==(const Match& other) const {
        return offset == other.offset && depth == other.depth && value_size == other.value_size;
    }
};

struct Outcome {
    tlv_result_t       rc;
    std::vector<Match> matches;
    size_t             error_offset = 0;
};

struct Visit {
    std::vector<Match>* matches;
    tlv_visit_result_t  result;
};

tlv_visit_result_t collect(const tlv_element_t* element, size_t depth, size_t offset,
                           void* context) {
    Visit* visit = static_cast<Visit*>(context);
    visit->matches->push_back({offset, depth, static_cast<size_t>(element->value.size)});
    return visit->result;
}

tlv_query_t parse(const char* text) {
    tlv_query_t query;
    EXPECT_EQ(TLV_OK, tlv_query_parse(text, &query, nullptr)) << text;
    return query;
}

Outcome visit_buffer(const char* text, const std::vector<uint8_t>& input = data,
                     tlv_is_constructed_fn predicate = is_constructed,
                     size_t max_depth = TLV_TREE_DEFAULT_DEPTH, size_t max_elements = 1000,
                     tlv_visit_result_t result = TLV_VISIT_CONTINUE) {
    Outcome      run;
    tlv_query_t  query = parse(text);
    Visit        visit = {&run.matches, result};
    tlv_format_t format = controlled::format;
    format.is_constructed = predicate;
    tlv_reader_diagnostic_t diagnostic{};
    run.rc = tlv_query_visit_buffer(input.data(), input.size(), &format, &query, max_depth,
                                    max_elements, collect, &visit, &diagnostic);
    run.error_offset = diagnostic.diagnostic.location.begin;
    return run;
}
} // namespace

TEST(Unit_Tlv_Query, ParsesTagsInEitherCase) {
    const tlv_query_t query = parse("6F/a5/50");
    ASSERT_EQ(3u, tlv_query_count(&query));
    EXPECT_EQ(0x6F, tlv_query_step(&query, 0).data[0]);
    EXPECT_EQ(1u, tlv_query_step(&query, 0).size);
    EXPECT_EQ(0xA5, tlv_query_step(&query, 1).data[0]);
    EXPECT_EQ(0x50, tlv_query_step(&query, 2).data[0]);
    const auto parse_zero = parse("00");
    EXPECT_EQ(1u, tlv_query_count(&parse_zero));
    const tlv_query_t wide = parse("9f02/DF8101");
    EXPECT_EQ(2u, tlv_query_step(&wide, 0).size);
    EXPECT_EQ(0x9F, tlv_query_step(&wide, 0).data[0]);
    EXPECT_EQ(0x02, tlv_query_step(&wide, 0).data[1]);
    EXPECT_EQ(3u, tlv_query_step(&wide, 1).size);
    // Steps past the end are empty.
    EXPECT_EQ(0u, tlv_query_step(&wide, 2).size);
    EXPECT_EQ(0u, tlv_query_step(nullptr, 0).size);
}

TEST(Unit_Tlv_Query, TagsOfAnyLengthAreKeptWithinTheTotalByteLimit) {
    // Tags longer than any built-in format accepts still parse; only the total is limited.
    std::string twelve;
    for (int i = 0; i < 12; ++i) twelve += "AB";
    const tlv_query_t query = parse((twelve + "/6F").c_str());
    ASSERT_EQ(2u, tlv_query_count(&query));
    EXPECT_EQ(12u, tlv_query_step(&query, 0).size);
    EXPECT_EQ(0xAB, tlv_query_step(&query, 0).data[11]);
    EXPECT_EQ(1u, tlv_query_step(&query, 1).size);
    // A query is a value: copies stay valid and independent.
    tlv_query_t copy = query;
    EXPECT_TRUE(tlv_tag_equal(tlv_query_step(&copy, 0), tlv_query_step(&query, 0)));
    EXPECT_NE(tlv_query_step(&copy, 0).data, tlv_query_step(&query, 0).data);
}

TEST(Unit_Tlv_Query, RejectsSyntaxErrorsAtTheOffendingPosition) {
    struct Case {
        const char* text;
        size_t      offset;
    };
    const Case cases[] = {{"", 0},       {"/", 0},   {"6F/", 3},    {"/6F", 0},
                          {"6F//50", 3}, {"6", 0},   {"6F/5", 3},   {"6G", 1},
                          {"6F 50", 2},  {" 6F", 0}, {"6F/50 ", 5}, {"0x6F", 1}};
    for (const Case& c : cases) {
        tlv_query_t      query = {};
        tlv_diagnostic_t offset = {};
        offset.location.begin = 99;
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse(c.text, &query, &offset)) << c.text;
        EXPECT_EQ(c.offset, offset.location.begin) << c.text;
        EXPECT_EQ(0u, tlv_query_count(&query)) << c.text;
    }
}

TEST(Unit_Tlv_Query, RejectsInvalidArgumentsAndLimits) {
    tlv_query_t query = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_parse(nullptr, &query, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_parse("6F", nullptr, nullptr));

    std::string wide;
    for (int i = 0; i <= TLV_QUERY_MAX_BYTES; ++i) wide += "AB";
    tlv_diagnostic_t offset = {};
    offset.location.begin = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_query_parse(("6F/" + wide).c_str(), &query, &offset));
    EXPECT_EQ(3u, offset.location.begin);
    std::string exact;
    for (int i = 0; i < TLV_QUERY_MAX_BYTES; ++i) exact += "AB";
    EXPECT_EQ(TLV_OK, tlv_query_parse(exact.c_str(), &query, nullptr));
    EXPECT_EQ(static_cast<size_t>(TLV_QUERY_MAX_BYTES), tlv_query_step(&query, 0).size);

    std::string deepest = "6F";
    for (int i = 1; i < TLV_QUERY_MAX_STEPS; ++i) deepest += "/6F";
    EXPECT_EQ(TLV_OK, tlv_query_parse(deepest.c_str(), &query, nullptr));
    EXPECT_EQ(static_cast<size_t>(TLV_QUERY_MAX_STEPS), tlv_query_count(&query));
    offset.location.begin = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_query_parse((deepest + "/6F").c_str(), &query, &offset));
    EXPECT_EQ(deepest.size() + 1, offset.location.begin);
    EXPECT_EQ(static_cast<size_t>(TLV_QUERY_MAX_STEPS),
              tlv_query_count(&query)); // Unchanged on failure.
}

TEST(Unit_Tlv_Query, MatcherRejectsInvalidQueries) {
    tlv_query_matcher_t matcher;
    tlv_query_t         query = parse("6F");
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_matcher_init(nullptr, &query));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_matcher_init(&matcher, nullptr));
    tlv_query_t empty = {};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_matcher_init(&matcher, &empty));
    auto corrupt = query_v1_load(&query);
    corrupt.count = TLV_QUERY_MAX_STEPS + 1;
    memcpy(&query, &corrupt, sizeof corrupt);
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_matcher_init(&matcher, &query));
    query = parse("6F");
    corrupt = query_v1_load(&query);
    corrupt.ends[0] = 0;
    memcpy(&query, &corrupt, sizeof corrupt); // An empty step.
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_query_matcher_init(&matcher, &query));
    corrupt.ends[0] = TLV_QUERY_MAX_BYTES + 1;
    memcpy(&query, &corrupt, sizeof corrupt); // A step beyond the stored bytes.
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_query_matcher_init(&matcher, &query));
}

TEST(Unit_Tlv_Query, MatcherFollowsAPreorderTraversal) {
    const tlv_query_t   query = parse("01/02");
    tlv_query_matcher_t matcher;
    ASSERT_EQ(TLV_OK, tlv_query_matcher_init(&matcher, &query));
    const tlv_tag_t t1 = TLV_TAG(1), t2 = TLV_TAG(2), t3 = TLV_TAG(3);
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t2, 0)); // Wrong top-level tag.
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t2, 1)); // Child of an unmatched element.
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t1, 0));
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t3, 1));
    EXPECT_EQ(1, tlv_query_matcher_visit(&matcher, &t2, 1));
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t2, 2)); // Below the addressed depth.
    EXPECT_EQ(1, tlv_query_matcher_visit(&matcher, &t2, 1)); // Next sibling.
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, &t2, 3)); // Skipped a level.
    EXPECT_EQ(0, tlv_query_matcher_visit(nullptr, &t1, 0));
    EXPECT_EQ(0, tlv_query_matcher_visit(&matcher, nullptr, 0));
    tlv_query_matcher_t unset = {};
    EXPECT_EQ(0, tlv_query_matcher_visit(&unset, &t1, 0));
}

TEST(Unit_Tlv_Query, AddressesEveryElementAlongTheExactPath) {
    const Outcome run = visit_buffer("6F/A5/50");
    EXPECT_EQ(TLV_OK, run.rc);
    EXPECT_EQ((std::vector<Match>{{8, 2, 2}, {19, 2, 1}, {22, 2, 1}}), run.matches);
}

TEST(Unit_Tlv_Query, DistinguishesDepthFromTag) {
    EXPECT_EQ((std::vector<Match>{{12, 0, 1}}), visit_buffer("50").matches);
    EXPECT_EQ((std::vector<Match>{{0, 0, 10}, {15, 0, 8}, {25, 0, 7}}), visit_buffer("6F").matches);
    EXPECT_EQ((std::vector<Match>{{6, 1, 4}, {17, 1, 6}}), visit_buffer("6F/A5").matches);
    EXPECT_EQ((std::vector<Match>{{2, 1, 2}}), visit_buffer("6F/84").matches);
    EXPECT_EQ((std::vector<Match>{{27, 1, 5}}), visit_buffer("6F/A6").matches);
    EXPECT_EQ((std::vector<Match>{{29, 2, 3}}), visit_buffer("6F/A6/A5").matches);
    EXPECT_EQ((std::vector<Match>{{31, 3, 1}}), visit_buffer("6F/A6/A5/50").matches);
    EXPECT_TRUE(visit_buffer("A5").matches.empty());
    EXPECT_TRUE(visit_buffer("6F/50").matches.empty());
    EXPECT_TRUE(visit_buffer("6F/A5/51").matches.empty());
    EXPECT_TRUE(visit_buffer("6F/A5/50/50").matches.empty());
    EXPECT_EQ(TLV_OK, visit_buffer("6F/A5/51").rc);
}

TEST(Unit_Tlv_Query, OpaqueValuesAnswerOnlyTopLevelQueries) {
    EXPECT_EQ(3u, visit_buffer("6F", data, nullptr).matches.size());
    EXPECT_TRUE(visit_buffer("6F/A5", data, nullptr).matches.empty());
}

TEST(Unit_Tlv_Query, HonorsVisitorResults) {
    EXPECT_EQ(
        1u,
        visit_buffer("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_STOP).matches.size());
    EXPECT_EQ(TLV_OK, visit_buffer("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_STOP).rc);
    const Outcome failed =
        visit_buffer("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_ERROR);
    EXPECT_EQ(TLV_ERR_VISITOR, failed.rc);
    EXPECT_EQ(8u, failed.error_offset);
    EXPECT_EQ(1u, failed.matches.size());
}

TEST(Unit_Tlv_Query, PropagatesTraversalErrorsAndLimits) {
    EXPECT_EQ(TLV_ERR_LIMIT, visit_buffer("6F/A5/50", data, is_constructed, 1).rc);
    EXPECT_EQ(TLV_ERR_LIMIT, visit_buffer("6F/A5/50", data, is_constructed, 2).rc);
    EXPECT_EQ(TLV_OK, visit_buffer("6F/A5/50", data, is_constructed, 3).rc);
    const Outcome few = visit_buffer("6F", data, is_constructed, 64, 3);
    EXPECT_EQ(TLV_ERR_LIMIT, few.rc);
    // Damage after the last match is still reported.
    std::vector<uint8_t> truncated(data.begin(), data.begin() + 14);
    const Outcome        run = visit_buffer("6F/A5/50", truncated);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, run.rc);
    EXPECT_EQ(14u, run.error_offset);
    EXPECT_EQ(1u, run.matches.size());
}

TEST(Unit_Tlv_Query, VisitBufferValidatesArguments) {
    const tlv_query_t query = parse("6F");
    Outcome           run;
    Visit             visit = {&run.matches, TLV_VISIT_CONTINUE};
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_query_visit_buffer(data.data(), data.size(), &controlled::format, &query, 1, 10,
                                     nullptr, &visit, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_query_visit_buffer(data.data(), data.size(), &controlled::format, nullptr, 1, 10,
                                     collect, &visit, nullptr));
    tlv_query_t empty = {};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_visit_buffer(data.data(), data.size(), &controlled::format, &empty, 1, 10,
                                     collect, &visit, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_visit_buffer(data.data(), data.size(), nullptr, &query, 1,
                                                       10, collect, &visit, nullptr));
    EXPECT_EQ(TLV_OK, tlv_query_visit_buffer(nullptr, 0, &controlled::format, &query, 1, 10,
                                             collect, &visit, nullptr));
    EXPECT_TRUE(run.matches.empty());
}

TEST(Unit_Tlv_Query, CallerOwnedCursorResumesAndTraversesBeyondPathCapacity) {
    constexpr size_t     depth = TLV_TREE_DEFAULT_DEPTH + 32;
    std::vector<uint8_t> wire;
    for (size_t i = 0; i <= depth; ++i) {
        wire.push_back(0x6F);
        wire.push_back(static_cast<uint8_t>(2 * (depth - i)));
    }
    auto format = controlled::format;
    format.is_constructed = is_constructed;
    std::vector<tlv_tree_frame_t> frames(depth);
    tlv_tree_reader_t             reader;
    ASSERT_EQ(TLV_OK, tlv_tree_reader_init_incremental(&reader, wire.data(), wire.size(), &format,
                                                       frames.data(), depth, depth, depth + 2));
    tlv_query_t         query;
    tlv_query_matcher_t matcher;
    ASSERT_EQ(TLV_OK, tlv_query_parse("6F", &query, nullptr));
    ASSERT_EQ(TLV_OK, tlv_query_matcher_init(&matcher, &query));
    size_t calls = 0;
    auto   visit = [](const tlv_element_t*, size_t d, size_t, void* context) {
        EXPECT_EQ(0u, d);
        ++*static_cast<size_t*>(context);
        return TLV_VISIT_STOP;
    };
    EXPECT_EQ(TLV_OK, tlv_query_visit(&reader, &matcher, visit, &calls, nullptr));
    EXPECT_EQ(TLV_NEED_MORE_DATA, tlv_query_visit(&reader, &matcher, visit, &calls, nullptr));
    EXPECT_EQ(1u, calls);
    const uint8_t final[] = {0x6F, 0};
    ASSERT_EQ(TLV_OK, tlv_tree_reader_set_input(&reader, final, sizeof(final), wire.size(), 1));
    EXPECT_EQ(TLV_OK, tlv_query_visit(&reader, &matcher, visit, &calls, nullptr));
    EXPECT_EQ(2u, calls);
    EXPECT_TRUE(tlv_tree_reader_at_end(&reader));
}
