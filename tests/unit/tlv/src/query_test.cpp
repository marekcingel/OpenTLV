#include "controlled_format.h"
#include "tlv/query/query.h"
#include <gtest/gtest.h>
#include <string>
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

tlv_visit_result_t collect(const tlv_view_t* view, size_t depth, size_t offset, void* context) {
    Visit* visit = static_cast<Visit*>(context);
    visit->matches->push_back({offset, depth, static_cast<size_t>(view->value.length)});
    return visit->result;
}

tlv_query_t parse(const char* text) {
    tlv_query_t query;
    EXPECT_EQ(TLV_OK, tlv_query_parse(text, &query, nullptr)) << text;
    return query;
}

Outcome walk(const char* text, const std::vector<uint8_t>& input = data,
             tlv_is_constructed_fn predicate = is_constructed,
             size_t max_depth = TLV_WALK_MAX_DEPTH, size_t max_elements = 1000,
             tlv_visit_result_t result = TLV_VISIT_CONTINUE) {
    Outcome     run;
    tlv_query_t query = parse(text);
    Visit       visit = {&run.matches, result};
    run.rc = tlv_query_walk(input.data(), input.size(), &controlled::reader, predicate, &query,
                            max_depth, max_elements, collect, &visit, &run.error_offset);
    return run;
}
} // namespace

TEST(Unit_Query, ParsesTagsInEitherCase) {
    const tlv_query_t query = parse("6F/a5/50");
    ASSERT_EQ(3u, query.count);
    EXPECT_EQ(0x6F, query.steps[0].data[0]);
    EXPECT_EQ(1, query.steps[0].size);
    EXPECT_EQ(0xA5, query.steps[1].data[0]);
    EXPECT_EQ(0x50, query.steps[2].data[0]);
    EXPECT_EQ(1u, parse("00").count);
#if TLV_TAG_CAPACITY >= 2
    const tlv_query_t wide = parse("9f02/DF8101");
    EXPECT_EQ(2, wide.steps[0].size);
    EXPECT_EQ(0x9F, wide.steps[0].data[0]);
    EXPECT_EQ(0x02, wide.steps[0].data[1]);
#endif
#if TLV_TAG_CAPACITY >= 3
    EXPECT_EQ(3, parse("DF8101").steps[0].size);
#endif
}

TEST(Unit_Query, RejectsSyntaxErrorsAtTheOffendingPosition) {
    struct Case {
        const char* text;
        size_t      offset;
    };
    const Case cases[] = {{"", 0},       {"/", 0},   {"6F/", 3},    {"/6F", 0},
                          {"6F//50", 3}, {"6", 0},   {"6F/5", 3},   {"6G", 1},
                          {"6F 50", 2},  {" 6F", 0}, {"6F/50 ", 5}, {"0x6F", 1}};
    for (const Case& c : cases) {
        tlv_query_t query = {};
        size_t      offset = 99;
        EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_parse(c.text, &query, &offset)) << c.text;
        EXPECT_EQ(c.offset, offset) << c.text;
        EXPECT_EQ(0u, query.count) << c.text;
    }
}

TEST(Unit_Query, RejectsInvalidArgumentsAndLimits) {
    tlv_query_t query = {};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_parse(nullptr, &query, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_parse("6F", nullptr, nullptr));

    std::string wide;
    for (int i = 0; i <= TLV_TAG_CAPACITY; ++i) wide += "AB";
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_query_parse(("6F/" + wide).c_str(), &query, &offset));
    EXPECT_EQ(3u, offset);

    std::string deepest = "6F";
    for (int i = 1; i < TLV_QUERY_MAX_STEPS; ++i) deepest += "/6F";
    EXPECT_EQ(TLV_OK, tlv_query_parse(deepest.c_str(), &query, nullptr));
    EXPECT_EQ(static_cast<size_t>(TLV_QUERY_MAX_STEPS), query.count);
    offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_query_parse((deepest + "/6F").c_str(), &query, &offset));
    EXPECT_EQ(deepest.size() + 1, offset);
    EXPECT_EQ(static_cast<size_t>(TLV_QUERY_MAX_STEPS), query.count); // Unchanged on failure.
}

TEST(Unit_Query, MatcherRejectsInvalidQueries) {
    tlv_query_matcher_t matcher;
    tlv_query_t         query = parse("6F");
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_matcher_init(nullptr, &query));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_matcher_init(&matcher, nullptr));
    tlv_query_t empty = {};
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_matcher_init(&matcher, &empty));
    query.count = TLV_QUERY_MAX_STEPS + 1;
    EXPECT_EQ(TLV_ERR_INVALID_ARG, tlv_query_matcher_init(&matcher, &query));
    query = parse("6F");
    query.steps[0].size = 0;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_query_matcher_init(&matcher, &query));
    query.steps[0].size = TLV_TAG_CAPACITY + 1;
    EXPECT_EQ(TLV_ERR_INVALID_TAG_SIZE, tlv_query_matcher_init(&matcher, &query));
}

TEST(Unit_Query, MatcherFollowsAPreorderTraversal) {
    const tlv_query_t   query = parse("01/02");
    tlv_query_matcher_t matcher;
    ASSERT_EQ(TLV_OK, tlv_query_matcher_init(&matcher, &query));
    const tlv_tag_t t1 = {{1}, 1}, t2 = {{2}, 1}, t3 = {{3}, 1};
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

TEST(Unit_Query, AddressesEveryElementAlongTheExactPath) {
    const Outcome run = walk("6F/A5/50");
    EXPECT_EQ(TLV_OK, run.rc);
    EXPECT_EQ((std::vector<Match>{{8, 2, 2}, {19, 2, 1}, {22, 2, 1}}), run.matches);
}

TEST(Unit_Query, DistinguishesDepthFromTag) {
    EXPECT_EQ((std::vector<Match>{{12, 0, 1}}), walk("50").matches);
    EXPECT_EQ((std::vector<Match>{{0, 0, 10}, {15, 0, 8}, {25, 0, 7}}), walk("6F").matches);
    EXPECT_EQ((std::vector<Match>{{6, 1, 4}, {17, 1, 6}}), walk("6F/A5").matches);
    EXPECT_EQ((std::vector<Match>{{2, 1, 2}}), walk("6F/84").matches);
    EXPECT_EQ((std::vector<Match>{{27, 1, 5}}), walk("6F/A6").matches);
    EXPECT_EQ((std::vector<Match>{{29, 2, 3}}), walk("6F/A6/A5").matches);
    EXPECT_EQ((std::vector<Match>{{31, 3, 1}}), walk("6F/A6/A5/50").matches);
    EXPECT_TRUE(walk("A5").matches.empty());
    EXPECT_TRUE(walk("6F/50").matches.empty());
    EXPECT_TRUE(walk("6F/A5/51").matches.empty());
    EXPECT_TRUE(walk("6F/A5/50/50").matches.empty());
    EXPECT_EQ(TLV_OK, walk("6F/A5/51").rc);
}

TEST(Unit_Query, OpaqueValuesAnswerOnlyTopLevelQueries) {
    EXPECT_EQ(3u, walk("6F", data, nullptr).matches.size());
    EXPECT_TRUE(walk("6F/A5", data, nullptr).matches.empty());
}

TEST(Unit_Query, HonorsVisitorResults) {
    EXPECT_EQ(1u, walk("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_STOP).matches.size());
    EXPECT_EQ(TLV_OK, walk("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_STOP).rc);
    const Outcome failed = walk("6F/A5/50", data, is_constructed, 64, 1000, TLV_VISIT_ERROR);
    EXPECT_EQ(TLV_ERR_VISITOR, failed.rc);
    EXPECT_EQ(8u, failed.error_offset);
    EXPECT_EQ(1u, failed.matches.size());
}

TEST(Unit_Query, PropagatesTraversalErrorsAndLimits) {
    EXPECT_EQ(TLV_ERR_LIMIT, walk("6F/A5/50", data, is_constructed, 1).rc);
    EXPECT_EQ(TLV_ERR_LIMIT, walk("6F/A5/50", data, is_constructed, 2).rc);
    EXPECT_EQ(TLV_OK, walk("6F/A5/50", data, is_constructed, 3).rc);
    const Outcome few = walk("6F", data, is_constructed, 64, 3);
    EXPECT_EQ(TLV_ERR_LIMIT, few.rc);
    // Damage after the last match is still reported.
    std::vector<uint8_t> truncated(data.begin(), data.begin() + 14);
    const Outcome        run = walk("6F/A5/50", truncated);
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT, run.rc);
    EXPECT_EQ(12u, run.error_offset);
    EXPECT_EQ(1u, run.matches.size());
}

TEST(Unit_Query, WalkValidatesArguments) {
    const tlv_query_t query = parse("6F");
    Outcome           run;
    Visit             visit = {&run.matches, TLV_VISIT_CONTINUE};
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_walk(data.data(), data.size(), &controlled::reader,
                                               nullptr, &query, 1, 10, nullptr, &visit, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_walk(data.data(), data.size(), &controlled::reader,
                                               nullptr, nullptr, 1, 10, collect, &visit, nullptr));
    tlv_query_t empty = {};
    EXPECT_EQ(TLV_ERR_INVALID_ARG,
              tlv_query_walk(data.data(), data.size(), &controlled::reader, nullptr, &empty, 1, 10,
                             collect, &visit, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_query_walk(data.data(), data.size(), nullptr, nullptr, &query,
                                               1, 10, collect, &visit, nullptr));
    EXPECT_EQ(TLV_OK, tlv_query_walk(nullptr, 0, &controlled::reader, nullptr, &query, 1, 10,
                                     collect, &visit, nullptr));
    EXPECT_TRUE(run.matches.empty());
}
