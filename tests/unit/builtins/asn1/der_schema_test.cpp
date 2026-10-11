// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/der_schema.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {

/* Universal tag numbers used throughout: BOOLEAN=1, INTEGER=2,
 * OCTET STRING=4, all primitive; SEQUENCE=16, SET=17, both constructed. */
const tlv_der_schema_type_t kBoolean = {
    TLV_DER_SCHEMA_UNIVERSAL, 1, nullptr, 0, nullptr, 0, 0, nullptr, 0};
const tlv_der_schema_type_t kInteger = {
    TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0, nullptr, 0};
const tlv_der_schema_type_t kOctetString = {
    TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, nullptr, 0};

tlv_der_schema_component_t Required(const tlv_der_schema_type_t& type) {
    return {&type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, nullptr, 0};
}

tlv_result_t Read(const std::vector<uint8_t>& data, const tlv_der_schema_type_t& root,
                  size_t* consumed = nullptr, size_t* error_offset = nullptr,
                  const tlv_der_schema_limits_t* limits = nullptr) {
    tlv_element_t           element{};
    size_t                  local_consumed = 0;
    tlv_schema_diagnostic_t diagnostic{};
    tlv_result_t rc = tlv_der_schema_read(data.data(), data.size(), &root, limits, &element,
                                          consumed ? consumed : &local_consumed, &diagnostic);
    if (error_offset) *error_offset = diagnostic.diagnostic.location.begin;
    return rc;
}

} // namespace

TEST(Unit_Tlv_DerSchema, CallbackContractAndWorkspaceFailuresRemainDistinct) {
    struct State {
        int      mode;
        unsigned calls;
    } state{};
    auto encode = [](const void* context, const tlv_der_schema_component_t*, size_t, uint8_t* data,
                     size_t, size_t* written, int* absent) -> tlv_result_t {
        auto& s = *const_cast<State*>(static_cast<const State*>(context));
        ++s.calls;
        *written = 1;
        *absent = s.mode == 2 && s.calls > 1;
        if (s.mode == 3) return TLV_ERR_INVALID_VALUE;
        if (s.mode == 4) return TLV_END;
        if (s.mode == 5) return static_cast<tlv_result_t>(23);
        if (data) {
            data[0] = 1;
            if (s.mode == 1) *written = 0;
        }
        return TLV_OK;
    };
    for (int mode = 0; mode <= 5; ++mode) {
        for (bool detailed : {false, true}) {
            state = {mode, 0};
            uint8_t destination[8], arena[32]{};
            std::memset(destination, 0xa5, sizeof destination);
            size_t                  written = 99;
            tlv_schema_diagnostic_t diagnostic{};
            const auto              expected = mode == 0   ? TLV_ERR_BUFFER_TOO_SHORT
                                               : mode == 3 ? TLV_ERR_INVALID_VALUE
                                                           : TLV_ERR_CALLBACK;
            EXPECT_EQ(expected,
                      tlv_der_schema_write(destination, sizeof destination, &kInteger, encode,
                                           &state, nullptr, arena, mode == 0 ? 0 : sizeof arena,
                                           nullptr, 0, &written, detailed ? &diagnostic : nullptr));
            EXPECT_EQ(99u, written);
            for (auto byte : destination) EXPECT_EQ(0xa5, byte);
            EXPECT_LE(state.calls, 3u);
            if (detailed) {
                EXPECT_EQ(expected, diagnostic.diagnostic.code);
                EXPECT_FALSE(diagnostic.diagnostic.location.kind);
            }
        }
    }
}

TEST(Unit_Tlv_DerSchema, InvalidDefinitionPrecedesInputAndCallbacks) {
    const tlv_value_constraint_t invalid = {
        static_cast<tlv_value_constraint_kind_t>(99), 0, 0, nullptr, 0, nullptr};
    const tlv_der_schema_leaf_constraint_t constraint = {0, SIZE_MAX, &invalid};
    const tlv_der_schema_type_t            type = {
        TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0, &constraint, 0};
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&type, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DEFINITION, diagnostic.detail.kind);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    tlv_element_t element{};
    size_t        consumed = 123;
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              tlv_der_schema_read(nullptr, 0, &type, nullptr, &element, &consumed, &diagnostic));
    EXPECT_EQ(123u, consumed);
    int  calls = 0;
    auto encode = [](const void* context, const tlv_der_schema_component_t*, size_t, uint8_t*,
                     size_t, size_t*, int*) -> tlv_result_t {
        ++*static_cast<int*>(const_cast<void*>(context));
        return TLV_ERR_VISITOR;
    };
    size_t written = 123;
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA,
              tlv_der_schema_write(nullptr, 0, &type, encode, &calls, nullptr, nullptr, 0, nullptr,
                                   0, &written, &diagnostic));
    EXPECT_EQ(0, calls);
    EXPECT_EQ(123u, written);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
}

TEST(Unit_Tlv_DerSchema, RequiredRootHasMissingDetailForReadAndWrite) {
    tlv_schema_diagnostic_t diagnostic{};
    tlv_element_t           element{};
    size_t                  consumed = 123;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_read(nullptr, 0, &kInteger, nullptr, &element,
                                                  &consumed, &diagnostic));
    EXPECT_EQ(TLV_ERR_SCHEMA, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.detail.kind);
    EXPECT_EQ(TLV_LOCATION_SCOPE_END, diagnostic.diagnostic.location.kind);
    EXPECT_TRUE(diagnostic.diagnostic.location.kind);
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(123u, consumed);
    auto absent = [](const void*, const tlv_der_schema_component_t*, size_t, uint8_t*, size_t,
                     size_t* written, int* missing) -> tlv_result_t {
        *written = 0;
        *missing = 1;
        return TLV_OK;
    };
    size_t written = 123;
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_write(nullptr, 0, &kInteger, absent, nullptr, nullptr,
                                                   nullptr, 0, nullptr, 0, &written, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_MISSING, diagnostic.detail.kind);
    EXPECT_EQ(TLV_LOCATION_INSERTION, diagnostic.diagnostic.location.kind);
    EXPECT_TRUE(diagnostic.diagnostic.location.kind);
    EXPECT_EQ(0u, diagnostic.diagnostic.location.begin);
    EXPECT_EQ(123u, written);
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_write(nullptr, 0, &kInteger, absent, nullptr, nullptr,
                                                   nullptr, 0, nullptr, 0, &written, nullptr));
}

TEST(Unit_Tlv_DerSchema, DefinitionGraphErrorsAreNotInputOrCapabilityFailures) {
    tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE_OF, 0, nullptr, 0, nullptr, 0, SIZE_MAX, nullptr, 0};
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&root, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DEFINITION, diagnostic.detail.kind);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    auto element = Required(root);
    root.element = &element;
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&root, &diagnostic));
    element.type = &kInteger;
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&root, &diagnostic));
    root.kind = TLV_DER_SCHEMA_SEQUENCE;
    root.components = &element;
    root.component_count = TLV_DER_SCHEMA_MAX_COMPONENTS + 1;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_der_schema_check(&root, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_NONE, diagnostic.detail.kind);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_check(nullptr, &diagnostic));
    EXPECT_EQ(TLV_ERR_NULL_ARG, diagnostic.diagnostic.code);
}

TEST(Unit_Tlv_DerSchema, DistinguishesSetFromSetOf) {
    /* Ascending-by-content INTEGER(1) then INTEGER(2), wrapped in the root
     * type's own tag (SET and SET OF share universal tag 17): valid SET OF
     * order, but never a valid SET (a SET requires components with distinct
     * tags; two untagged INTEGER components share a tag). */
    const std::vector<uint8_t> data = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};

    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t set_of = {
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX, nullptr, 0};
    size_t consumed = 0;
    EXPECT_EQ(TLV_OK, Read(data, set_of, &consumed));
    EXPECT_EQ(data.size(), consumed);

    tlv_der_schema_component_t  bad_components[2] = {Required(kInteger), Required(kInteger)};
    const tlv_der_schema_type_t bad_set = {
        TLV_DER_SCHEMA_SET, 0, bad_components, 2, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, Read(data, bad_set));
}

TEST(Unit_Tlv_DerSchema, SetRequiresCanonicalTagOrder) {
    tlv_der_schema_component_t  components[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&set_type, nullptr));

    const std::vector<uint8_t> ascending = {0x31, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x01};
    size_t                     consumed = 0;
    EXPECT_EQ(TLV_OK, Read(ascending, set_type, &consumed));
    EXPECT_EQ(ascending.size(), consumed);

    const std::vector<uint8_t> descending = {0x31, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x05};
    size_t                     offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, Read(descending, set_type, nullptr, &offset));
    EXPECT_EQ(5u, offset);
}

TEST(Unit_Tlv_DerSchema, SetOfRequiresCanonicalEncodingOrder) {
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t set_of = {
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX, nullptr, 0};

    const std::vector<uint8_t> ascending = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    EXPECT_EQ(TLV_OK, Read(ascending, set_of));

    const std::vector<uint8_t> descending = {0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
    size_t                     offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, Read(descending, set_of, nullptr, &offset));
    EXPECT_EQ(5u, offset);

    const std::vector<uint8_t> equal_pair = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    EXPECT_EQ(TLV_OK, Read(equal_pair, set_of));
}

TEST(Unit_Tlv_DerSchema, SetOfElementCountBounds) {
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t set_of = {
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 2, 2, nullptr, 0};
    EXPECT_EQ(TLV_OK,
              Read(std::vector<uint8_t>{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, set_of));
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x31, 0x03, 0x02, 0x01, 0x01}, set_of));
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01,
                                                        0x02, 0x02, 0x01, 0x03},
                                   set_of));
}

TEST(Unit_Tlv_DerSchema, SequenceOfAcceptsAnyElementOrder) {
    /* Unlike SET OF, SEQUENCE OF (universal tag 16, shared with SEQUENCE)
     * does not require elements to be sorted by complete encoding. */
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t sequence_of = {
        TLV_DER_SCHEMA_SEQUENCE_OF, 0, nullptr, 0, &element, 0, SIZE_MAX, nullptr, 0};

    const std::vector<uint8_t> ascending = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    size_t                     consumed = 0;
    EXPECT_EQ(TLV_OK, Read(ascending, sequence_of, &consumed));
    EXPECT_EQ(ascending.size(), consumed);

    const std::vector<uint8_t> descending = {0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
    EXPECT_EQ(TLV_OK, Read(descending, sequence_of, &consumed));
    EXPECT_EQ(descending.size(), consumed);
}

TEST(Unit_Tlv_DerSchema, SequenceOfElementCountBounds) {
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t sequence_of = {
        TLV_DER_SCHEMA_SEQUENCE_OF, 0, nullptr, 0, &element, 2, 2, nullptr, 0};
    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02},
                           sequence_of));
    EXPECT_EQ(TLV_ERR_SCHEMA,
              Read(std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x01}, sequence_of));
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01,
                                                        0x02, 0x02, 0x01, 0x03},
                                   sequence_of));
}

TEST(Unit_Tlv_DerSchema, LeafValueRangeConstraint) {
    static const tlv_value_constraint_t kRange = {
        TLV_VALUE_CONSTRAINT_RANGE, 0, 255, nullptr, 0, nullptr};
    static const tlv_der_schema_leaf_constraint_t kConstraint = {0, SIZE_MAX, &kRange};
    const tlv_der_schema_type_t                   constrained_integer = {
        TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0, &kConstraint, 0};
    ASSERT_EQ(TLV_OK, tlv_der_schema_check(&constrained_integer, nullptr));

    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x02, 0x01, 0x05}, constrained_integer));

    /* 0x0100 == 256, outside [0, 255]; the offset points at the value bytes. */
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x02, 0x02, 0x01, 0x00},
                                   constrained_integer, nullptr, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_DerSchema, LeafSizeConstraint) {
    static const tlv_der_schema_leaf_constraint_t kSize = {2, 4, nullptr};
    const tlv_der_schema_type_t                   sized_octet_string = {
        TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, &kSize, 0};
    ASSERT_EQ(TLV_OK, tlv_der_schema_check(&sized_octet_string, nullptr));

    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x04, 0x02, 0xAA, 0xBB}, sized_octet_string));

    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              Read(std::vector<uint8_t>{0x04, 0x01, 0xAA}, sized_octet_string, nullptr, &offset));
    EXPECT_EQ(2u, offset);

    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x04, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE},
                                   sized_octet_string));
}

TEST(Unit_Tlv_DerSchema, SchemaCheckRejectsInvalidLeafConstraint) {
    /* value_constraint is only valid on INTEGER (2) or ENUMERATED (10). */
    static const tlv_value_constraint_t kRange = {
        TLV_VALUE_CONSTRAINT_RANGE, 0, 10, nullptr, 0, nullptr};
    static const tlv_der_schema_leaf_constraint_t kBadValueConstraint = {0, SIZE_MAX, &kRange};
    const tlv_der_schema_type_t                   bad_octet_string = {
        TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, &kBadValueConstraint, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&bad_octet_string, nullptr));

    static const tlv_der_schema_leaf_constraint_t kBadLengthConstraint = {10, 5, nullptr};
    const tlv_der_schema_type_t                   bad_length = {
        TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, &kBadLengthConstraint, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&bad_length, nullptr));
}

TEST(Unit_Tlv_DerSchema, SequenceExtensionMarkerAcceptsTrailingContent) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t extensible_seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 1};
    ASSERT_EQ(TLV_OK, tlv_der_schema_check(&extensible_seq, nullptr));

    /* SEQUENCE { INTEGER 5, <unknown future extension: OCTET STRING "z"> }. */
    const std::vector<uint8_t> one_extension = {0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 'z'};
    size_t                     consumed = 0;
    EXPECT_EQ(TLV_OK, Read(one_extension, extensible_seq, &consumed));
    EXPECT_EQ(one_extension.size(), consumed);

    /* Multiple trailing unknown elements are all accepted. */
    const std::vector<uint8_t> two_extensions = {0x30, 0x09, 0x02, 0x01, 0x05, 0x04,
                                                 0x01, 'z',  0x01, 0x01, 0xFF};
    EXPECT_EQ(TLV_OK, Read(two_extensions, extensible_seq, &consumed));
    EXPECT_EQ(two_extensions.size(), consumed);
}

TEST(Unit_Tlv_DerSchema, SequenceWithoutExtensionMarkerRejectsTrailingContent) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    const std::vector<uint8_t> with_extra = {0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 'z'};
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(with_extra, seq));
}

TEST(Unit_Tlv_DerSchema, SequenceExtensionMarkerStillValidatesWellFormedness) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t extensible_seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 1};
    /* The extension element is a dangling tag byte with no length byte
     * within the SEQUENCE's own declared content: still rejected as
     * malformed, even though its tag/content would otherwise be
     * uninterpreted. */
    const std::vector<uint8_t> data = {0x30, 0x04, 0x02, 0x01, 0x05, 0x30};
    EXPECT_NE(TLV_OK, Read(data, extensible_seq));
}

TEST(Unit_Tlv_DerSchema, SequenceExtensionMarkerDoesNotWaiveRequiredComponents) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t extensible_seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 1};
    /* No INTEGER at all, just an unknown extension element. */
    const std::vector<uint8_t> data = {0x30, 0x03, 0x04, 0x01, 'z'};
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(data, extensible_seq));
}

TEST(Unit_Tlv_DerSchema, SequenceRequiredOptionalDefault) {
    static const uint8_t       kFalseDefault[] = {0x01, 0x01, 0x00};
    tlv_der_schema_component_t components[3] = {
        Required(kInteger),
        {&kOctetString, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, nullptr, 0},
        {&kBoolean, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_DEFAULT, kFalseDefault,
         sizeof(kFalseDefault)},
    };
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 3, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&seq, nullptr));

    /* Required only. */
    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x05}, seq));
    /* Required + optional. */
    EXPECT_EQ(TLV_OK,
              Read(std::vector<uint8_t>{0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x01}, seq));
    /* Required + non-default boolean (TRUE). */
    EXPECT_EQ(TLV_OK,
              Read(std::vector<uint8_t>{0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF}, seq));
    /* Required + default-equal boolean (FALSE) must be rejected. */
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              Read(std::vector<uint8_t>{0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0x00}, seq,
                   nullptr, &offset));
    EXPECT_EQ(5u, offset);
    /* Missing required. */
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x30, 0x03, 0x04, 0x01, 0x01}, seq));
}

TEST(Unit_Tlv_DerSchema, ImplicitTagging) {
    tlv_der_schema_component_t component = {
        &kInteger, TLV_DER_TAG_IMPLICIT, TLV_ASN1_CONTEXT_SPECIFIC, 0, TLV_DER_REQUIRED, nullptr,
        0};
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&seq, nullptr));

    /* SEQUENCE(0x30) { [0] IMPLICIT INTEGER 5 (0x80 01 05) }. */
    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x30, 0x03, 0x80, 0x01, 0x05}, seq));

    /* Non-canonical (non-minimal) INTEGER content is rejected via the
     * underlying type, even though the wire tag is context-specific. */
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, Read(std::vector<uint8_t>{0x30, 0x04, 0x80, 0x02, 0x00, 0x05},
                                          seq, nullptr, &offset));
    EXPECT_EQ(4u, offset);

    /* Wrong constructed bit for the underlying (primitive) type: no
     * component matches, so it is reported as a missing required field. */
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x30, 0x03, 0xA0, 0x01, 0x05}, seq));
}

TEST(Unit_Tlv_DerSchema, ExplicitTagging) {
    tlv_der_schema_component_t component = {
        &kInteger, TLV_DER_TAG_EXPLICIT, TLV_ASN1_CONTEXT_SPECIFIC, 0, TLV_DER_REQUIRED, nullptr,
        0};
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&seq, nullptr));

    /* SEQUENCE { [0] EXPLICIT INTEGER 5 }: 30 05 A0 03 02 01 05. */
    size_t                     consumed = 0;
    const std::vector<uint8_t> valid = {0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x05};
    EXPECT_EQ(TLV_OK, Read(valid, seq, &consumed));
    EXPECT_EQ(valid.size(), consumed);

    /* Trailing byte after the one complete inner TLV inside the wrapper:
     * offset points at the unexpected trailing byte itself. */
    size_t                     offset = 99;
    const std::vector<uint8_t> trailing = {0x30, 0x06, 0xA0, 0x04, 0x02, 0x01, 0x05, 0xFF};
    EXPECT_EQ(TLV_ERR_INVALID_VALUE, Read(trailing, seq, nullptr, &offset));
    EXPECT_EQ(7u, offset);

    /* Inner tag does not match the underlying type's natural identity. */
    const std::vector<uint8_t> wrong_inner = {0x30, 0x05, 0xA0, 0x03, 0x04, 0x01, 0x05};
    EXPECT_EQ(TLV_ERR_INVALID_TAG, Read(wrong_inner, seq));
}

TEST(Unit_Tlv_DerSchema, ChoiceResolution) {
    tlv_der_schema_component_t  alternatives[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t choice = {
        TLV_DER_SCHEMA_CHOICE, 0, alternatives, 2, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&choice, nullptr));

    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x02, 0x01, 0x05}, choice));
    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x04, 0x01, 0x01}, choice));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, Read(std::vector<uint8_t>{0x01, 0x01, 0xFF}, choice));
}

TEST(Unit_Tlv_DerSchema, DepthLimitAppliesToPushingAFrame) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    limits.base.max_depth = 0;
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x05}, seq, nullptr,
                                  &offset, &limits));
    /* Matches tlv_der_read's own convention: a depth-limit failure points at
     * the position where the (disallowed) value/first child would begin. */
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_DerSchema, ElementCountLimitAppliesAcrossNesting) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    limits.base.max_elements = 1;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x05}, seq, nullptr,
                                  nullptr, &limits));
}

TEST(Unit_Tlv_DerSchema, SchemaCheckCatchesAuthoringErrors) {
    tlv_der_schema_component_t  duplicate[2] = {Required(kInteger), Required(kInteger)};
    const tlv_der_schema_type_t bad_set = {
        TLV_DER_SCHEMA_SET, 0, duplicate, 2, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&bad_set, nullptr));

    tlv_der_schema_component_t optional_alt[1] = {
        {&kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, nullptr, 0}};
    const tlv_der_schema_type_t bad_choice = {
        TLV_DER_SCHEMA_CHOICE, 0, optional_alt, 1, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&bad_choice, nullptr));

    const tlv_der_schema_type_t choice_type = {
        TLV_DER_SCHEMA_CHOICE, 0, nullptr, 0, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_component_t  implicit_choice = {&choice_type,
                                                   TLV_DER_TAG_IMPLICIT,
                                                   TLV_ASN1_CONTEXT_SPECIFIC,
                                                   0,
                                                   TLV_DER_REQUIRED,
                                                   nullptr,
                                                   0};
    const tlv_der_schema_type_t wrapper = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &implicit_choice, 1, nullptr, 0, 0, nullptr, 0};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&wrapper, nullptr));

    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_check(nullptr, nullptr));
}

namespace {

struct ScriptEntry {
    const tlv_der_schema_component_t* component;
    size_t                            index;
    bool                              present;
    std::vector<uint8_t>              bytes;
};

tlv_result_t ScriptEncode(const void* context, const tlv_der_schema_component_t* component,
                          size_t index, uint8_t* data, size_t capacity, size_t* written,
                          int* absent) {
    const auto* entries = static_cast<const std::vector<ScriptEntry>*>(context);
    for (const auto& entry : *entries) {
        if (entry.component != component || entry.index != index) continue;
        if (!entry.present) {
            *absent = 1;
            return TLV_OK;
        }
        *absent = 0;
        if (data) {
            if (capacity < entry.bytes.size()) return TLV_ERR_BUFFER_TOO_SHORT;
            if (!entry.bytes.empty()) std::memcpy(data, entry.bytes.data(), entry.bytes.size());
        }
        *written = entry.bytes.size();
        return TLV_OK;
    }
    /* An unscripted container component (SEQUENCE/SET/SET OF/SEQUENCE OF/
     * CHOICE, or the synthetic root wrapper) is reported present with no
     * content of its own, since its bytes come from its children instead. An
     * unscripted leaf (UNIVERSAL/ANY) -- including a SET OF or SEQUENCE OF
     * element index beyond the scripted ones -- is reported absent. */
    switch (component->type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF:
        case TLV_DER_SCHEMA_SEQUENCE_OF:
        case TLV_DER_SCHEMA_CHOICE:
            *absent = 0;
            *written = 0;
            return TLV_OK;
        default: *absent = 1; return TLV_OK;
    }
}

tlv_result_t Write(const tlv_der_schema_type_t& root, const std::vector<ScriptEntry>& script,
                   std::vector<uint8_t>* output, size_t* error_offset = nullptr) {
    std::vector<uint8_t>                 arena(4096);
    std::vector<tlv_der_schema_record_t> records(64);
    output->assign(256, 0);
    size_t                  written = 0;
    tlv_schema_diagnostic_t diagnostic{};
    tlv_result_t            rc =
        tlv_der_schema_write(output->data(), output->size(), &root, ScriptEncode, &script, nullptr,
                             arena.data(), arena.size(), records.data(), records.size(), &written,
                             error_offset ? &diagnostic : nullptr);
    if (error_offset) *error_offset = diagnostic.diagnostic.location.begin;
    output->resize(rc == TLV_OK ? written : 0);
    return rc;
}

} // namespace

TEST(Unit_Tlv_DerSchema, WriteSequenceOmitsDefaultEqualComponent) {
    static const uint8_t       kFalseDefault[] = {0x01, 0x01, 0x00};
    tlv_der_schema_component_t components[2] = {
        Required(kInteger),
        {&kBoolean, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_DEFAULT, kFalseDefault,
         sizeof(kFalseDefault)},
    };
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0, nullptr, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK,
              Write(seq, {{&components[0], 0, true, {0x05}}, {&components[1], 0, true, {0x00}}},
                    &output));
    const std::vector<uint8_t> expected = {0x30, 0x03, 0x02, 0x01, 0x05};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteSequenceKeepsNonDefaultValue) {
    static const uint8_t       kFalseDefault[] = {0x01, 0x01, 0x00};
    tlv_der_schema_component_t components[2] = {
        Required(kInteger),
        {&kBoolean, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_DEFAULT, kFalseDefault,
         sizeof(kFalseDefault)},
    };
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0, nullptr, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK,
              Write(seq, {{&components[0], 0, true, {0x05}}, {&components[1], 0, true, {0xFF}}},
                    &output));
    const std::vector<uint8_t> expected = {0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteSetOrdersComponentsByTag) {
    tlv_der_schema_component_t  components[2] = {Required(kOctetString), Required(kInteger)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK, Write(set_type,
                            {{&components[0], 0, true, {0x01}}, {&components[1], 0, true, {0x05}}},
                            &output));
    /* INTEGER (tag 2) sorts before OCTET STRING (tag 4) regardless of the
     * declared component order or callback invocation order. */
    const std::vector<uint8_t> expected = {0x31, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x01};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteSetOfSortsElementsByCompleteEncoding) {
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t set_of = {
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX, nullptr, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK,
              Write(set_of, {{&element, 0, true, {0x02}}, {&element, 1, true, {0x01}}}, &output));
    const std::vector<uint8_t> expected = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteSequenceOfKeepsProductionOrder) {
    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t sequence_of = {
        TLV_DER_SCHEMA_SEQUENCE_OF, 0, nullptr, 0, &element, 0, SIZE_MAX, nullptr, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK, Write(sequence_of, {{&element, 0, true, {0x02}}, {&element, 1, true, {0x01}}},
                            &output));
    /* Unlike SET OF, elements are not reordered: 0x02 stays before 0x01. */
    const std::vector<uint8_t> expected = {0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteRejectsValueOutsideConstraint) {
    static const tlv_value_constraint_t kRange = {
        TLV_VALUE_CONSTRAINT_RANGE, 0, 255, nullptr, 0, nullptr};
    static const tlv_der_schema_leaf_constraint_t kConstraint = {0, SIZE_MAX, &kRange};
    const tlv_der_schema_type_t                   constrained_integer = {
        TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0, &kConstraint, 0};
    tlv_der_schema_component_t  component = Required(constrained_integer);
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};

    std::vector<uint8_t> output;
    /* 0x0100 == 256, outside [0, 255]. */
    size_t offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, Write(seq, {{&component, 0, true, {0x01, 0x00}}}, &output, &offset));
    EXPECT_EQ(4u, offset);

    ASSERT_EQ(TLV_OK, Write(seq, {{&component, 0, true, {0x05}}}, &output));
    const std::vector<uint8_t> expected = {0x30, 0x03, 0x02, 0x01, 0x05};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteMissingRequiredFails) {
    tlv_der_schema_component_t  components[1] = {Required(kInteger)};
    const tlv_der_schema_type_t seq = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 1, nullptr, 0, 0, nullptr, 0};
    std::vector<uint8_t> output;
    size_t               offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, Write(seq, {}, &output, &offset));
    EXPECT_EQ(2u, offset);
}

TEST(Unit_Tlv_DerSchema, WriteRoundTripsThroughRead) {
    tlv_der_schema_component_t  components[2] = {Required(kOctetString), Required(kInteger)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};
    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK, Write(set_type,
                            {{&components[0], 0, true, {0x01}}, {&components[1], 0, true, {0x05}}},
                            &output));
    size_t consumed = 0;
    EXPECT_EQ(TLV_OK, Read(output, set_type, &consumed));
    EXPECT_EQ(output.size(), consumed);
}

TEST(Unit_Tlv_DerSchema, WriteMissingRequiredMatchesReadPosition) {
    for (auto kind : {TLV_DER_SCHEMA_SEQUENCE, TLV_DER_SCHEMA_SET}) {
        tlv_der_schema_component_t  components[] = {Required(kInteger), Required(kOctetString)};
        const tlv_der_schema_type_t root = {kind, 0, components, 2, nullptr, 0, 0, nullptr, 0};
        std::vector<uint8_t>        output;
        size_t                      offset = 99;
        EXPECT_EQ(TLV_ERR_SCHEMA, Write(root, {}, &output, &offset));
        EXPECT_EQ(2u, offset);
        EXPECT_EQ(TLV_ERR_SCHEMA,
                  Write(root, {{&components[1], 0, true, {0x55}}}, &output, &offset));
        EXPECT_EQ(kind == TLV_DER_SCHEMA_SEQUENCE ? 2u : 5u, offset);
        size_t read_offset = 99;
        EXPECT_EQ(
            TLV_ERR_SCHEMA,
            Read({static_cast<uint8_t>(kind == TLV_DER_SCHEMA_SET ? 0x31 : 0x30), 3, 4, 1, 0x55},
                 root, nullptr, &read_offset));
        EXPECT_EQ(read_offset, offset);
        EXPECT_EQ(TLV_ERR_SCHEMA,
                  Write(root, {{&components[0], 0, true, {0x55}}}, &output, &offset));
        EXPECT_EQ(5u, offset); // The absent second field follows the encoded INTEGER.
    }
}

TEST(Unit_Tlv_DerSchema, WriteNestedMissingAccountsForLongHeadersAndSetOrder) {
    tlv_der_schema_component_t  missing = Required(kInteger);
    const tlv_der_schema_type_t inner = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &missing, 1, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_component_t  components[] = {Required(inner), Required(kOctetString)};
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};
    std::vector<uint8_t> output;
    size_t               offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA,
              Write(root, {{&components[1], 0, true, std::vector<uint8_t>(128, 0x55)}}, &output,
                    &offset));
    // SET header (3), sorted OCTET STRING (3+128), empty SEQUENCE header (2).
    EXPECT_EQ(136u, offset);
    std::vector<uint8_t> wire = {0x31, 0x81, 0x85, 4, 0x81, 0x80};
    wire.insert(wire.end(), 128, 0x55);
    wire.insert(wire.end(), {0x30, 0});
    size_t read_offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(wire, root, nullptr, &read_offset));
    EXPECT_EQ(read_offset, offset);
}

TEST(Unit_Tlv_DerSchema, WriteNestedSequenceMissingIncludesPrecedingSibling) {
    tlv_der_schema_component_t  missing = Required(kInteger);
    const tlv_der_schema_type_t inner = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &missing, 1, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_component_t  components[] = {Required(kBoolean), Required(inner)};
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0, nullptr, 0};
    std::vector<uint8_t> output;
    size_t               offset = 99;
    EXPECT_EQ(TLV_ERR_SCHEMA, Write(root, {{&components[0], 0, true, {0xff}}}, &output, &offset));
    EXPECT_EQ(7u, offset);
}

TEST(Unit_Tlv_DerSchema, WriteLeafOffsetIncludesTaggingAndSortedSiblings) {
    const tlv_der_schema_leaf_constraint_t size = {2, 4, nullptr};
    const tlv_der_schema_type_t            leaf = {
        TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, &size, 0};
    for (auto tagging : {TLV_DER_TAG_NONE, TLV_DER_TAG_IMPLICIT, TLV_DER_TAG_EXPLICIT}) {
        tlv_der_schema_component_t components[] = {Required(leaf), Required(kInteger)};
        components[0].tagging = tagging;
        if (tagging != TLV_DER_TAG_NONE) {
            components[0].tag_class = TLV_ASN1_CONTEXT_SPECIFIC;
            components[0].tag_number = 32;
        }
        const tlv_der_schema_type_t root = {
            TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};
        std::vector<uint8_t> output;
        size_t               offset = 99;
        EXPECT_EQ(TLV_ERR_SCHEMA,
                  Write(root, {{&components[0], 0, true, {0x55}}, {&components[1], 0, true, {1}}},
                        &output, &offset));
        EXPECT_EQ(tagging == TLV_DER_TAG_NONE       ? 7u
                  : tagging == TLV_DER_TAG_IMPLICIT ? 8u
                                                    : 10u,
                  offset);
    }
}

TEST(Unit_Tlv_DerSchema, WriteInvalidEmptyIntegerOffsetIsNotDoubleCounted) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    std::vector<uint8_t>    output;
    size_t                  read_offset = 99;
    tlv_schema_diagnostic_t offset{};
    const tlv_result_t      rc = Read({0x30, 2, 2, 0}, root, nullptr, &read_offset);
    EXPECT_NE(TLV_OK, rc);
    EXPECT_EQ(rc,
              Write(root, {{&component, 0, true, {}}}, &output, &offset.diagnostic.location.begin));
    EXPECT_EQ(read_offset, offset.diagnostic.location.begin);
    const std::vector<ScriptEntry> script = {{&component, 0, true, {}}};
    uint8_t                        arena[1] = {};
    size_t                         written = 77;
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(rc, tlv_der_schema_write(nullptr, 0, &root, ScriptEncode, &script, nullptr, arena,
                                       sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    EXPECT_EQ(77u, written);
}

TEST(Unit_Tlv_DerSchema, WriteCollectionCountOffsetsMatchRead) {
    for (auto kind : {TLV_DER_SCHEMA_SEQUENCE_OF, TLV_DER_SCHEMA_SET_OF}) {
        tlv_der_schema_component_t element = Required(kInteger);
        tlv_der_schema_type_t      root = {kind, 0, nullptr, 0, &element, 2, 2, nullptr, 0};
        std::vector<uint8_t>       output;
        size_t                     offset = 99;
        EXPECT_EQ(TLV_ERR_SCHEMA, Write(root, {{&element, 0, true, {1}}}, &output, &offset));
        EXPECT_EQ(5u, offset);
        root.min_elements = 0;
        root.max_elements = 1;
        EXPECT_EQ(TLV_ERR_SCHEMA, Write(root, {{&element, 0, true, {2}}, {&element, 1, true, {1}}},
                                        &output, &offset));
        EXPECT_EQ(5u, offset);
    }
}

TEST(Unit_Tlv_DerSchema, WriteFailurePreservesDestinationAndWritten) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0, nullptr, 0};
    std::vector<ScriptEntry> script;
    uint8_t                  destination[] = {0xaa, 0xbb};
    uint8_t                  arena[64] = {};
    size_t                   written = 77;
    tlv_schema_diagnostic_t  offset{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_der_schema_write(destination, sizeof(destination), &root, ScriptEncode, &script,
                                   nullptr, arena, sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(2u, offset.diagnostic.location.begin);
    EXPECT_EQ(77u, written);
    EXPECT_EQ(0xaa, destination[0]);
    EXPECT_EQ(0xbb, destination[1]);
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_der_schema_write(destination, sizeof(destination), nullptr, ScriptEncode, &script,
                                   nullptr, arena, sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    script.push_back({&component, 0, true, {1}});
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(TLV_ERR_BUFFER_TOO_SHORT,
              tlv_der_schema_write(destination, sizeof(destination), &root, ScriptEncode, &script,
                                   nullptr, arena, sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    EXPECT_EQ(77u, written);
}

TEST(Unit_Tlv_DerSchema, WritePreservesFirstFailureWhenOffsetCompositionCannotFinish) {
    tlv_der_schema_component_t  components[] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0, nullptr, 0};
    const std::vector<ScriptEntry> script = {{&components[1], 0, true, {0x55}}};
    uint8_t                        arena[1] = {};
    size_t                         written = 77;
    tlv_schema_diagnostic_t        offset{};
    // Missing first component wins over later scratch exhaustion.
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_der_schema_write(nullptr, 0, &root, ScriptEncode, &script, nullptr, arena,
                                   sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
    EXPECT_EQ(77u, written);
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_der_schema_write(nullptr, 0, &root, ScriptEncode, &script, nullptr, arena,
                                   sizeof(arena), nullptr, 0, &written, nullptr));
}

TEST(Unit_Tlv_DerSchema, WriteSizeQueryReportsSameSchemaOffset) {
    tlv_der_schema_component_t  missing = Required(kInteger);
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &missing, 1, nullptr, 0, 0, nullptr, 0};
    const std::vector<ScriptEntry> script;
    uint8_t                        arena[16] = {};
    size_t                         written = 77;
    tlv_schema_diagnostic_t        offset{};
    EXPECT_EQ(TLV_ERR_SCHEMA,
              tlv_der_schema_write(nullptr, 0, &root, ScriptEncode, &script, nullptr, arena,
                                   sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(2u, offset.diagnostic.location.begin);
    EXPECT_EQ(77u, written);
    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    limits.base.max_depth = TLV_DER_MAX_DEPTH + 1;
    offset.diagnostic.location.begin = 99;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED,
              tlv_der_schema_write(nullptr, 0, &root, ScriptEncode, &script, &limits, arena,
                                   sizeof(arena), nullptr, 0, &written, &offset));
    EXPECT_EQ(0u, offset.diagnostic.location.begin);
}

TEST(Unit_Tlv_DerSchema, SharedDagAndDeepUnusedDefinitionsHaveBoundedCheckingWork) {
    tlv_der_schema_type_t      types[40]{};
    tlv_der_schema_component_t components[40][2]{};
    for (size_t i = 0; i < 40; ++i) {
        types[i] = {TLV_DER_SCHEMA_SEQUENCE, 0, components[i], 2, nullptr, 0, 0, nullptr, 0};
        for (size_t j = 0; j < 2; ++j) {
            components[i][j] = Required(i + 1 < 40 ? types[i + 1] : kInteger);
            components[i][j].presence = TLV_DER_OPTIONAL;
        }
    }
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(types, nullptr));
    EXPECT_EQ(TLV_OK, Read({0x30, 0}, types[0]));
    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK, Write(types[0],
                            {{&components[0][0], 0, false, {}}, {&components[0][1], 0, false, {}}},
                            &output));
    EXPECT_EQ((std::vector<uint8_t>{0x30, 0}), output);
    components[39][1].type = nullptr;
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, Read({0x30, 0}, types[0]));
}

TEST(Unit_Tlv_DerSchema, RecursiveContainersReadAndWriteUnderLiveDepthLimits) {
    for (auto kind : {TLV_DER_SCHEMA_SEQUENCE_OF, TLV_DER_SCHEMA_SET_OF}) {
        tlv_der_schema_type_t root = {kind, 0, nullptr, 0, nullptr, 0, SIZE_MAX, nullptr, 0};
        auto                  element = Required(root);
        root.element = &element;
        const uint8_t              tag = kind == TLV_DER_SCHEMA_SET_OF ? 0x31 : 0x30;
        const std::vector<uint8_t> wire = {tag, 2, tag, 0};
        EXPECT_EQ(TLV_OK, Read(wire, root));
        tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
        limits.base.max_depth = 1;
        EXPECT_EQ(TLV_ERR_LIMIT, Read(wire, root, nullptr, nullptr, &limits));
        struct State {
            const tlv_der_schema_component_t* element;
            size_t                            calls;
        };
        State state{&element, 0};
        auto  encode = [](const void* context, const tlv_der_schema_component_t* component, size_t,
                          uint8_t*, size_t, size_t* written, int* absent) -> tlv_result_t {
            auto* state = const_cast<State*>(static_cast<const State*>(context));
            *written = 0;
            *absent = component == state->element && state->calls++ != 0;
            return TLV_OK;
        };
        uint8_t                 arena[128]{}, output[16]{};
        tlv_der_schema_record_t records[4]{};
        size_t                  written = 999;
        EXPECT_EQ(TLV_OK,
                  tlv_der_schema_write(output, sizeof(output), &root, encode, &state, nullptr,
                                       arena, sizeof(arena), records, 4, &written, nullptr));
        ASSERT_EQ(wire.size(), written);
        EXPECT_EQ(0, std::memcmp(output, wire.data(), written));
        state.calls = 0;
        written = 999;
        EXPECT_EQ(TLV_ERR_LIMIT,
                  tlv_der_schema_write(output, sizeof(output), &root, encode, &state, &limits,
                                       arena, sizeof(arena), records, 4, &written, nullptr));
        EXPECT_EQ(999u, written);
    }
}

TEST(Unit_Tlv_DerSchema, TransparentCyclesAreRejectedEvenInsideProductiveCycles) {
    tlv_der_schema_type_t choice = {
        TLV_DER_SCHEMA_CHOICE, 0, nullptr, 1, nullptr, 0, 0, nullptr, 0};
    auto alternative = Required(choice);
    choice.components = &alternative;
    tlv_schema_diagnostic_t diagnostic{};
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&choice, &diagnostic));
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DEFINITION, diagnostic.detail.kind);
    EXPECT_FALSE(diagnostic.diagnostic.location.kind);
    // A consuming edge elsewhere in the graph must not hide this CHOICE self-loop.
    tlv_der_schema_component_t members[2] = {Required(choice), Required(choice)};
    tlv_der_schema_type_t      sequence = {
        TLV_DER_SCHEMA_SEQUENCE, 0, members, 2, nullptr, 0, 0, nullptr, 0};
    members[0] = Required(sequence);
    members[0].presence = TLV_DER_OPTIONAL;
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_check(&sequence, nullptr));
    // EXPLICIT consumes an identifier, allowing a finite branch to end recursion.
    tlv_der_schema_component_t alternatives[2] = {Required(choice), Required(kInteger)};
    alternatives[0].tagging = TLV_DER_TAG_EXPLICIT;
    alternatives[0].tag_class = TLV_ASN1_CONTEXT_SPECIFIC;
    alternatives[0].tag_number = 0;
    choice.components = alternatives;
    choice.component_count = 2;
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&choice, nullptr));
    EXPECT_EQ(TLV_OK, Read({0xa0, 3, 2, 1, 1}, choice));
    std::vector<uint8_t> deep = {2, 1, 1};
    for (size_t i = 0; i < 36; ++i) {
        deep.insert(deep.begin(), static_cast<uint8_t>(deep.size()));
        deep.insert(deep.begin(), 0xa0);
    }
    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    limits.base.max_depth = 40;
    EXPECT_EQ(TLV_OK, Read(deep, choice, nullptr, nullptr, &limits));
    limits.base.max_depth = 35;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(deep, choice, nullptr, nullptr, &limits));
    struct State {
        const tlv_der_schema_component_t* recursive;
        size_t                            wrappers;
    } state{&alternatives[0], 0};
    auto encode = [](const void* context, const tlv_der_schema_component_t* component, size_t,
                     uint8_t* data, size_t capacity, size_t* written, int* absent) -> tlv_result_t {
        auto* state = const_cast<State*>(static_cast<const State*>(context));
        *absent = component == state->recursive && state->wrappers++ == 36;
        *written = component->type->kind == TLV_DER_SCHEMA_UNIVERSAL ? 1 : 0;
        if (data && *written) {
            if (!capacity) return TLV_ERR_BUFFER_TOO_SHORT;
            data[0] = 1;
        }
        return TLV_OK;
    };
    uint8_t arena[4096]{}, output[128]{};
    size_t  written = 999;
    limits.base.max_depth = 40;
    ASSERT_EQ(TLV_OK, tlv_der_schema_write(output, sizeof(output), &choice, encode, &state, &limits,
                                           arena, sizeof(arena), nullptr, 0, &written, nullptr));
    ASSERT_EQ(deep.size(), written);
    EXPECT_EQ(0, std::memcmp(output, deep.data(), written));
    state.wrappers = 0;
    written = 999;
    limits.base.max_depth = 35;
    EXPECT_EQ(TLV_ERR_LIMIT,
              tlv_der_schema_write(output, sizeof(output), &choice, encode, &state, &limits, arena,
                                   sizeof(arena), nullptr, 0, &written, nullptr));
    EXPECT_EQ(999u, written);
}

TEST(Unit_Tlv_DerSchema, RecursiveExplicitContainersKeepWireDepthAcrossFrames) {
    tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE_OF, 0, nullptr, 0, nullptr, 0, SIZE_MAX, nullptr, 0};
    auto element = Required(root);
    element.tagging = TLV_DER_TAG_EXPLICIT;
    element.tag_class = TLV_ASN1_CONTEXT_SPECIFIC;
    root.element = &element;
    const std::vector<uint8_t> wire = {0x30, 8, 0xa0, 6, 0x30, 4, 0xa0, 2, 0x30, 0};
    tlv_der_schema_limits_t    limits = tlv_der_schema_default_limits;
    limits.base.max_depth = 5;
    EXPECT_EQ(TLV_OK, Read(wire, root, nullptr, nullptr, &limits));
    limits.base.max_depth = 4;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(wire, root, nullptr, nullptr, &limits));
}

TEST(Unit_Tlv_DerSchema, DefinitionCapacityAndTransparentDepthAreSeparateBounds) {
    tlv_der_schema_type_t      types[TLV_DER_SCHEMA_MAX_TYPES + 1]{};
    tlv_der_schema_component_t edges[TLV_DER_SCHEMA_MAX_TYPES]{};
    types[TLV_DER_SCHEMA_MAX_TYPES] = kInteger;
    for (size_t i = 0; i < TLV_DER_SCHEMA_MAX_TYPES; ++i) {
        edges[i] = Required(types[i + 1]);
        types[i] = {TLV_DER_SCHEMA_SEQUENCE, 0, &edges[i], 1, nullptr, 0, 0, nullptr, 0};
    }
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_der_schema_check(types, nullptr));
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(types + 1, nullptr));
    for (size_t i = 0; i <= TLV_DER_SCHEMA_MAX_TYPE_DEPTH; ++i)
        types[i].kind = TLV_DER_SCHEMA_CHOICE;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_der_schema_check(types, nullptr));
    // Restrict the reachable graph so this rejection comes only from CHOICE depth.
    types[TLV_DER_SCHEMA_MAX_TYPE_DEPTH + 1] = kInteger;
    EXPECT_EQ(TLV_ERR_UNSUPPORTED, tlv_der_schema_check(types, nullptr));
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(types + 1, nullptr));
}
