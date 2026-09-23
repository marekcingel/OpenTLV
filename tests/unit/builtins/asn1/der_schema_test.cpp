#include "tlv/builtins/asn1/der_schema.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {

/* Universal tag numbers used throughout: BOOLEAN=1, INTEGER=2,
 * OCTET STRING=4, all primitive; SEQUENCE=16, SET=17, both constructed. */
const tlv_der_schema_type_t kBoolean = {TLV_DER_SCHEMA_UNIVERSAL, 1, nullptr, 0, nullptr, 0, 0};
const tlv_der_schema_type_t kInteger = {TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0};
const tlv_der_schema_type_t kOctetString = {TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0};

tlv_der_schema_component_t Required(const tlv_der_schema_type_t& type) {
    return {&type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, nullptr, 0};
}

tlv_result_t Read(const std::vector<uint8_t>& data, const tlv_der_schema_type_t& root,
                  size_t* consumed = nullptr, size_t* error_offset = nullptr,
                  const tlv_der_schema_limits_t* limits = nullptr) {
    tlv_view_t   view{};
    size_t       local_consumed = 0, local_offset = 0;
    tlv_result_t rc = tlv_der_schema_read(data.data(), data.size(), &root, limits, &view,
                                          consumed ? consumed : &local_consumed,
                                          error_offset ? error_offset : &local_offset);
    return rc;
}

} // namespace

TEST(Unit_Tlv_DerSchema, DistinguishesSetFromSetOf) {
    /* Ascending-by-content INTEGER(1) then INTEGER(2), wrapped in the root
     * type's own tag (SET and SET OF share universal tag 17): valid SET OF
     * order, but never a valid SET (a SET requires components with distinct
     * tags; two untagged INTEGER components share a tag). */
    const std::vector<uint8_t> data = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};

    tlv_der_schema_component_t  element = Required(kInteger);
    const tlv_der_schema_type_t set_of = {
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX};
    size_t consumed = 0;
    EXPECT_EQ(TLV_OK, Read(data, set_of, &consumed));
    EXPECT_EQ(data.size(), consumed);

    tlv_der_schema_component_t  bad_components[2] = {Required(kInteger), Required(kInteger)};
    const tlv_der_schema_type_t bad_set = {TLV_DER_SCHEMA_SET, 0, bad_components, 2, nullptr, 0, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(data, bad_set));
}

TEST(Unit_Tlv_DerSchema, SetRequiresCanonicalTagOrder) {
    tlv_der_schema_component_t  components[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t set_type = {TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0};
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
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX};

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
    const tlv_der_schema_type_t set_of = {TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 2, 2};
    EXPECT_EQ(TLV_OK,
              Read(std::vector<uint8_t>{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}, set_of));
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x31, 0x03, 0x02, 0x01, 0x01}, set_of));
    EXPECT_EQ(TLV_ERR_SCHEMA, Read(std::vector<uint8_t>{0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01,
                                                        0x02, 0x02, 0x01, 0x03},
                                   set_of));
}

TEST(Unit_Tlv_DerSchema, SequenceRequiredOptionalDefault) {
    static const uint8_t       kFalseDefault[] = {0x01, 0x01, 0x00};
    tlv_der_schema_component_t components[3] = {
        Required(kInteger),
        {&kOctetString, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, nullptr, 0},
        {&kBoolean, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_DEFAULT, kFalseDefault,
         sizeof(kFalseDefault)},
    };
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, components, 3, nullptr, 0, 0};
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
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0};
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
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0};
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
    const tlv_der_schema_type_t choice = {TLV_DER_SCHEMA_CHOICE, 0, alternatives, 2, nullptr, 0, 0};
    EXPECT_EQ(TLV_OK, tlv_der_schema_check(&choice, nullptr));

    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x02, 0x01, 0x05}, choice));
    EXPECT_EQ(TLV_OK, Read(std::vector<uint8_t>{0x04, 0x01, 0x01}, choice));
    EXPECT_EQ(TLV_ERR_INVALID_TAG, Read(std::vector<uint8_t>{0x01, 0x01, 0xFF}, choice));
}

TEST(Unit_Tlv_DerSchema, DepthLimitAppliesToPushingAFrame) {
    tlv_der_schema_component_t  component = Required(kInteger);
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0};
    tlv_der_schema_limits_t     limits = tlv_der_schema_default_limits;
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
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, &component, 1, nullptr, 0, 0};
    tlv_der_schema_limits_t     limits = tlv_der_schema_default_limits;
    limits.base.max_elements = 1;
    EXPECT_EQ(TLV_ERR_LIMIT, Read(std::vector<uint8_t>{0x30, 0x03, 0x02, 0x01, 0x05}, seq, nullptr,
                                  nullptr, &limits));
}

TEST(Unit_Tlv_DerSchema, SchemaCheckCatchesAuthoringErrors) {
    tlv_der_schema_component_t  duplicate[2] = {Required(kInteger), Required(kInteger)};
    const tlv_der_schema_type_t bad_set = {TLV_DER_SCHEMA_SET, 0, duplicate, 2, nullptr, 0, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_check(&bad_set, nullptr));

    tlv_der_schema_component_t optional_alt[1] = {
        {&kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, nullptr, 0}};
    const tlv_der_schema_type_t bad_choice = {
        TLV_DER_SCHEMA_CHOICE, 0, optional_alt, 1, nullptr, 0, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_check(&bad_choice, nullptr));

    const tlv_der_schema_type_t choice_type = {TLV_DER_SCHEMA_CHOICE, 0, nullptr, 0, nullptr, 0, 0};
    tlv_der_schema_component_t  implicit_choice = {&choice_type,
                                                   TLV_DER_TAG_IMPLICIT,
                                                   TLV_ASN1_CONTEXT_SPECIFIC,
                                                   0,
                                                   TLV_DER_REQUIRED,
                                                   nullptr,
                                                   0};
    const tlv_der_schema_type_t wrapper = {
        TLV_DER_SCHEMA_SEQUENCE, 0, &implicit_choice, 1, nullptr, 0, 0};
    EXPECT_EQ(TLV_ERR_SCHEMA, tlv_der_schema_check(&wrapper, nullptr));

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
            std::memcpy(data, entry.bytes.data(), entry.bytes.size());
        }
        *written = entry.bytes.size();
        return TLV_OK;
    }
    /* An unscripted container component (SEQUENCE/SET/SET OF/CHOICE, or the
     * synthetic root wrapper) is reported present with no content of its
     * own, since its bytes come from its children instead. An unscripted
     * leaf (UNIVERSAL/ANY) -- including a SET OF element index beyond the
     * scripted ones -- is reported absent. */
    switch (component->type->kind) {
        case TLV_DER_SCHEMA_SEQUENCE:
        case TLV_DER_SCHEMA_SET:
        case TLV_DER_SCHEMA_SET_OF:
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
    size_t       written = 0;
    tlv_result_t rc = tlv_der_schema_write(output->data(), output->size(), &root, ScriptEncode,
                                           &script, nullptr, arena.data(), arena.size(),
                                           records.data(), records.size(), &written, error_offset);
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
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0};

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
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, components, 2, nullptr, 0, 0};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK,
              Write(seq, {{&components[0], 0, true, {0x05}}, {&components[1], 0, true, {0xFF}}},
                    &output));
    const std::vector<uint8_t> expected = {0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteSetOrdersComponentsByTag) {
    tlv_der_schema_component_t  components[2] = {Required(kOctetString), Required(kInteger)};
    const tlv_der_schema_type_t set_type = {TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0};

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
        TLV_DER_SCHEMA_SET_OF, 0, nullptr, 0, &element, 0, SIZE_MAX};

    std::vector<uint8_t> output;
    ASSERT_EQ(TLV_OK,
              Write(set_of, {{&element, 0, true, {0x02}}, {&element, 1, true, {0x01}}}, &output));
    const std::vector<uint8_t> expected = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02};
    EXPECT_EQ(expected, output);
}

TEST(Unit_Tlv_DerSchema, WriteMissingRequiredFails) {
    tlv_der_schema_component_t  components[1] = {Required(kInteger)};
    const tlv_der_schema_type_t seq = {TLV_DER_SCHEMA_SEQUENCE, 0, components, 1, nullptr, 0, 0};
    std::vector<uint8_t>        output;
    EXPECT_EQ(TLV_ERR_SCHEMA, Write(seq, {}, &output));
}

TEST(Unit_Tlv_DerSchema, WriteRoundTripsThroughRead) {
    tlv_der_schema_component_t  components[2] = {Required(kOctetString), Required(kInteger)};
    const tlv_der_schema_type_t set_type = {TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0};
    std::vector<uint8_t>        output;
    ASSERT_EQ(TLV_OK, Write(set_type,
                            {{&components[0], 0, true, {0x01}}, {&components[1], 0, true, {0x05}}},
                            &output));
    size_t consumed = 0;
    EXPECT_EQ(TLV_OK, Read(output, set_type, &consumed));
    EXPECT_EQ(output.size(), consumed);
}
