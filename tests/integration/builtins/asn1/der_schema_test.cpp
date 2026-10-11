// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/der_validation.h"
#include "tlv/builtins/asn1/der_schema.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

namespace {

const tlv_der_schema_type_t kInteger = {
    TLV_DER_SCHEMA_UNIVERSAL, 2, nullptr, 0, nullptr, 0, 0, nullptr, 0};
const tlv_der_schema_type_t kOctetString = {
    TLV_DER_SCHEMA_UNIVERSAL, 4, nullptr, 0, nullptr, 0, 0, nullptr, 0};

tlv_der_schema_component_t Required(const tlv_der_schema_type_t& type) {
    return {&type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, nullptr, 0};
}

} // namespace

/* A SET's components must be encoded in ascending tag order to be canonical
 * DER; generic (schema-unaware) DER-TLV processing has no notion of "SET"
 * versus any other constructed value and accepts either order, so the same
 * misordered bytes are valid to tlv_der_visit_strict but rejected by the
 * schema-aware reader -- the exact distinction issue #63 introduces. */
TEST(Integration_Tlv_DerSchema, SchemaRejectsNonCanonicalSetOrderGenericDerAccepts) {
    tlv_der_schema_component_t  components[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};

    /* SET { OCTET STRING, INTEGER } encoded in declaration (non-canonical)
     * order: 31 06 04 01 01 02 01 05. */
    const std::vector<uint8_t> misordered = {0x31, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x05};

    tlv_schema_diagnostic_t schema_offset{};
    tlv_element_t           schema_element{};
    size_t                  schema_consumed = 0;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_schema_read(misordered.data(), misordered.size(), &set_type, nullptr,
                                  &schema_element, &schema_consumed, &schema_offset));

    tlv_diagnostic_t generic_offset = {};
    EXPECT_EQ(TLV_OK, tlv_der_visit_strict(misordered.data(), misordered.size(), nullptr, nullptr,
                                           nullptr, &generic_offset));
}

struct ScriptEntry {
    const tlv_der_schema_component_t* component;
    size_t                            index;
    bool                              present;
    std::vector<uint8_t>              bytes;
};

static tlv_result_t ScriptEncode(const void* context, const tlv_der_schema_component_t* component,
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

/* A composite structure exercising EXPLICIT tagging with a DEFAULT, a SET,
 * and a CHOICE together, round-tripped through the schema-aware writer and
 * reader and cross-checked against plain generic strict DER. */
TEST(Integration_Tlv_DerSchema, CompositeStructureRoundTrips) {
    static const uint8_t        kZeroDefault[] = {0x02, 0x01, 0x00};
    tlv_der_schema_component_t  choice_alts[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t choice_name = {
        TLV_DER_SCHEMA_CHOICE, 0, choice_alts, 2, nullptr, 0, 0, nullptr, 0};

    tlv_der_schema_component_t  set_members[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, set_members, 2, nullptr, 0, 0, nullptr, 0};

    tlv_der_schema_component_t root_components[3] = {
        {&kInteger, TLV_DER_TAG_EXPLICIT, TLV_ASN1_CONTEXT_SPECIFIC, 0, TLV_DER_DEFAULT,
         kZeroDefault, sizeof(kZeroDefault)},
        {&set_type, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, nullptr, 0},
        {&choice_name, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, nullptr, 0},
    };
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, root_components, 3, nullptr, 0, 0, nullptr, 0};
    ASSERT_EQ(TLV_OK, tlv_der_schema_check(&root, nullptr));

    std::vector<ScriptEntry> script = {
        {&root_components[0], 0, true, {0x07}},
        {&set_members[0], 0, true, {0x05}},
        {&set_members[1], 0, true, {0x01}},
        {&choice_alts[1], 0, true, {0xAB}},
    };

    std::vector<uint8_t>                 arena(4096);
    std::vector<tlv_der_schema_record_t> records(64);
    std::vector<uint8_t>                 output(256);
    size_t                               written = 0;
    ASSERT_EQ(TLV_OK, tlv_der_schema_write(output.data(), output.size(), &root, ScriptEncode,
                                           &script, nullptr, arena.data(), arena.size(),
                                           records.data(), records.size(), &written, nullptr));
    output.resize(written);

    tlv_element_t           element{};
    size_t                  consumed = 0;
    tlv_schema_diagnostic_t error_offset{};
    ASSERT_EQ(TLV_OK, tlv_der_schema_read(output.data(), output.size(), &root, nullptr, &element,
                                          &consumed, &error_offset));
    EXPECT_EQ(output.size(), consumed);

    /* Schema output must also be plain, generic, strict-canonical DER. */
    tlv_element_t generic_element{};
    size_t        generic_consumed = 0;
    EXPECT_EQ(TLV_OK, tlv_der_read_strict(output.data(), output.size(), nullptr, &generic_element,
                                          &generic_consumed, nullptr));
    EXPECT_EQ(output.size(), generic_consumed);
}

/* A prepared handle skips only the definition check: reads, writes, their
 * diagnostics and limits
 * match the plain API for the same schema. */
TEST(Integration_Tlv_DerSchema, CheckedHandleMatchesPlainReadAndWrite) {
    tlv_der_schema_component_t  members[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, members, 2, nullptr, 0, 0, nullptr, 0};
    tlv_der_schema_checked_t checked;
    ASSERT_EQ(TLV_OK, tlv_der_schema_prepare(&checked, &root, nullptr));
    EXPECT_EQ(&root, checked.root);

    const std::vector<std::vector<uint8_t>> inputs = {
        {0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAB}, // valid
        {0x30, 0x03, 0x02, 0x01, 0x05},                   // missing OCTET STRING
        {0x30, 0x03, 0x04, 0x01, 0xAB},                   // wrong component
        {0x30, 0x06, 0x02, 0x01},                         // truncated
        {},                                               // absent root
    };
    for (size_t i = 0; i < inputs.size(); ++i) {
        SCOPED_TRACE(i);
        const auto&             wire = inputs[i];
        tlv_element_t           plain_element{}, checked_element{};
        size_t                  plain_consumed = 0, checked_consumed = 0;
        tlv_schema_diagnostic_t plain, prepared;
        const tlv_result_t expected = tlv_der_schema_read(wire.data(), wire.size(), &root, nullptr,
                                                          &plain_element, &plain_consumed, &plain);
        EXPECT_EQ(expected,
                  tlv_der_schema_read_checked(&checked, wire.data(), wire.size(), nullptr,
                                              &checked_element, &checked_consumed, &prepared));
        EXPECT_EQ(plain_consumed, checked_consumed);
        EXPECT_EQ(plain.diagnostic.code, prepared.diagnostic.code);
        EXPECT_EQ(plain.diagnostic.location.domain, prepared.diagnostic.location.domain);
        EXPECT_EQ(plain.diagnostic.location.kind, prepared.diagnostic.location.kind);
        EXPECT_EQ(plain.diagnostic.location.begin, prepared.diagnostic.location.begin);
        EXPECT_EQ(plain.detail.kind, prepared.detail.kind);
    }

    std::vector<ScriptEntry>             complete = {{&members[0], 0, true, {0x05}},
                                                     {&members[1], 0, true, {0xAB}}};
    std::vector<ScriptEntry>             incomplete = {{&members[0], 0, true, {0x05}}};
    std::vector<uint8_t>                 arena(256);
    std::vector<tlv_der_schema_record_t> records(4);
    for (auto* script : {&complete, &incomplete}) {
        uint8_t                 plain_output[32] = {0}, checked_output[32] = {0};
        size_t                  plain_written = 0, checked_written = 0;
        tlv_schema_diagnostic_t plain, prepared;
        const tlv_result_t      expected = tlv_der_schema_write(
            plain_output, sizeof plain_output, &root, ScriptEncode, script, nullptr, arena.data(),
            arena.size(), records.data(), records.size(), &plain_written, &plain);
        EXPECT_EQ(expected, tlv_der_schema_write_checked(
                                checked_output, sizeof checked_output, &checked, ScriptEncode,
                                script, nullptr, arena.data(), arena.size(), records.data(),
                                records.size(), &checked_written, &prepared));
        EXPECT_EQ(plain_written, checked_written);
        EXPECT_EQ(0, std::memcmp(plain_output, checked_output, sizeof plain_output));
        EXPECT_EQ(plain.diagnostic.code, prepared.diagnostic.code);
        EXPECT_EQ(plain.diagnostic.location.domain, prepared.diagnostic.location.domain);
        EXPECT_EQ(plain.diagnostic.location.kind, prepared.diagnostic.location.kind);
        EXPECT_EQ(plain.diagnostic.location.begin, prepared.diagnostic.location.begin);
        EXPECT_EQ(plain.detail.kind, prepared.detail.kind);
    }
}

TEST(Integration_Tlv_DerSchema, CheckedHandleKeepsLimitsAndRejectsInvalidUse) {
    tlv_der_schema_component_t  members[1] = {Required(kInteger)};
    const tlv_der_schema_type_t root = {
        TLV_DER_SCHEMA_SEQUENCE, 0, members, 1, nullptr, 0, 0, nullptr, 0};
    /* A CHOICE alternative must be REQUIRED, so this definition is invalid. */
    tlv_der_schema_component_t alternatives[1] = {
        {&kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, nullptr, 0}};
    const tlv_der_schema_type_t invalid = {
        TLV_DER_SCHEMA_CHOICE, 0, alternatives, 1, nullptr, 0, 0, nullptr, 0};
    const uint8_t            wire[] = {0x30, 0x03, 0x02, 0x01, 0x05};
    tlv_der_schema_checked_t checked;
    tlv_schema_diagnostic_t  diagnostic;
    tlv_element_t            element{};
    size_t                   consumed = 0;
    ASSERT_EQ(TLV_OK, tlv_der_schema_prepare(&checked, &root, nullptr));

    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    limits.base.max_input_size = sizeof wire - 1;
    EXPECT_EQ(TLV_ERR_LIMIT, tlv_der_schema_read_checked(&checked, wire, sizeof wire, &limits,
                                                         &element, &consumed, nullptr));
    ASSERT_EQ(TLV_OK, tlv_der_schema_read_checked(&checked, wire, sizeof wire, nullptr, &element,
                                                  &consumed, nullptr));
    EXPECT_EQ(sizeof wire, consumed);

    /* A failed preparation never leaves the handle on the previous definition. */
    EXPECT_EQ(TLV_ERR_INVALID_SCHEMA, tlv_der_schema_prepare(&checked, &invalid, &diagnostic));
    EXPECT_EQ(nullptr, checked.root);
    EXPECT_EQ(TLV_SCHEMA_ISSUE_DEFINITION, diagnostic.detail.kind);
    EXPECT_EQ(TLV_ERR_INVALID_STATE,
              tlv_der_schema_read_checked(&checked, wire, sizeof wire, nullptr, &element, &consumed,
                                          &diagnostic));
    EXPECT_EQ(TLV_ERR_INVALID_STATE, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_LOCATION_UNKNOWN, diagnostic.diagnostic.location.kind);

    std::vector<ScriptEntry> script = {{&members[0], 0, true, {0x05}}};
    uint8_t                  scratch_bytes[64];
    size_t                   written = 7;
    EXPECT_EQ(TLV_ERR_INVALID_STATE,
              tlv_der_schema_write_checked(nullptr, 0, &checked, ScriptEncode, &script, nullptr,
                                           scratch_bytes, sizeof scratch_bytes, nullptr, 0,
                                           &written, nullptr));
    EXPECT_EQ(7u, written);

    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_prepare(nullptr, &root, &diagnostic));
    EXPECT_EQ(TLV_ERR_NULL_ARG, diagnostic.diagnostic.code);
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_prepare(&checked, nullptr, nullptr));
    ASSERT_EQ(TLV_OK, tlv_der_schema_prepare(&checked, &root, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_read_checked(nullptr, wire, sizeof wire, nullptr,
                                                            &element, &consumed, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_read_checked(&checked, wire, sizeof wire, nullptr,
                                                            nullptr, &consumed, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG,
              tlv_der_schema_write_checked(nullptr, 0, nullptr, ScriptEncode, &script, nullptr,
                                           scratch_bytes, sizeof scratch_bytes, nullptr, 0,
                                           &written, nullptr));
    EXPECT_EQ(TLV_ERR_NULL_ARG, tlv_der_schema_write_checked(
                                    nullptr, 0, &checked, nullptr, &script, nullptr, scratch_bytes,
                                    sizeof scratch_bytes, nullptr, 0, &written, nullptr));
    ASSERT_EQ(TLV_OK, tlv_der_schema_write_checked(nullptr, 0, &checked, ScriptEncode, &script,
                                                   nullptr, scratch_bytes, sizeof scratch_bytes,
                                                   nullptr, 0, &written, nullptr));
    EXPECT_EQ(sizeof wire, written);
}
