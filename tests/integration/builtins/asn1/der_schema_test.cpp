#include "tlv/builtins/asn1/der_profile.h"
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
 * misordered bytes are valid to tlv_der_walk_strict but rejected by the
 * schema-aware reader -- the exact distinction issue #63 introduces. */
TEST(Integration_Tlv_DerSchema, SchemaRejectsNonCanonicalSetOrderGenericDerAccepts) {
    tlv_der_schema_component_t  components[2] = {Required(kInteger), Required(kOctetString)};
    const tlv_der_schema_type_t set_type = {
        TLV_DER_SCHEMA_SET, 0, components, 2, nullptr, 0, 0, nullptr, 0};

    /* SET { OCTET STRING, INTEGER } encoded in declaration (non-canonical)
     * order: 31 06 04 01 01 02 01 05. */
    const std::vector<uint8_t> misordered = {0x31, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x05};

    size_t     schema_offset = 0;
    tlv_view_t schema_view{};
    size_t     schema_consumed = 0;
    EXPECT_EQ(TLV_ERR_INVALID_VALUE,
              tlv_der_schema_read(misordered.data(), misordered.size(), &set_type, nullptr,
                                  &schema_view, &schema_consumed, &schema_offset));

    size_t generic_offset = 0;
    EXPECT_EQ(TLV_OK, tlv_der_walk_strict(misordered.data(), misordered.size(), nullptr, nullptr,
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

    tlv_view_t view{};
    size_t     consumed = 0, error_offset = 0;
    ASSERT_EQ(TLV_OK, tlv_der_schema_read(output.data(), output.size(), &root, nullptr, &view,
                                          &consumed, &error_offset));
    EXPECT_EQ(output.size(), consumed);

    /* Schema output must also be plain, generic, strict-canonical DER. */
    tlv_view_t generic_view{};
    size_t     generic_consumed = 0;
    EXPECT_EQ(TLV_OK, tlv_der_read_strict(output.data(), output.size(), nullptr, &generic_view,
                                          &generic_consumed, nullptr));
    EXPECT_EQ(output.size(), generic_consumed);
}
