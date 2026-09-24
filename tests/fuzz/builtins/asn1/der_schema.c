#include "common.h"
#include "tlv/builtins/asn1/der_schema.h"

/* A fixed representative schema exercising every construct issue #63 added:
 * IMPLICIT and EXPLICIT tagging, a DEFAULT component, SET, SET OF and
 * CHOICE, all as optional components of one root SEQUENCE so arbitrary
 * fuzzer bytes can reach any of them from a single top-level element. */
static const tlv_der_schema_type_t kInteger = {
    TLV_DER_SCHEMA_UNIVERSAL, 2, NULL, 0, NULL, 0, 0, NULL, 0};
static const tlv_der_schema_type_t kOctetString = {
    TLV_DER_SCHEMA_UNIVERSAL, 4, NULL, 0, NULL, 0, 0, NULL, 0};
static const tlv_der_schema_type_t kBoolean = {
    TLV_DER_SCHEMA_UNIVERSAL, 1, NULL, 0, NULL, 0, 0, NULL, 0};

static const tlv_der_schema_component_t kSetMembers[] = {
    {&kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
    {&kOctetString, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
};
static const tlv_der_schema_type_t kSet = {
    TLV_DER_SCHEMA_SET, 0, kSetMembers, 2, NULL, 0, 0, NULL, 0};

static const tlv_der_schema_component_t kSetOfElement = {
    &kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0};
static const tlv_der_schema_type_t kSetOf = {
    TLV_DER_SCHEMA_SET_OF, 0, NULL, 0, &kSetOfElement, 0, SIZE_MAX, NULL, 0};

static const tlv_der_schema_component_t kSequenceOfElement = {
    &kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0};
static const tlv_der_schema_type_t kSequenceOf = {
    TLV_DER_SCHEMA_SEQUENCE_OF, 0, NULL, 0, &kSequenceOfElement, 0, SIZE_MAX, NULL, 0};

static const tlv_der_schema_component_t kChoiceAlts[] = {
    {&kInteger, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
    {&kOctetString, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_REQUIRED, NULL, 0},
};
static const tlv_der_schema_type_t kChoice = {
    TLV_DER_SCHEMA_CHOICE, 0, kChoiceAlts, 2, NULL, 0, 0, NULL, 0};

static const uint8_t kDefaultBoolean[] = {0x01, 0x01, 0x00};

static const tlv_der_schema_component_t kRootComponents[] = {
    {&kInteger, TLV_DER_TAG_IMPLICIT, TLV_ASN1_CONTEXT_SPECIFIC, 0, TLV_DER_OPTIONAL, NULL, 0},
    {&kOctetString, TLV_DER_TAG_EXPLICIT, TLV_ASN1_CONTEXT_SPECIFIC, 1, TLV_DER_OPTIONAL, NULL, 0},
    {&kBoolean, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_DEFAULT, kDefaultBoolean,
     sizeof(kDefaultBoolean)},
    {&kSet, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, NULL, 0},
    {&kSetOf, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, NULL, 0},
    {&kSequenceOf, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, NULL, 0},
    {&kChoice, TLV_DER_TAG_NONE, TLV_ASN1_UNIVERSAL, 0, TLV_DER_OPTIONAL, NULL, 0},
};
static const tlv_der_schema_type_t kRoot = {
    TLV_DER_SCHEMA_SEQUENCE, 0, kRootComponents, 7, NULL, 0, 0, NULL, 0};

/* Same components as kRoot, but with the extension marker set, so arbitrary
 * fuzzer bytes left over after the declared (all-optional) components also
 * exercise the "accept and skip an opaque trailing extension" path. */
static const tlv_der_schema_type_t kExtensibleRoot = {
    TLV_DER_SCHEMA_SEQUENCE, 0, kRootComponents, 7, NULL, 0, 0, NULL, 1};

static void check_der_schema(const tlv_der_schema_type_t* root, const uint8_t* data, size_t size,
                             const tlv_der_schema_limits_t* limits) {
    const tlv_der_schema_limits_t* actual = limits ? limits : &tlv_der_schema_default_limits;
    tlv_view_t                     view = fuzz_sentinel(data), before = view;
    size_t                         consumed = SIZE_MAX, error = SIZE_MAX;
    tlv_result_t rc = tlv_der_schema_read(data, size, root, limits, &view, &consumed, &error);
    if (rc == TLV_OK) {
        FUZZ_CHECK(consumed > 0 && consumed <= size);
        fuzz_view_bounds(&view, data, consumed);
        FUZZ_CHECK(size <= actual->base.max_input_size);
        FUZZ_CHECK(view.value.length <= actual->base.max_value_size);
        FUZZ_CHECK(error == SIZE_MAX);
    } else {
        fuzz_unchanged(&view, &before);
        FUZZ_CHECK(consumed == SIZE_MAX && error <= size);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tlv_der_schema_limits_t limits = tlv_der_schema_default_limits;
    FUZZ_CHECK(tlv_der_schema_check(&kRoot, NULL) == TLV_OK);
    FUZZ_CHECK(tlv_der_schema_check(&kExtensibleRoot, NULL) == TLV_OK);
    check_der_schema(&kRoot, data, size, NULL);
    check_der_schema(&kExtensibleRoot, data, size, NULL);
    check_der_schema(&kRoot, data, size, &limits);
    /* Vary each limit independently, matching fuzz_der.c's approach, so one
     * early rejection cannot mask the others. */
    limits.base.max_depth = size ? data[0] % (TLV_DER_MAX_DEPTH + 2) : 0;
    check_der_schema(&kRoot, data, size, &limits);
    limits.base.max_depth = tlv_der_schema_default_limits.base.max_depth;
    limits.base.max_elements = size > 1 ? data[1] : 0;
    check_der_schema(&kRoot, data, size, &limits);
    limits.base.max_elements = tlv_der_schema_default_limits.base.max_elements;
    limits.base.max_value_size = size > 2 ? data[2] : 0;
    check_der_schema(&kRoot, data, size, &limits);
    limits.base.max_value_size = tlv_der_schema_default_limits.base.max_value_size;
    limits.base.max_input_size = size > 3 ? data[3] : 0;
    check_der_schema(&kRoot, data, size, &limits);
    return 0;
}
