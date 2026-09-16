#include "common.h"
#include "tlv/profiles/dol.h"

static tlv_result_t visit_count(const tlv_dol_entry_t* entry, size_t index, void* context) {
    (void)index;
    FUZZ_CHECK(entry->tag.size > 0 && entry->tag.size <= TLV_TAG_CAPACITY);
    FUZZ_CHECK(entry->requested_length <= 255);
    ++*(size_t*)context;
    return TLV_OK;
}

static void check_dol_read(const uint8_t* data, size_t size, const tlv_dol_limits_t* limits) {
    size_t       count = 0, error = SIZE_MAX;
    tlv_result_t rc = tlv_dol_read(data, size, limits, visit_count, &count, &error);
    if (rc == TLV_OK)
        FUZZ_CHECK(error == SIZE_MAX);
    else
        FUZZ_CHECK(error <= size);
}

/* Every third entry (by wire position) is reported unavailable; the rest
 * report a deterministic natural length derived from the tag's own first
 * byte (independent of the requested length, so shorter-than-requested,
 * equal, and longer-than-requested are all reachable) and alternate
 * padding/truncation styles. Produced bytes are the value's own byte
 * offsets, so a truncated/padded segment's content is easy to reason about. */
static tlv_result_t resolve(const tlv_dol_entry_t* entry, size_t index, size_t skip, uint8_t* data,
                            size_t capacity, size_t* available_length, tlv_dol_format_t* format,
                            int* absent, void* context) {
    size_t natural = (size_t)entry->tag.data[0] % (TLV_DOL_MAX_VALUE_LENGTH + 1);
    (void)context;
    if (index % 3 == 0) {
        *absent = 1;
        return TLV_OK;
    }
    *absent = 0;
    *format = (index % 2) ? TLV_DOL_FORMAT_NUMERIC : TLV_DOL_FORMAT_BINARY;
    if (!data) {
        *available_length = natural;
        return TLV_OK;
    }
    FUZZ_CHECK(capacity <= natural && skip <= natural - capacity);
    {
        size_t i;
        for (i = 0; i < capacity; ++i) data[i] = (uint8_t)(skip + i);
    }
    return TLV_OK;
}

static void check_dol_write(const uint8_t* data, size_t size, const tlv_dol_limits_t* limits) {
    static uint8_t buffer[65536];
    size_t         written = SIZE_MAX, error = SIZE_MAX;
    size_t         produced = SIZE_MAX, error2 = SIZE_MAX;
    tlv_result_t   rc, rc2;

    rc = tlv_dol_write(data, size, NULL, 0, limits, NULL, NULL, &written, &error);
    if (rc == TLV_OK)
        FUZZ_CHECK(error == SIZE_MAX);
    else
        FUZZ_CHECK(error <= size);

    rc2 = tlv_dol_write(data, size, buffer, sizeof(buffer), limits, resolve, NULL, &produced,
                        &error2);
    if (rc2 == TLV_OK) {
        /* tlv_dol_write's output length depends only on the DOL itself. */
        FUZZ_CHECK(rc == TLV_OK);
        FUZZ_CHECK(produced == written);
        FUZZ_CHECK(produced <= sizeof(buffer));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    tlv_dol_limits_t limits = tlv_dol_default_limits;
    check_dol_read(data, size, NULL);
    check_dol_read(data, size, &limits);
    check_dol_write(data, size, NULL);
    check_dol_write(data, size, &limits);
    /* Vary each limit independently, matching fuzz_der_schema.c's approach,
     * so one early rejection cannot mask the other. */
    limits.max_entries = size ? data[0] : 0;
    check_dol_read(data, size, &limits);
    check_dol_write(data, size, &limits);
    limits.max_entries = tlv_dol_default_limits.max_entries;
    limits.max_value_length = size > 1 ? data[1] % (TLV_DOL_MAX_VALUE_LENGTH + 1) : 0;
    check_dol_read(data, size, &limits);
    check_dol_write(data, size, &limits);
    return 0;
}
