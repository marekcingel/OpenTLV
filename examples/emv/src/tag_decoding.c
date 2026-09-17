/*
 * Practical EMV workflow: parse a TLV record, look up each tag in the Book 3
 * dictionary, validate its value length, and decode the value into a C
 * representation -- while handling unknown tags and invalid lengths without
 * aborting. All storage belongs to the caller; there is no heap allocation.
 *
 * The fields below are gathered from several real EMV responses (a Read
 * Record, GPO outcome data, and account metadata) into a single READ RECORD
 * response template purely to exercise one decoded value per TLV_EMV_VALUE_*
 * kind in one place; it is not a literal capture of any single response.
 */
#include "tlv/formats/asn1/ber.h"
#include "tlv/length.h"
#include "tlv/profiles/emv.h"
#include "tlv/reader/reader.h"
#include "tlv/reader/walker.h"
#include "tlv/writer/writer.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define CHECK(call)                                                                                \
    do {                                                                                           \
        tlv_result_t rc_ = (call);                                                                 \
        if (rc_ != TLV_OK) {                                                                       \
            fprintf(stderr, "%s: %s\n", #call, tlv_strerror(rc_));                                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
#define CHECK_CODEC(call)                                                                          \
    do {                                                                                           \
        tlv_codec_result_t rc_ = (call);                                                           \
        if (rc_ != TLV_CODEC_OK) {                                                                 \
            fprintf(stderr, "%s: %s\n", #call, tlv_codec_strerror(rc_));                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
#define EXPECT(cond, message)                                                                      \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "assertion failed: %s\n", (message));                                  \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static void print_tag(const tlv_tag_t* tag) {
    size_t i;
    for (i = 0; i < tag->size; ++i) printf("%02X", (unsigned)tag->data[i]);
}

/* Encodes `value` through its semantic codec into caller-owned `scratch`. */
static int encode_child(const tlv_codec_t* codec, const void* value, size_t value_size,
                        uint8_t* scratch, size_t scratch_capacity, size_t* size) {
    CHECK_CODEC(tlv_codec_encode(codec, value, value_size, scratch, scratch_capacity, size));
    return 0;
}

/* Assembles the record's children as a sequence of BER TLVs, mixing values
 * encoded through their EMV codec with two deliberately invalid inputs (a
 * wrong-length CVM Results and a proprietary tag absent from the Book 3
 * dictionary) to exercise the graceful-handling paths below. */
static int build_record(uint8_t* content, size_t capacity, size_t* content_size) {
    tlv_writer_t writer;
    uint8_t      scratch[16];
    size_t       size;

    CHECK(tlv_writer_init(&writer, content, capacity, &tlv_writer_format_ber));

    /* PAN (5A): BCD-packed digits; trailing 'F' padding is not needed here. */
    if (encode_child(tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_pan)->codec,
                     "4111111111111111", 16, scratch, sizeof(scratch), &size))
        return 1;
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_pan, scratch, size));

    /* Application Expiration Date (5F24): YYMMDD BCD. */
    {
        const tlv_emv_date_t expiry = {27, 12, 31};
        if (encode_child(
                tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_application_expiration_date)->codec,
                &expiry, sizeof(expiry), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_application_expiration_date, scratch, size));

    /* AIP (82): SDA and CDA supported. */
    {
        const uint64_t aip = TLV_EMV_AIP_SDA_SUPPORTED | TLV_EMV_AIP_CDA_SUPPORTED;
        if (encode_child(tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_aip)->codec, &aip,
                         sizeof(aip), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_aip, scratch, size));

    /* AFL (94): one entry, SFI 1, records 1-1, no offline data
     * authentication records. */
    {
        tlv_emv_afl_t afl;
        memset(&afl, 0, sizeof(afl));
        afl.count = 1;
        afl.entries[0].sfi = 1;
        afl.entries[0].first_record = 1;
        afl.entries[0].last_record = 1;
        afl.entries[0].offline_auth_record_count = 0;
        if (encode_child(tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_afl)->codec, &afl,
                         sizeof(afl), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_afl, scratch, size));

    /* Amount, Authorised (9F02): n12 BCD, unscaled minor units. */
    {
        const uint64_t amount = 12345; /* 123.45 in a two-decimal currency */
        if (encode_child(tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_amount_authorised)->codec,
                         &amount, sizeof(amount), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_amount_authorised, scratch, size));

    /* Cryptogram Information Data (9F27): ARQC requested. */
    {
        const tlv_emv_cryptogram_info_t cid = {TLV_EMV_CRYPTOGRAM_ARQC, 0x15};
        if (encode_child(
                tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_cryptogram_information_data)->codec,
                &cid, sizeof(cid), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_cryptogram_information_data, scratch, size));

    /* CVM Results (9F34) deliberately truncated to two bytes instead of the
     * dictionary's required three, to demonstrate a length mismatch. */
    {
        static const uint8_t bad_cvm_results[] = {0x1F, 0x00};
        CHECK(tlv_writer_write(&writer, tlv_emv_tag_cvm_results, bad_cvm_results,
                               sizeof(bad_cvm_results)));
    }

    /* Account Type (5F57). */
    {
        const tlv_emv_account_type_t account = TLV_EMV_ACCOUNT_CREDIT;
        if (encode_child(tlv_emv_find(TLV_EMV_CONTEXT_BASE, &tlv_emv_tag_account_type)->codec,
                         &account, sizeof(account), scratch, sizeof(scratch), &size))
            return 1;
    }
    CHECK(tlv_writer_write(&writer, tlv_emv_tag_account_type, scratch, size));

    /* A proprietary issuer tag absent from the Book 3 dictionary. */
    {
        const tlv_tag_t      proprietary = {{0xDF, 0x01}, 2};
        static const uint8_t proprietary_value[] = {0xAA, 0xBB, 0xCC};
        CHECK(tlv_writer_write(&writer, proprietary, proprietary_value, sizeof(proprietary_value)));
    }

    *content_size = tlv_writer_size(&writer);
    return 0;
}

/* Everything the walk below successfully decoded, plus counters used to
 * assert the record was handled as expected once the walk completes. */
typedef struct {
    int                       errors, known_count, unknown_count, invalid_length_count;
    int                       pan_seen;
    char                      pan[32];
    int                       expiry_seen;
    tlv_emv_date_t            expiry;
    int                       aip_seen;
    uint64_t                  aip;
    int                       afl_seen;
    tlv_emv_afl_t             afl;
    int                       amount_seen;
    uint64_t                  amount;
    int                       cryptogram_seen;
    tlv_emv_cryptogram_info_t cryptogram;
    int                       account_seen;
    tlv_emv_account_type_t    account;
} record_t;

static tlv_visit_result_t decode_field(const tlv_view_t* view, void* context) {
    record_t*                   record = (record_t*)context;
    const tlv_emv_definition_t* def;
    size_t                      length;

    print_tag(&view->tag);
    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) {
        printf(" -> value length is not representable here\n");
        ++record->errors;
        return TLV_VISIT_CONTINUE;
    }

    def = tlv_emv_find(TLV_EMV_CONTEXT_BASE, &view->tag);
    if (!def) {
        printf(" -> unknown tag, not in the Book 3 dictionary; skipping\n");
        ++record->unknown_count;
        return TLV_VISIT_CONTINUE;
    }
    printf(" (%s)", def->name);

    if (tlv_emv_validate_length(def, length) != TLV_OK) {
        printf(" -> invalid length %zu for this tag; skipping\n", length);
        ++record->invalid_length_count;
        return TLV_VISIT_CONTINUE;
    }

    switch (def->value_kind) {
        case TLV_EMV_VALUE_DIGITS: {
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     record->pan, sizeof(record->pan));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = %s\n", record->pan);
            record->pan_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_DATE: {
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     &record->expiry, sizeof(record->expiry));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = 20%02u-%02u-%02u (century assumed by the caller)\n",
                   (unsigned)record->expiry.year, (unsigned)record->expiry.month,
                   (unsigned)record->expiry.day);
            record->expiry_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_FLAGS: {
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     &record->aip, sizeof(record->aip));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = 0x%04" PRIX64 " (SDA supported: %s, CDA supported: %s)\n", record->aip,
                   (record->aip & TLV_EMV_AIP_SDA_SUPPORTED) ? "yes" : "no",
                   (record->aip & TLV_EMV_AIP_CDA_SUPPORTED) ? "yes" : "no");
            record->aip_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_NUMBER: {
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     &record->amount, sizeof(record->amount));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = %" PRIu64 " minor units\n", record->amount);
            record->amount_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_CRYPTOGRAM: {
            static const char* const names[] = {"AAC", "TC", "ARQC", "RFU"};
            tlv_codec_result_t       rc =
                tlv_codec_decode(def->codec, view->value.data, length, &record->cryptogram,
                                 sizeof(record->cryptogram));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = %s\n", names[record->cryptogram.type]);
            record->cryptogram_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_ACCOUNT: {
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     &record->account, sizeof(record->account));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" = %s\n", record->account == TLV_EMV_ACCOUNT_CREDIT         ? "credit"
                              : record->account == TLV_EMV_ACCOUNT_SAVINGS      ? "savings"
                              : record->account == TLV_EMV_ACCOUNT_CHEQUE_DEBIT ? "cheque/debit"
                                                                                : "default");
            record->account_seen = 1;
            break;
        }
        case TLV_EMV_VALUE_AFL: {
            size_t             i;
            tlv_codec_result_t rc = tlv_codec_decode(def->codec, view->value.data, length,
                                                     &record->afl, sizeof(record->afl));
            if (rc != TLV_CODEC_OK) {
                printf(" -> decode error: %s\n", tlv_codec_strerror(rc));
                ++record->errors;
                break;
            }
            printf(" =");
            for (i = 0; i < record->afl.count; ++i)
                printf(" (sfi %u, records %u-%u, %u for offline auth)",
                       (unsigned)record->afl.entries[i].sfi,
                       (unsigned)record->afl.entries[i].first_record,
                       (unsigned)record->afl.entries[i].last_record,
                       (unsigned)record->afl.entries[i].offline_auth_record_count);
            putchar('\n');
            record->afl_seen = 1;
            break;
        }
        default:
            /* TEXT, TEMPLATE, TIME, BIOMETRIC, NUMBER_LIST: not present in this
             * demo record. Decode with the same tlv_codec_decode() dispatch,
             * keyed on def->value_kind, into their documented C representation. */
            printf(" -> %s value, %zu raw bytes (not decoded by this example)\n", def->name,
                   length);
            break;
    }
    ++record->known_count;
    return TLV_VISIT_CONTINUE;
}

int main(void) {
    uint8_t    content[256], wire[300];
    size_t     content_size, wire_size, consumed, wire_content_size;
    tlv_view_t outer;
    record_t   record;
    memset(&record, 0, sizeof(record));

    if (build_record(content, sizeof(content), &content_size)) return 1;

    /* Wrap the children in a READ RECORD response template (70), then parse
     * that record exactly as it would arrive over the wire. */
    CHECK(tlv_write(wire, sizeof(wire), &tlv_writer_format_ber, tlv_emv_tag_read_record_template,
                    content, content_size, &wire_size));

    puts("Parsing a simulated EMV READ RECORD response template (70):");
    CHECK(tlv_read(wire, wire_size, &tlv_reader_format_ber, &outer, &consumed));
    EXPECT(consumed == wire_size, "unexpected trailing bytes after the record template");
    CHECK(tlv_length_to_size(outer.value.length, &wire_content_size));

    CHECK(tlv_walk(outer.value.data, wire_content_size, &tlv_reader_format_ber, decode_field,
                   &record));

    EXPECT(record.errors == 0, "no decode errors were expected");
    EXPECT(record.known_count == 7, "seven tags with a dictionary entry were expected");
    EXPECT(record.unknown_count == 1, "one tag outside the dictionary was expected");
    EXPECT(record.invalid_length_count == 1, "one invalid-length tag was expected");
    EXPECT(record.pan_seen && strcmp(record.pan, "4111111111111111") == 0,
           "PAN decoded incorrectly");
    EXPECT(record.expiry_seen && record.expiry.year == 27 && record.expiry.month == 12 &&
               record.expiry.day == 31,
           "expiration date decoded incorrectly");
    EXPECT(record.aip_seen && record.aip == (TLV_EMV_AIP_SDA_SUPPORTED | TLV_EMV_AIP_CDA_SUPPORTED),
           "AIP decoded incorrectly");
    EXPECT(record.afl_seen && record.afl.count == 1 && record.afl.entries[0].sfi == 1 &&
               record.afl.entries[0].first_record == 1 && record.afl.entries[0].last_record == 1 &&
               record.afl.entries[0].offline_auth_record_count == 0,
           "AFL decoded incorrectly");
    EXPECT(record.amount_seen && record.amount == 12345, "amount decoded incorrectly");
    EXPECT(record.cryptogram_seen && record.cryptogram.type == TLV_EMV_CRYPTOGRAM_ARQC &&
               record.cryptogram.flags == 0x15,
           "cryptogram information decoded incorrectly");
    EXPECT(record.account_seen && record.account == TLV_EMV_ACCOUNT_CREDIT,
           "account type decoded incorrectly");

    puts("All known tags decoded and validated; the unknown tag and the "
         "invalid-length tag were skipped without aborting the walk.");
    return 0;
}
