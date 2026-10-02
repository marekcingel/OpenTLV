// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "emv_codec_internal.h"
#include "tlv/builtins/emv/emv.h"
#include <string.h>
#include "tlv/codec/number.h"
#include "tlv/codec/digits.h"

enum {
    EMV_BCD_NIBBLE_BITS = 4, /* bit width of one BCD nibble */
    EMV_NIBBLE_MASK = 0xF,   /* mask isolating one BCD nibble */
    EMV_BCD_PAD_NIBBLE = 0xF /* nibble value marking an unused (odd-length) digit position */
};

/* YYMMDD/HHMMSS decimal fields, decoded/encoded as a single number: the
 * first field is separated by a factor of 100 twice, the middle and last
 * fields each by a single factor of 100. This is a
 * place-value scale, not per-byte packing. */
enum { EMV_DATE_TIME_MAJOR_FIELD_SCALE = 10000, EMV_DATE_TIME_MINOR_FIELD_SCALE = 100 };

enum { EMV_MAX_HOUR = 23, EMV_MAX_MINUTE = 59, EMV_MAX_SECOND = 59 };

/* Cryptogram Information Data byte: a 2-bit type in the high bits, a 6-bit
 * flags field in the low bits. */
enum { EMV_CID_TYPE_SHIFT = 6, EMV_CID_FLAGS_MASK = 0x3F };

/* AFL entry byte one: SFI occupies the top five bits, the low three are RFU. */
enum { EMV_AFL_SFI_SHIFT = 3, EMV_AFL_MIN_SFI = 1, EMV_AFL_MAX_SFI = 30 };

/* Track 2: BCD digit nibbles, a field-separator nibble (hex D), then a fixed
 * four-digit expiration date and three-digit service code. */
enum {
    EMV_TRACK2_FIELD_SEPARATOR = 0xD,
    EMV_TRACK2_EXPIRY_DIGITS = 4,
    EMV_TRACK2_SERVICE_CODE_DIGITS = 3,
    EMV_TRACK2_MAX_DIGITS = TLV_EMV_TRACK2_PAN_MAX_DIGITS + 1 + EMV_TRACK2_EXPIRY_DIGITS +
        EMV_TRACK2_SERVICE_CODE_DIGITS + TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS + 1
};

/* Upper bound for a semantic codec's encoded output: AFL's 252-byte maximum
 * (63 four-byte entries) is the largest; every other kind needs far less. */
enum { EMV_MAX_ENCODED_VALUE_SIZE = 252 };

static int valid_length(const emv_value_rule_t* rule, size_t size) {
    return tlv_schema_validate_length(rule->schema, size) == TLV_OK;
}

/* Domain codecs compose the same numeric primitive as dictionary entries. */
static int read_number(const uint8_t* data, size_t size, unsigned digits, uint64_t* value) {
    const tlv_number_codec_config_t config = {digits ? TLV_NUMBER_BCD : TLV_NUMBER_BINARY_BE, size,
                                              digits};
    return size <= 8 &&
           tlv_number_decode(&config, data, size, value, sizeof(*value)) == TLV_CODEC_OK;
}

static int write_number(uint64_t value, unsigned digits, uint8_t* data, size_t size) {
    const tlv_number_codec_config_t config = {digits ? TLV_NUMBER_BCD : TLV_NUMBER_BINARY_BE, size,
                                              digits};
    size_t written;
    return size <= 8 &&
           tlv_number_encode(&config, &value, sizeof(value), data, size, &written) == TLV_CODEC_OK;
}

static int valid_date(tlv_emv_date_t date) {
    static const uint8_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned limit;
    if (date.year > 99 || date.month < 1 || date.month > 12) return 0;
    limit = days[date.month - 1];
    if (date.month == 2 && date.year % 4 == 0) ++limit;
    return date.day >= 1 && date.day <= limit;
}

static int valid_account(uint64_t account) {
    return account == TLV_EMV_ACCOUNT_DEFAULT || account == TLV_EMV_ACCOUNT_SAVINGS ||
           account == TLV_EMV_ACCOUNT_CHEQUE_DEBIT || account == TLV_EMV_ACCOUNT_CREDIT;
}

static int valid_biometric(uint64_t biometric) {
    return biometric == TLV_EMV_BIOMETRIC_FACIAL || biometric == TLV_EMV_BIOMETRIC_VOICE ||
           biometric == TLV_EMV_BIOMETRIC_FINGER || biometric == TLV_EMV_BIOMETRIC_IRIS ||
           biometric == TLV_EMV_BIOMETRIC_PALM;
}

static int valid_afl_entry(uint8_t sfi, uint8_t first_record, uint8_t last_record,
                           uint8_t offline_auth_record_count) {
    return sfi >= EMV_AFL_MIN_SFI && sfi <= EMV_AFL_MAX_SFI && first_record >= 1 &&
           last_record >= first_record &&
           offline_auth_record_count <= (uint8_t)(last_record - first_record + 1);
}

/* i counts nibbles from the start of `data`, high nibble of each byte first. */
static unsigned track2_nibble(const uint8_t* data, size_t i) {
    return (i % 2 ? data[i / 2] : data[i / 2] >> EMV_BCD_NIBBLE_BITS) & EMV_NIBBLE_MASK;
}

static size_t emv_strnlen(const char* value, size_t limit) {
    size_t length = 0;
    while (length < limit && value[length]) ++length;
    return length;
}

static tlv_codec_result_t decode_digits(const emv_value_rule_t* rule, const uint8_t* data,
                                        size_t size, void* value, size_t capacity) {
    const tlv_digits_codec_config_t config = {0};
    char pan[20];
    tlv_codec_result_t result;
    size_t count;
    if (!rule->argument) return tlv_digits_decode(&config, data, size, value, capacity);
    result = tlv_digits_decode(&config, data, size, pan, sizeof(pan));
    if (result != TLV_CODEC_OK) return TLV_CODEC_ERR_INVALID_VALUE;
    count = strlen(pan);
    if (!count || count > rule->argument) return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity <= count) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    memcpy(value, pan, count + 1);
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_digits(const emv_value_rule_t* rule, const void* value,
                                        size_t size, uint8_t* data, size_t capacity,
                                        size_t* written) {
    const tlv_digits_codec_config_t config = {0};
    if (!valid_length(rule, size / 2 + size % 2) ||
        (rule->argument && (!size || size > rule->argument)))
        return TLV_CODEC_ERR_INVALID_VALUE;
    return tlv_digits_encode(&config, value, size, data, capacity, written);
}

#define EMV_STORE(object)                                                                          \
    do {                                                                                           \
        if (capacity < sizeof(object)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;                      \
        memcpy(value, &(object), sizeof(object));                                                  \
        return TLV_CODEC_OK;                                                                       \
    } while (0)

tlv_codec_result_t emv_value_decode(const void* context, const uint8_t* data, size_t size,
                                    void* value, size_t capacity) {
    const emv_value_rule_t* rule = (const emv_value_rule_t*)context;
    uint64_t number;
    if (!valid_length(rule, size)) return TLV_CODEC_ERR_INVALID_VALUE;
    switch (rule->kind) {
        case EMV_REP_DIGITS: return decode_digits(rule, data, size, value, capacity);
        case EMV_REP_DATE: {
            tlv_emv_date_t date;
            if (!read_number(data, size, 6, &number)) return TLV_CODEC_ERR_INVALID_VALUE;
            date.year = (uint8_t)(number / EMV_DATE_TIME_MAJOR_FIELD_SCALE);
            date.month = (uint8_t)((number / EMV_DATE_TIME_MINOR_FIELD_SCALE) %
                                   EMV_DATE_TIME_MINOR_FIELD_SCALE);
            date.day = (uint8_t)(number % EMV_DATE_TIME_MINOR_FIELD_SCALE);
            if (!valid_date(date)) return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(date);
        }
        case EMV_REP_TIME: {
            tlv_emv_time_t time;
            if (!read_number(data, size, 6, &number)) return TLV_CODEC_ERR_INVALID_VALUE;
            time.hour = (uint8_t)(number / EMV_DATE_TIME_MAJOR_FIELD_SCALE);
            time.minute = (uint8_t)((number / EMV_DATE_TIME_MINOR_FIELD_SCALE) %
                                    EMV_DATE_TIME_MINOR_FIELD_SCALE);
            time.second = (uint8_t)(number % EMV_DATE_TIME_MINOR_FIELD_SCALE);
            if (time.hour > EMV_MAX_HOUR || time.minute > EMV_MAX_MINUTE ||
                time.second > EMV_MAX_SECOND)
                return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(time);
        }
        case EMV_REP_ACCOUNT: {
            tlv_emv_account_type_t account;
            if (!read_number(data, size, 2, &number) || !valid_account(number))
                return TLV_CODEC_ERR_INVALID_VALUE;
            account = (tlv_emv_account_type_t)number;
            EMV_STORE(account);
        }
        case EMV_REP_CRYPTOGRAM: {
            tlv_emv_cryptogram_info_t info = {TLV_EMV_CRYPTOGRAM_AAC, 0};
            info.type = (tlv_emv_cryptogram_type_t)(data[0] >> EMV_CID_TYPE_SHIFT);
            info.flags = data[0] & EMV_CID_FLAGS_MASK;
            EMV_STORE(info);
        }
        case EMV_REP_BIOMETRIC: {
            tlv_emv_biometric_type_t biometric;
            if (!read_number(data, size, 0, &number) || !valid_biometric(number))
                return TLV_CODEC_ERR_INVALID_VALUE;
            biometric = (tlv_emv_biometric_type_t)number;
            EMV_STORE(biometric);
        }
        case EMV_REP_NUMBER_LIST: {
            tlv_emv_number_list_t list = {{0}, 0};
            size_t i, width = (rule->argument + 1) / 2;
            list.count = size / width;
            if (size % width || list.count > sizeof(list.values) / sizeof(list.values[0]))
                return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < list.count; ++i)
                if (!read_number(data + i * width, width, rule->argument, &list.values[i]))
                    return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(list);
        }
        case EMV_REP_AFL: {
            tlv_emv_afl_t afl;
            size_t i;
            memset(&afl, 0, sizeof(afl));
            afl.count = size / 4;
            for (i = 0; i < afl.count; ++i) {
                const uint8_t* entry = data + i * 4;
                uint8_t sfi = (uint8_t)(entry[0] >> EMV_AFL_SFI_SHIFT);
                if (!valid_afl_entry(sfi, entry[1], entry[2], entry[3]))
                    return TLV_CODEC_ERR_INVALID_VALUE;
                afl.entries[i].sfi = sfi;
                afl.entries[i].first_record = entry[1];
                afl.entries[i].last_record = entry[2];
                afl.entries[i].offline_auth_record_count = entry[3];
            }
            EMV_STORE(afl);
        }
        case EMV_REP_CVM_RESULT: {
            tlv_emv_cvm_result_t result;
            result.method = data[0];
            result.condition = data[1];
            result.result = data[2];
            EMV_STORE(result);
        }
        case EMV_REP_TRACK2: {
            tlv_emv_track2_t track2;
            size_t total_nibbles, pad = 0, sep = (size_t)-1, i, disc_len;
            if (!size) return TLV_CODEC_ERR_INVALID_VALUE;
            total_nibbles = size * 2;
            memset(&track2, 0, sizeof(track2));
            if (track2_nibble(data, total_nibbles - 1) == EMV_BCD_PAD_NIBBLE) pad = 1;
            for (i = 0; i < total_nibbles - pad && i <= TLV_EMV_TRACK2_PAN_MAX_DIGITS; ++i) {
                unsigned nibble = track2_nibble(data, i);
                if (nibble == EMV_TRACK2_FIELD_SEPARATOR) {
                    sep = i;
                    break;
                }
                if (nibble > 9) return TLV_CODEC_ERR_INVALID_VALUE;
            }
            if (sep == (size_t)-1 || sep == 0 ||
                sep + 1 + EMV_TRACK2_EXPIRY_DIGITS + EMV_TRACK2_SERVICE_CODE_DIGITS >
                    total_nibbles - pad)
                return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < EMV_TRACK2_EXPIRY_DIGITS + EMV_TRACK2_SERVICE_CODE_DIGITS; ++i)
                if (track2_nibble(data, sep + 1 + i) > 9) return TLV_CODEC_ERR_INVALID_VALUE;
            disc_len = (total_nibbles - pad) -
                       (sep + 1 + EMV_TRACK2_EXPIRY_DIGITS + EMV_TRACK2_SERVICE_CODE_DIGITS);
            if (disc_len > TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS)
                return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < disc_len; ++i)
                if (track2_nibble(data, sep + 1 + EMV_TRACK2_EXPIRY_DIGITS +
                                            EMV_TRACK2_SERVICE_CODE_DIGITS + i) > 9)
                    return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < sep; ++i) track2.pan[i] = (char)('0' + track2_nibble(data, i));
            track2.expiration_year =
                (uint8_t)(track2_nibble(data, sep + 1) * 10 + track2_nibble(data, sep + 2));
            track2.expiration_month =
                (uint8_t)(track2_nibble(data, sep + 3) * 10 + track2_nibble(data, sep + 4));
            if (track2.expiration_month < 1 || track2.expiration_month > 12)
                return TLV_CODEC_ERR_INVALID_VALUE;
            track2.service_code =
                (uint16_t)(track2_nibble(data, sep + 5) * 100 + track2_nibble(data, sep + 6) * 10 +
                           track2_nibble(data, sep + 7));
            for (i = 0; i < disc_len; ++i)
                track2.discretionary_data[i] =
                    (char)('0' + track2_nibble(data, sep + 1 + EMV_TRACK2_EXPIRY_DIGITS +
                                                         EMV_TRACK2_SERVICE_CODE_DIGITS + i));
            EMV_STORE(track2);
        }
        default: return TLV_CODEC_ERR_UNSUPPORTED;
    }
}
#undef EMV_STORE

#define EMV_LOAD(object)                                                                           \
    do {                                                                                           \
        if (size != sizeof(object)) return TLV_CODEC_ERR_INVALID_VALUE;                            \
        memcpy(&(object), value, sizeof(object));                                                  \
    } while (0)

tlv_codec_result_t emv_value_encode(const void* context, const void* value, size_t size,
                                    uint8_t* data, size_t capacity, size_t* written) {
    const emv_value_rule_t* rule = (const emv_value_rule_t*)context;
    uint8_t bytes[EMV_MAX_ENCODED_VALUE_SIZE];
    uint64_t number;
    size_t count = rule->schema->min_length;
    if (rule->kind == EMV_REP_DIGITS)
        return encode_digits(rule, value, size, data, capacity, written);
    switch (rule->kind) {
        case EMV_REP_DATE: {
            tlv_emv_date_t date;
            EMV_LOAD(date);
            if (!valid_date(date)) return TLV_CODEC_ERR_INVALID_VALUE;
            number = (uint64_t)date.year * EMV_DATE_TIME_MAJOR_FIELD_SCALE +
                     (uint64_t)date.month * EMV_DATE_TIME_MINOR_FIELD_SCALE + date.day;
            write_number(number, 6, bytes, count);
            break;
        }
        case EMV_REP_TIME: {
            tlv_emv_time_t time;
            EMV_LOAD(time);
            if (time.hour > EMV_MAX_HOUR || time.minute > EMV_MAX_MINUTE ||
                time.second > EMV_MAX_SECOND)
                return TLV_CODEC_ERR_INVALID_VALUE;
            number = (uint64_t)time.hour * EMV_DATE_TIME_MAJOR_FIELD_SCALE +
                     (uint64_t)time.minute * EMV_DATE_TIME_MINOR_FIELD_SCALE + time.second;
            write_number(number, 6, bytes, count);
            break;
        }
        case EMV_REP_ACCOUNT: {
            tlv_emv_account_type_t account;
            EMV_LOAD(account);
            if (!valid_account((uint64_t)account)) return TLV_CODEC_ERR_INVALID_VALUE;
            write_number((uint64_t)account, 2, bytes, count);
            break;
        }
        case EMV_REP_CRYPTOGRAM: {
            tlv_emv_cryptogram_info_t info;
            EMV_LOAD(info);
            if ((unsigned)info.type > 3 || info.flags > EMV_CID_FLAGS_MASK)
                return TLV_CODEC_ERR_INVALID_VALUE;
            bytes[0] = (uint8_t)(((unsigned)info.type << EMV_CID_TYPE_SHIFT) | info.flags);
            break;
        }
        case EMV_REP_BIOMETRIC: {
            tlv_emv_biometric_type_t biometric;
            EMV_LOAD(biometric);
            if (!valid_biometric((uint64_t)biometric)) return TLV_CODEC_ERR_INVALID_VALUE;
            count = biometric == TLV_EMV_BIOMETRIC_PALM ? 3 : 1;
            write_number((uint64_t)biometric, 0, bytes, count);
            break;
        }
        case EMV_REP_NUMBER_LIST: {
            tlv_emv_number_list_t list;
            size_t i, width = (rule->argument + 1) / 2;
            EMV_LOAD(list);
            if (!list.count || list.count > sizeof(list.values) / sizeof(list.values[0]))
                return TLV_CODEC_ERR_INVALID_VALUE;
            count = list.count * width;
            for (i = 0; i < list.count; ++i)
                if (!write_number(list.values[i], rule->argument, bytes + i * width, width))
                    return TLV_CODEC_ERR_INVALID_VALUE;
            break;
        }
        case EMV_REP_AFL: {
            tlv_emv_afl_t afl;
            size_t i;
            EMV_LOAD(afl);
            if (!afl.count || afl.count > TLV_EMV_AFL_MAX_ENTRIES)
                return TLV_CODEC_ERR_INVALID_VALUE;
            count = afl.count * 4;
            for (i = 0; i < afl.count; ++i) {
                const tlv_emv_afl_entry_t* entry = &afl.entries[i];
                if (!valid_afl_entry(entry->sfi, entry->first_record, entry->last_record,
                                     entry->offline_auth_record_count))
                    return TLV_CODEC_ERR_INVALID_VALUE;
                bytes[i * 4 + 0] = (uint8_t)(entry->sfi << EMV_AFL_SFI_SHIFT);
                bytes[i * 4 + 1] = entry->first_record;
                bytes[i * 4 + 2] = entry->last_record;
                bytes[i * 4 + 3] = entry->offline_auth_record_count;
            }
            break;
        }
        case EMV_REP_CVM_RESULT: {
            tlv_emv_cvm_result_t result;
            EMV_LOAD(result);
            bytes[0] = result.method;
            bytes[1] = result.condition;
            bytes[2] = result.result;
            break;
        }
        case EMV_REP_TRACK2: {
            tlv_emv_track2_t track2;
            uint8_t nibbles[EMV_TRACK2_MAX_DIGITS];
            size_t pan_len, disc_len, n = 0, i;
            EMV_LOAD(track2);
            pan_len = emv_strnlen(track2.pan, sizeof(track2.pan));
            disc_len = emv_strnlen(track2.discretionary_data, sizeof(track2.discretionary_data));
            if (!pan_len || pan_len > TLV_EMV_TRACK2_PAN_MAX_DIGITS ||
                disc_len > TLV_EMV_TRACK2_DISCRETIONARY_MAX_DIGITS || track2.expiration_month < 1 ||
                track2.expiration_month > 12 || track2.expiration_year > 99 ||
                track2.service_code > 999)
                return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < pan_len; ++i) {
                if (track2.pan[i] < '0' || track2.pan[i] > '9') return TLV_CODEC_ERR_INVALID_VALUE;
                nibbles[n++] = (uint8_t)(track2.pan[i] - '0');
            }
            nibbles[n++] = EMV_TRACK2_FIELD_SEPARATOR;
            nibbles[n++] = (uint8_t)(track2.expiration_year / 10);
            nibbles[n++] = (uint8_t)(track2.expiration_year % 10);
            nibbles[n++] = (uint8_t)(track2.expiration_month / 10);
            nibbles[n++] = (uint8_t)(track2.expiration_month % 10);
            nibbles[n++] = (uint8_t)(track2.service_code / 100);
            nibbles[n++] = (uint8_t)((track2.service_code / 10) % 10);
            nibbles[n++] = (uint8_t)(track2.service_code % 10);
            for (i = 0; i < disc_len; ++i) {
                if (track2.discretionary_data[i] < '0' || track2.discretionary_data[i] > '9')
                    return TLV_CODEC_ERR_INVALID_VALUE;
                nibbles[n++] = (uint8_t)(track2.discretionary_data[i] - '0');
            }
            if (n % 2) nibbles[n++] = EMV_BCD_PAD_NIBBLE;
            count = n / 2;
            for (i = 0; i < count; ++i)
                bytes[i] = (uint8_t)((nibbles[i * 2] << EMV_BCD_NIBBLE_BITS) | nibbles[i * 2 + 1]);
            break;
        }
        default: return TLV_CODEC_ERR_UNSUPPORTED;
    }
    if (!valid_length(rule, count)) return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < count) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        memcpy(data, bytes, count);
    }
    *written = count;
    return TLV_CODEC_OK;
}
#undef EMV_LOAD

const char* tlv_emv_symbol(const tlv_emv_definition_t* definition) {
    return definition && definition->schema ? definition->schema->name : NULL;
}
