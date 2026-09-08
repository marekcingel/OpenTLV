#include "emv_internal.h"
#include <string.h>

static int valid_length(const emv_value_rule_t* rule, size_t size) {
    return size >= rule->min_length && size <= rule->max_length &&
           rule->step && (size - rule->min_length) % rule->step == 0;
}

static uint64_t decimal_limit(unsigned digits) {
    uint64_t limit = 1;
    while (digits--) limit *= 10;
    return limit - 1;
}

static int read_number(const uint8_t* data, size_t size, unsigned digits,
                       uint64_t* value) {
    uint64_t number = 0;
    size_t i;
    if (!size || size > 8 || digits > 18) return 0;
    for (i = 0; i < size; ++i) {
        unsigned part = data[i];
        unsigned radix = 256;
        if (digits) {
            if ((part >> 4) > 9 || (part & 15) > 9) return 0;
            part = (part >> 4) * 10 + (part & 15);
            radix = 100;
        }
        if (number > (UINT64_MAX - part) / radix) return 0;
        number = number * radix + part;
    }
    if (digits && number > decimal_limit(digits)) return 0;
    *value = number;
    return 1;
}

static int write_number(uint64_t value, unsigned digits,
                        uint8_t* data, size_t size) {
    size_t i;
    if (!size || size > 8 || digits > 18 ||
        (digits && value > decimal_limit(digits))) return 0;
    for (i = size; i > 0; --i) {
        if (digits) {
            unsigned pair = (unsigned)(value % 100);
            data[i - 1] = (uint8_t)(((pair / 10) << 4) | (pair % 10));
            value /= 100;
        } else {
            data[i - 1] = (uint8_t)(value & 255);
            value >>= 8;
        }
    }
    return value == 0;
}

static int valid_date(tlv_emv_date_t date) {
    static const uint8_t days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
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

static tlv_codec_result_t decode_digits(const emv_value_rule_t* rule,
        const uint8_t* data, size_t size, void* value, size_t capacity) {
    size_t i, count = 0;
    int padding = 0;
    char* digits = (char*)value;
    if (size > (SIZE_MAX - 1) / 2) return TLV_CODEC_ERR_INVALID_VALUE;
    for (i = 0; i < size * 2; ++i) {
        unsigned digit = (i % 2 ? data[i / 2] : data[i / 2] >> 4) & 15;
        if (digit == 15) padding = 1;
        else {
            if (digit > 9 || padding) return TLV_CODEC_ERR_INVALID_VALUE;
            ++count;
        }
    }
    if (rule->argument && (!count || count > rule->argument))
        return TLV_CODEC_ERR_INVALID_VALUE;
    if (capacity < count + 1) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    for (i = 0; i < count; ++i) {
        unsigned digit = (i % 2 ? data[i / 2] : data[i / 2] >> 4) & 15;
        digits[i] = (char)('0' + digit);
    }
    digits[count] = '\0';
    return TLV_CODEC_OK;
}

static tlv_codec_result_t encode_digits(const emv_value_rule_t* rule,
        const void* value, size_t size, uint8_t* data, size_t capacity,
        size_t* written) {
    const char* digits = (const char*)value;
    size_t i, bytes = size / 2 + size % 2;
    if (!valid_length(rule, bytes) ||
        (rule->argument && (!size || size > rule->argument)))
        return TLV_CODEC_ERR_INVALID_VALUE;
    for (i = 0; i < size; ++i)
        if (digits[i] < '0' || digits[i] > '9') return TLV_CODEC_ERR_INVALID_VALUE;
    if (data) {
        if (capacity < bytes) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
        for (i = 0; i < bytes; ++i) {
            unsigned high = (unsigned)(digits[i * 2] - '0');
            unsigned low = i * 2 + 1 < size ? (unsigned)(digits[i * 2 + 1] - '0') : 15;
            data[i] = (uint8_t)((high << 4) | low);
        }
    }
    *written = bytes;
    return TLV_CODEC_OK;
}

#define EMV_STORE(object) do { \
    if (capacity < sizeof(object)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT; \
    memcpy(value, &(object), sizeof(object)); \
    return TLV_CODEC_OK; \
} while (0)

tlv_codec_result_t emv_value_decode(const void* context, const uint8_t* data,
        size_t size, void* value, size_t capacity) {
    const emv_value_rule_t* rule = (const emv_value_rule_t*)context;
    uint64_t number;
    if (!valid_length(rule, size)) return TLV_CODEC_ERR_INVALID_VALUE;
    switch (rule->kind) {
        case TLV_EMV_VALUE_NUMBER:
        case TLV_EMV_VALUE_FLAGS:
            if (!read_number(data, size, rule->argument, &number))
                return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(number);
        case TLV_EMV_VALUE_DIGITS:
            return decode_digits(rule, data, size, value, capacity);
        case TLV_EMV_VALUE_DATE: {
            tlv_emv_date_t date;
            if (!read_number(data, size, 6, &number)) return TLV_CODEC_ERR_INVALID_VALUE;
            date.year = (uint8_t)(number / 10000);
            date.month = (uint8_t)((number / 100) % 100);
            date.day = (uint8_t)(number % 100);
            if (!valid_date(date)) return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(date);
        }
        case TLV_EMV_VALUE_TIME: {
            tlv_emv_time_t time;
            if (!read_number(data, size, 6, &number)) return TLV_CODEC_ERR_INVALID_VALUE;
            time.hour = (uint8_t)(number / 10000);
            time.minute = (uint8_t)((number / 100) % 100);
            time.second = (uint8_t)(number % 100);
            if (time.hour > 23 || time.minute > 59 || time.second > 59)
                return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(time);
        }
        case TLV_EMV_VALUE_ACCOUNT: {
            tlv_emv_account_type_t account;
            if (!read_number(data, size, 2, &number) || !valid_account(number))
                return TLV_CODEC_ERR_INVALID_VALUE;
            account = (tlv_emv_account_type_t)number;
            EMV_STORE(account);
        }
        case TLV_EMV_VALUE_CRYPTOGRAM: {
            tlv_emv_cryptogram_info_t info = {TLV_EMV_CRYPTOGRAM_AAC, 0};
            info.type = (tlv_emv_cryptogram_type_t)(data[0] >> 6);
            info.flags = data[0] & 63;
            EMV_STORE(info);
        }
        case TLV_EMV_VALUE_BIOMETRIC: {
            tlv_emv_biometric_type_t biometric;
            if (!read_number(data, size, 0, &number) || !valid_biometric(number))
                return TLV_CODEC_ERR_INVALID_VALUE;
            biometric = (tlv_emv_biometric_type_t)number;
            EMV_STORE(biometric);
        }
        case TLV_EMV_VALUE_NUMBER_LIST: {
            tlv_emv_number_list_t list = {{0}, 0};
            size_t i, width = (rule->argument + 1) / 2;
            list.count = size / width;
            if (size % width || list.count > 4) return TLV_CODEC_ERR_INVALID_VALUE;
            for (i = 0; i < list.count; ++i)
                if (!read_number(data + i * width, width, rule->argument, &list.values[i]))
                    return TLV_CODEC_ERR_INVALID_VALUE;
            EMV_STORE(list);
        }
        default: return TLV_CODEC_ERR_UNSUPPORTED;
    }
}
#undef EMV_STORE

#define EMV_LOAD(object) do { \
    if (size != sizeof(object)) return TLV_CODEC_ERR_INVALID_VALUE; \
    memcpy(&(object), value, sizeof(object)); \
} while (0)

tlv_codec_result_t emv_value_encode(const void* context, const void* value,
        size_t size, uint8_t* data, size_t capacity, size_t* written) {
    const emv_value_rule_t* rule = (const emv_value_rule_t*)context;
    uint8_t bytes[8];
    uint64_t number;
    size_t count = rule->min_length;
    if (rule->kind == TLV_EMV_VALUE_DIGITS)
        return encode_digits(rule, value, size, data, capacity, written);
    switch (rule->kind) {
        case TLV_EMV_VALUE_NUMBER:
        case TLV_EMV_VALUE_FLAGS:
            EMV_LOAD(number);
            while (count <= rule->max_length && count <= sizeof(bytes)) {
                if (write_number(number, rule->argument, bytes, count)) break;
                count += rule->step;
            }
            if (count > rule->max_length || count > sizeof(bytes))
                return TLV_CODEC_ERR_INVALID_VALUE;
            break;
        case TLV_EMV_VALUE_DATE: {
            tlv_emv_date_t date;
            EMV_LOAD(date);
            if (!valid_date(date)) return TLV_CODEC_ERR_INVALID_VALUE;
            number = date.year * UINT64_C(10000) + date.month * 100 + date.day;
            write_number(number, 6, bytes, count);
            break;
        }
        case TLV_EMV_VALUE_TIME: {
            tlv_emv_time_t time;
            EMV_LOAD(time);
            if (time.hour > 23 || time.minute > 59 || time.second > 59)
                return TLV_CODEC_ERR_INVALID_VALUE;
            number = time.hour * UINT64_C(10000) + time.minute * 100 + time.second;
            write_number(number, 6, bytes, count);
            break;
        }
        case TLV_EMV_VALUE_ACCOUNT: {
            tlv_emv_account_type_t account;
            EMV_LOAD(account);
            if (!valid_account((uint64_t)account)) return TLV_CODEC_ERR_INVALID_VALUE;
            write_number((uint64_t)account, 2, bytes, count);
            break;
        }
        case TLV_EMV_VALUE_CRYPTOGRAM: {
            tlv_emv_cryptogram_info_t info;
            EMV_LOAD(info);
            if ((unsigned)info.type > 3 || info.flags > 63) return TLV_CODEC_ERR_INVALID_VALUE;
            bytes[0] = (uint8_t)(((unsigned)info.type << 6) | info.flags);
            break;
        }
        case TLV_EMV_VALUE_BIOMETRIC: {
            tlv_emv_biometric_type_t biometric;
            EMV_LOAD(biometric);
            if (!valid_biometric((uint64_t)biometric)) return TLV_CODEC_ERR_INVALID_VALUE;
            count = biometric == TLV_EMV_BIOMETRIC_PALM ? 3 : 1;
            write_number((uint64_t)biometric, 0, bytes, count);
            break;
        }
        case TLV_EMV_VALUE_NUMBER_LIST: {
            tlv_emv_number_list_t list;
            size_t i, width = (rule->argument + 1) / 2;
            EMV_LOAD(list);
            if (!list.count || list.count > 4) return TLV_CODEC_ERR_INVALID_VALUE;
            count = list.count * width;
            for (i = 0; i < list.count; ++i)
                if (!write_number(list.values[i], rule->argument, bytes + i * width, width))
                    return TLV_CODEC_ERR_INVALID_VALUE;
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

static const emv_value_rule_t amount_rule = {6, 6, 1, TLV_EMV_VALUE_NUMBER, 12};
const tlv_codec_t tlv_emv_codec_amount = {&amount_rule, emv_value_decode, emv_value_encode};
