#include "decode.hpp"
#include "tlv/config.h"
#if OPENTLV_PROFILE_EMV
#include <cinttypes>
#include <cstdio>
#include <limits>
#include "tlv/length.h"
#include "tlv/builtins/emv/emv.h"
#endif

namespace cli {

#if OPENTLV_PROFILE_EMV
namespace {

std::string format_number(const uint64_t& value) {
    return std::to_string(value);
}

std::string format_flags(const uint64_t& value) {
    char buffer[2 + 16 + 1];
    std::snprintf(buffer, sizeof(buffer), "0x%" PRIX64, value);
    return buffer;
}

std::string format_date(const tlv_emv_date_t& date) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "20%02u-%02u-%02u", (unsigned)date.year,
                  (unsigned)date.month, (unsigned)date.day);
    return buffer;
}

std::string format_time(const tlv_emv_time_t& time) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u", (unsigned)time.hour,
                  (unsigned)time.minute, (unsigned)time.second);
    return buffer;
}

const char* account_name(tlv_emv_account_type_t account) {
    switch (account) {
        case TLV_EMV_ACCOUNT_SAVINGS: return "savings";
        case TLV_EMV_ACCOUNT_CHEQUE_DEBIT: return "cheque/debit";
        case TLV_EMV_ACCOUNT_CREDIT: return "credit";
        default: return "default";
    }
}

const char* cryptogram_name(tlv_emv_cryptogram_type_t type) {
    switch (type) {
        case TLV_EMV_CRYPTOGRAM_AAC: return "AAC";
        case TLV_EMV_CRYPTOGRAM_TC: return "TC";
        case TLV_EMV_CRYPTOGRAM_ARQC: return "ARQC";
        default: return "RFU";
    }
}

std::string format_cryptogram(const tlv_emv_cryptogram_info_t& info) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%s (flags=0x%02X)", cryptogram_name(info.type),
                  (unsigned)info.flags);
    return buffer;
}

const char* biometric_name(tlv_emv_biometric_type_t type) {
    switch (type) {
        case TLV_EMV_BIOMETRIC_FACIAL: return "facial";
        case TLV_EMV_BIOMETRIC_VOICE: return "voice";
        case TLV_EMV_BIOMETRIC_FINGER: return "finger";
        case TLV_EMV_BIOMETRIC_IRIS: return "iris";
        case TLV_EMV_BIOMETRIC_PALM: return "palm";
        default: return "unknown";
    }
}

std::string format_number_list(const tlv_emv_number_list_t& list) {
    std::string result;
    for (size_t i = 0; i < list.count; ++i) {
        if (i) result += ',';
        result += std::to_string(list.values[i]);
    }
    return result;
}

std::string format_afl(const tlv_emv_afl_t& afl) {
    std::string result;
    char        entry[64];
    for (size_t i = 0; i < afl.count; ++i) {
        if (i) result += ';';
        std::snprintf(entry, sizeof(entry), "sfi=%u records=%u-%u offline=%u",
                      (unsigned)afl.entries[i].sfi, (unsigned)afl.entries[i].first_record,
                      (unsigned)afl.entries[i].last_record,
                      (unsigned)afl.entries[i].offline_auth_record_count);
        result += entry;
    }
    return result;
}

const char* cvm_result_name(uint8_t result) {
    switch (result) {
        case TLV_EMV_CVM_RESULT_FAILED: return "failed";
        case TLV_EMV_CVM_RESULT_SUCCESSFUL: return "successful";
        default: return "unknown";
    }
}

std::string format_cvm_result(const tlv_emv_cvm_result_t& result) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "method=0x%02X condition=0x%02X result=%s",
                  (unsigned)result.method, (unsigned)result.condition,
                  cvm_result_name(result.result));
    return buffer;
}

std::string format_track2(const tlv_emv_track2_t& track2) {
    char buffer[128];
    std::snprintf(buffer, sizeof(buffer), "pan=%s exp=%02u/%02u service=%03u discretionary=%s",
                  track2.pan, (unsigned)track2.expiration_year, (unsigned)track2.expiration_month,
                  (unsigned)track2.service_code, track2.discretionary_data);
    return buffer;
}

template <typename T>
decode_result decode_fixed(const tlv_codec_t* codec, const uint8_t* data, size_t size,
                           std::string (*format)(const T&)) {
    decode_result      result;
    T                  value;
    tlv_codec_result_t rc = tlv_codec_decode(codec, data, size, &value, sizeof(value));
    if (rc != TLV_CODEC_OK) {
        result.status = decode_status::error;
        result.text = tlv_codec_strerror(rc);
        return result;
    }
    result.status = decode_status::ok;
    result.text = format(value);
    return result;
}

decode_result decode_digits(const tlv_codec_t* codec, const uint8_t* data, size_t size) {
    decode_result result;
    // The codec writes at most 2 digits per input byte, plus a NUL terminator.
    if (size > (std::numeric_limits<size_t>::max)() / 2 - 1) {
        result.status = decode_status::error;
        result.text = "value too large to decode";
        return result;
    }
    std::string        buffer(size * 2 + 1, '\0');
    tlv_codec_result_t rc = tlv_codec_decode(codec, data, size, &buffer[0], buffer.size());
    if (rc != TLV_CODEC_OK) {
        result.status = decode_status::error;
        result.text = tlv_codec_strerror(rc);
        return result;
    }
    result.status = decode_status::ok;
    result.text = buffer.c_str();
    return result;
}

} // namespace
#endif

decode_result decode_emv_value(int context, const tlv_view_t* view) {
    decode_result result;
#if OPENTLV_PROFILE_EMV
    const tlv_emv_definition_t* definition = tlv_emv_find((tlv_emv_context_t)context, &view->tag);
    size_t                      length;
    if (!definition || !definition->codec) return result;
    if (tlv_length_to_size(view->value.length, &length) != TLV_OK) {
        result.status = decode_status::error;
        result.text = "value length is not representable here";
        return result;
    }
    switch (definition->value_kind) {
        case TLV_EMV_VALUE_NUMBER:
            return decode_fixed<uint64_t>(definition->codec, view->value.data, length,
                                          format_number);
        case TLV_EMV_VALUE_FLAGS:
            return decode_fixed<uint64_t>(definition->codec, view->value.data, length,
                                          format_flags);
        case TLV_EMV_VALUE_DIGITS:
            return decode_digits(definition->codec, view->value.data, length);
        case TLV_EMV_VALUE_DATE:
            return decode_fixed<tlv_emv_date_t>(definition->codec, view->value.data, length,
                                                format_date);
        case TLV_EMV_VALUE_TIME:
            return decode_fixed<tlv_emv_time_t>(definition->codec, view->value.data, length,
                                                format_time);
        case TLV_EMV_VALUE_ACCOUNT:
            return decode_fixed<tlv_emv_account_type_t>(
                definition->codec, view->value.data, length,
                [](const tlv_emv_account_type_t& account) -> std::string {
                    return account_name(account);
                });
        case TLV_EMV_VALUE_CRYPTOGRAM:
            return decode_fixed<tlv_emv_cryptogram_info_t>(definition->codec, view->value.data,
                                                           length, format_cryptogram);
        case TLV_EMV_VALUE_BIOMETRIC:
            return decode_fixed<tlv_emv_biometric_type_t>(
                definition->codec, view->value.data, length,
                [](const tlv_emv_biometric_type_t& biometric) -> std::string {
                    return biometric_name(biometric);
                });
        case TLV_EMV_VALUE_NUMBER_LIST:
            return decode_fixed<tlv_emv_number_list_t>(definition->codec, view->value.data, length,
                                                       format_number_list);
        case TLV_EMV_VALUE_AFL:
            return decode_fixed<tlv_emv_afl_t>(definition->codec, view->value.data, length,
                                               format_afl);
        case TLV_EMV_VALUE_CVM_RESULT:
            return decode_fixed<tlv_emv_cvm_result_t>(definition->codec, view->value.data, length,
                                                      format_cvm_result);
        case TLV_EMV_VALUE_TRACK2:
            return decode_fixed<tlv_emv_track2_t>(definition->codec, view->value.data, length,
                                                  format_track2);
        default: return result; // BYTES, TEXT, TEMPLATE: no codec, already returned above
    }
#else
    (void)context;
    (void)view;
    return result;
#endif
}

} // namespace cli
