// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/emv/dol.h"
#include "tlv/builtins/asn1/ber.h"
#include <string.h>

const tlv_dol_limits_t tlv_dol_default_limits = {1000, TLV_DOL_MAX_VALUE_LENGTH};

static tlv_result_t fail(tlv_result_t rc, size_t offset, tlv_diagnostic_t* diagnostic) {
    if (diagnostic) {
        tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
        tlv_diagnostic_set_location(diagnostic, TLV_LOCATION_INPUT, TLV_LOCATION_POINT, offset,
                                    offset);
    }
    return rc;
}

static tlv_result_t unlocated(tlv_result_t rc, tlv_diagnostic_t* diagnostic) {
    if (diagnostic) tlv_diagnostic_init(diagnostic, rc, TLV_DIAGNOSTIC_SEVERITY_ERROR);
    return rc;
}

/* One DOL entry's tag is an ordinary BER tag; the byte immediately after it
 * is always a single raw unsigned length, never a BER length field, and no
 * value bytes follow. */
static tlv_result_t read_entry(const uint8_t* data, size_t size, size_t offset,
                               tlv_dol_entry_t* entry, size_t* used) {
    size_t tag_used;
    tlv_result_t rc = tlv_ber_read_identifier(data + offset, size - offset, &entry->tag, &tag_used);
    if (rc != TLV_OK) return rc;
    if (offset + tag_used == size) return TLV_ERR_TRUNCATED;
    entry->requested_length = data[offset + tag_used];
    *used = tag_used + 1;
    return TLV_OK;
}

tlv_result_t tlv_dol_read(const uint8_t* data, size_t size, const tlv_dol_limits_t* limits,
                          tlv_dol_visit_fn visit, void* context, tlv_diagnostic_t* diagnostic) {
    size_t offset = 0, count = 0;
    if (!limits) limits = &tlv_dol_default_limits;
    if ((!data && size) || !visit) return unlocated(TLV_ERR_NULL_ARG, diagnostic);
    while (offset < size) {
        tlv_dol_entry_t entry;
        size_t used;
        tlv_result_t rc;
        if (count == limits->max_entries) return fail(TLV_ERR_LIMIT, offset, diagnostic);
        rc = read_entry(data, size, offset, &entry, &used);
        if (rc != TLV_OK) return fail(rc, offset, diagnostic);
        rc = visit(&entry, count, context);
        if (rc != TLV_OK) return fail(rc, offset, diagnostic);
        ++count;
        offset += used;
    }
    return TLV_OK;
}

/* Fills one entry's output segment (exactly entry->requested_length bytes,
 * already known to fit within the caller's capacity) by probing resolve for
 * presence/length/format and then, per EMV Book 3 5.4, either zero-filling
 * it (unavailable), padding the value with zeros on the side its format
 * dictates (shorter than requested), or dropping bytes from that same side
 * (longer than requested) before copying what remains. */
static tlv_result_t produce_entry(const tlv_dol_entry_t* entry, size_t index,
                                  tlv_dol_resolve_fn resolve, void* context,
                                  const tlv_dol_limits_t* limits, uint8_t* segment,
                                  size_t dol_offset, tlv_diagnostic_t* diagnostic) {
    size_t available_length = 0;
    tlv_dol_format_t format = TLV_DOL_FORMAT_BINARY;
    int absent = 0;
    tlv_result_t rc =
        resolve(entry, index, 0, NULL, 0, &available_length, &format, &absent, context);
    if (rc != TLV_OK) return fail(rc, dol_offset, diagnostic);
    if (absent) {
        memset(segment, 0, entry->requested_length);
        return TLV_OK;
    }
    if (available_length > limits->max_value_length)
        return fail(TLV_ERR_LIMIT, dol_offset, diagnostic);
    if (format != TLV_DOL_FORMAT_BINARY && format != TLV_DOL_FORMAT_NUMERIC)
        return fail(TLV_ERR_INVALID_ARG, dol_offset, diagnostic);

    if (available_length <= entry->requested_length) {
        size_t pad = entry->requested_length - available_length;
        size_t prefix = format == TLV_DOL_FORMAT_NUMERIC ? pad : 0;
        size_t suffix = pad - prefix;
        memset(segment, 0, prefix);
        memset(segment + prefix + available_length, 0, suffix);
        if (available_length) {
            rc = resolve(entry, index, 0, segment + prefix, available_length, &available_length,
                         &format, &absent, context);
            if (rc != TLV_OK) return fail(rc, dol_offset, diagnostic);
        }
    } else {
        size_t skip =
            format == TLV_DOL_FORMAT_NUMERIC ? available_length - entry->requested_length : 0;
        rc = resolve(entry, index, skip, segment, entry->requested_length, &available_length,
                     &format, &absent, context);
        if (rc != TLV_OK) return fail(rc, dol_offset, diagnostic);
    }
    return TLV_OK;
}

tlv_result_t tlv_dol_write(const uint8_t* dol, size_t dol_size, uint8_t* data, size_t capacity,
                           const tlv_dol_limits_t* limits, tlv_dol_resolve_fn resolve,
                           void* context, size_t* written, tlv_diagnostic_t* diagnostic) {
    size_t offset = 0, count = 0, total = 0;
    if (!limits) limits = &tlv_dol_default_limits;
    if ((!dol && dol_size) || !written || (!data && capacity) || (!resolve && data))
        return unlocated(TLV_ERR_NULL_ARG, diagnostic);
    if (limits->max_value_length > TLV_DOL_MAX_VALUE_LENGTH)
        return unlocated(TLV_ERR_LIMIT, diagnostic);

    while (offset < dol_size) {
        tlv_dol_entry_t entry;
        size_t used;
        tlv_result_t rc;
        if (count == limits->max_entries) return fail(TLV_ERR_LIMIT, offset, diagnostic);
        rc = read_entry(dol, dol_size, offset, &entry, &used);
        if (rc != TLV_OK) return fail(rc, offset, diagnostic);
        if (data) {
            if (total + entry.requested_length > capacity)
                return fail(TLV_ERR_BUFFER_TOO_SHORT, offset, diagnostic);
            rc = produce_entry(&entry, count, resolve, context, limits, data + total, offset,
                               diagnostic);
            if (rc != TLV_OK) return rc;
        }
        total += entry.requested_length;
        ++count;
        offset += used;
    }
    *written = total;
    return TLV_OK;
}
