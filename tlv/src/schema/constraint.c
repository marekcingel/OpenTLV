#include "tlv/schema/constraint.h"

tlv_result_t tlv_value_constraint_validate(const tlv_value_constraint_t* constraint,
                                           int64_t value) {
    size_t i;
    if (!constraint) return TLV_ERR_NULL_ARG;
    switch (constraint->kind) {
        case TLV_VALUE_CONSTRAINT_NONE: return TLV_OK;
        case TLV_VALUE_CONSTRAINT_RANGE:
            if (constraint->min_value > constraint->max_value || value < constraint->min_value ||
                value > constraint->max_value)
                return TLV_ERR_SCHEMA;
            return TLV_OK;
        case TLV_VALUE_CONSTRAINT_ALLOWED_VALUES:
            if (constraint->allowed_values_count && !constraint->allowed_values)
                return TLV_ERR_SCHEMA;
            for (i = 0; i < constraint->allowed_values_count; ++i)
                if (constraint->allowed_values[i] == value) return TLV_OK;
            return TLV_ERR_SCHEMA;
        default: return TLV_ERR_SCHEMA;
    }
}

const char* tlv_value_constraint_name(const tlv_value_constraint_t* constraint, int64_t value) {
    size_t i;
    if (!constraint || constraint->kind != TLV_VALUE_CONSTRAINT_ALLOWED_VALUES ||
        !constraint->allowed_values || !constraint->allowed_value_names)
        return NULL;
    for (i = 0; i < constraint->allowed_values_count; ++i)
        if (constraint->allowed_values[i] == value) return constraint->allowed_value_names[i];
    return NULL;
}
