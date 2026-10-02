// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/ad_types.h"

static const uint8_t identifiers[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0A, 0x16, 0x20, 0x21, 0xFF};

static const tlv_definition_t definitions[] = {
    {{identifiers + 0, 1}, "Flags"},
    {{identifiers + 1, 1}, "Incomplete List of 16-bit Service or Service Class UUIDs"},
    {{identifiers + 2, 1}, "Complete List of 16-bit Service or Service Class UUIDs"},
    {{identifiers + 3, 1}, "Incomplete List of 32-bit Service or Service Class UUIDs"},
    {{identifiers + 4, 1}, "Complete List of 32-bit Service or Service Class UUIDs"},
    {{identifiers + 5, 1}, "Incomplete List of 128-bit Service or Service Class UUIDs"},
    {{identifiers + 6, 1}, "Complete List of 128-bit Service or Service Class UUIDs"},
    {{identifiers + 7, 1}, "Shortened Local Name"},
    {{identifiers + 8, 1}, "Complete Local Name"},
    {{identifiers + 9, 1}, "Tx Power Level"},
    {{identifiers + 10, 1}, "Service Data - 16-bit UUID"},
    {{identifiers + 11, 1}, "Service Data - 32-bit UUID"},
    {{identifiers + 12, 1}, "Service Data - 128-bit UUID"},
    {{identifiers + 13, 1}, "Manufacturer Specific Data"},
};

const tlv_definition_registry_t tlv_bluetooth_ad_types = {definitions, sizeof(definitions) /
                                                                           sizeof(definitions[0])};
