// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/bluetooth/company_ids.h"

static const uint8_t identifiers[][2] = {
    {0x00, 0x00}, {0x06, 0x00}, {0x4C, 0x00}, {0x59, 0x00}, {0x75, 0x00}, {0xE0, 0x00},
};

static const tlv_definition_t definitions[] = {
    {{identifiers[0], 2}, "Ericsson AB"},
    {{identifiers[1], 2}, "Microsoft"},
    {{identifiers[2], 2}, "Apple, Inc."},
    {{identifiers[3], 2}, "Nordic Semiconductor ASA"},
    {{identifiers[4], 2}, "Samsung Electronics Co. Ltd."},
    {{identifiers[5], 2}, "Google"},
};

const tlv_definition_registry_t tlv_bluetooth_company_ids = {
    definitions, sizeof(definitions) / sizeof(definitions[0])};
