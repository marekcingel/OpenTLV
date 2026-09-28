#include "tlv/builtins/dhcp/options.h"

static const uint8_t identifiers[] = {0,  1,  3,  6,  12, 15, 50, 51, 53,
                                      54, 55, 57, 58, 59, 60, 61, 255};

static const tlv_definition_t definitions[] = {
    {{identifiers + 0, 1}, "Pad"},
    {{identifiers + 1, 1}, "Subnet Mask"},
    {{identifiers + 2, 1}, "Router"},
    {{identifiers + 3, 1}, "Domain Name Server"},
    {{identifiers + 4, 1}, "Host Name"},
    {{identifiers + 5, 1}, "Domain Name"},
    {{identifiers + 6, 1}, "Requested IP Address"},
    {{identifiers + 7, 1}, "IP Address Lease Time"},
    {{identifiers + 8, 1}, "DHCP Message Type"},
    {{identifiers + 9, 1}, "Server Identifier"},
    {{identifiers + 10, 1}, "Parameter Request List"},
    {{identifiers + 11, 1}, "Maximum DHCP Message Size"},
    {{identifiers + 12, 1}, "Renewal Time Value"},
    {{identifiers + 13, 1}, "Rebinding Time Value"},
    {{identifiers + 14, 1}, "Vendor Class Identifier"},
    {{identifiers + 15, 1}, "Client Identifier"},
    {{identifiers + 16, 1}, "End"},
};

const tlv_definition_registry_t tlv_dhcpv4_options = {definitions,
                                                      sizeof(definitions) / sizeof(definitions[0])};
