// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

// Package capi contains the private cgo bridge to OpenTLV.
// Its boundary uses Go values so C types cannot escape to the public facade.
package capi

/*
#cgo LDFLAGS: -ltlv
#include <tlv/version.h>
*/
import "C"

// Version copies the linked library's static version string into Go storage.
func Version() string {
	return C.GoString(C.tlv_version_string())
}
