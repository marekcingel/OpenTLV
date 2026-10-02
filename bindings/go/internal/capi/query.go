// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

package capi

/*
#include "bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"strings"
	"unsafe"
)

// Query delegates parsing and document traversal to C and retains no Go pointers.
func (d *Document) Query(text string) ([]Node, Code, OptionalSize) {
	if i := strings.IndexByte(text, 0); i >= 0 {
		return nil, InvalidArg, OptionalSize{Value: uint64(i), Present: true}
	}
	s := C.CString(text)
	defer C.free(unsafe.Pointer(s))
	defer runtime.KeepAlive(d)
	var nodes *unsafe.Pointer
	var count C.size_t
	offset := ^C.size_t(0)
	code := Code(C.go_document_query(d.ptr, s, &nodes, &count, &offset))
	defer C.go_query_free(nodes)
	detail := OptionalSize{Value: uint64(offset), Present: offset != ^C.size_t(0)}
	if code != OK {
		return nil, code, detail
	}
	if uint64(count) > uint64(^uint(0)>>1) {
		return nil, NativeSize, OptionalSize{}
	}
	result := make([]Node, int(count))
	for i, p := range unsafe.Slice(nodes, int(count)) {
		result[i] = Node{p}
	}
	return result, OK, OptionalSize{}
}
