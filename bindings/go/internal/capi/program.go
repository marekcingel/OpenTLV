// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
package capi

/*
#include "bridge.h"
#include <stdlib.h>
extern int goQueryCallback(uintptr_t handle, tlv_tree_event_t* event);
static tlv_visit_result_t query_callback(const tlv_tree_event_t* event, void* context) {
    return (tlv_visit_result_t)goQueryCallback((uintptr_t)context, (tlv_tree_event_t*)event);
}
static tlv_result_t query_visit_handle(go_query_execution* q, uintptr_t handle, tlv_query_diagnostic_t* d) {
    return go_query_visit(q, query_callback, (void*)handle, d);
}
*/
import "C"
import (
	"bytes"
	"runtime"
	"runtime/cgo"
	"sort"
	"strings"
	"unsafe"
)

// ProgramDiagnostic copies all Query fields and the original Reader diagnostic.
type ProgramDiagnostic struct {
	Kind                                 int
	Begin, End, SourceOffset, Configured uint64
	HasSourceOffset                      bool
	Expected, Limit                      string
	Codec                                int
	Reader                               Diagnostic
}

func programDiagnostic(d C.tlv_query_diagnostic_t, code Code) ProgramDiagnostic {
	return ProgramDiagnostic{Kind: int(d.kind), Begin: uint64(d.begin), End: uint64(d.end),
		SourceOffset: uint64(d.source_offset), HasSourceOffset: d.has_source_offset != 0,
		Configured: uint64(d.configured), Expected: C.GoString(d.expected), Limit: C.GoString(d.limit),
		Codec: int(d.codec), Reader: readerDiagnostic(d.reader, code)}
}

// ProgramOptions owns maps; C borrows only during bounded compilation.
type ProgramOptions struct {
	Variables                                                             map[string]int
	Names                                                                 map[string][]byte
	Optimize                                                              bool
	MaxText, MaxTokens, MaxNesting, MaxStates, MaxPattern, MaxResolvedTag int
}

// Program owns a reference-counted C image. Existing executions survive Close.
type Program struct{ ptr *C.go_query_program }

// CompileProgram compiles bounded bytes or loads a same-release image copy.
func (f Format) CompileProgram(data []byte, options ProgramOptions, image bool) (*Program, Code, ProgramDiagnostic) {
	var config C.tlv_query_compile_options_t
	C.tlv_query_compile_options_init(&config)
	values := []struct {
		input  int
		target *C.size_t
	}{
		{options.MaxText, &config.max_text}, {options.MaxTokens, &config.max_tokens},
		{options.MaxNesting, &config.max_nesting}, {options.MaxStates, &config.max_states},
		{options.MaxPattern, &config.max_pattern}, {options.MaxResolvedTag, &config.max_resolved_tag},
	}
	for _, value := range values {
		if value.input < 0 {
			return nil, InvalidArg, ProgramDiagnostic{}
		}
		if value.input > 0 {
			*value.target = C.size_t(value.input)
		}
	}
	if !options.Optimize {
		config.optimize = 0
	}
	keys := make([]string, 0, len(options.Variables))
	for key := range options.Variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var variables []C.tlv_query_variable_t
	if len(keys) > 0 {
		memory := C.calloc(C.size_t(len(keys)), C.size_t(C.sizeof_tlv_query_variable_t))
		if memory == nil {
			return nil, OutOfMemory, ProgramDiagnostic{}
		}
		defer C.free(memory)
		variables = unsafe.Slice((*C.tlv_query_variable_t)(memory), len(keys))
	}
	defer func() {
		for _, v := range variables {
			C.free(unsafe.Pointer(v.name))
		}
	}()
	for i, key := range keys {
		if strings.IndexByte(key, 0) >= 0 {
			return nil, InvalidArg, ProgramDiagnostic{}
		}
		variables[i].name = C.CString(key)
		variables[i]._type = C.tlv_query_result_kind_t(options.Variables[key])
	}
	if len(variables) > 0 {
		config.variables = &variables[0]
		config.variable_count = C.size_t(len(variables))
	}
	keys = keys[:0]
	for key := range options.Names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var names []C.go_query_name
	if len(keys) > 0 {
		memory := C.calloc(C.size_t(len(keys)), C.size_t(C.sizeof_go_query_name))
		if memory == nil {
			return nil, OutOfMemory, ProgramDiagnostic{}
		}
		defer C.free(memory)
		names = unsafe.Slice((*C.go_query_name)(memory), len(keys))
	}
	defer func() {
		for _, n := range names {
			C.free(unsafe.Pointer(n.name))
			C.free(unsafe.Pointer(n.tag))
		}
	}()
	for i, key := range keys {
		if strings.IndexByte(key, 0) >= 0 {
			return nil, InvalidArg, ProgramDiagnostic{}
		}
		names[i].name = C.CString(key)
		names[i].tag = (*C.uint8_t)(C.CBytes(options.Names[key]))
		names[i].size = C.size_t(len(options.Names[key]))
	}
	var first *C.go_query_name
	if len(names) > 0 {
		first = &names[0]
	}
	var code C.tlv_result_t
	var diagnostic C.tlv_query_diagnostic_t
	var load C.int
	if image {
		load = 1
	}
	ptr := C.go_query_compile(f.config, bytePointer(data), C.size_t(len(data)), &config, first, C.size_t(len(names)), load, &code, &diagnostic)
	runtime.KeepAlive(data)
	runtime.KeepAlive(variables)
	runtime.KeepAlive(names)
	detail := programDiagnostic(diagnostic, Code(code))
	if Code(code) != OK {
		return nil, Code(code), detail
	}
	p := &Program{ptr}
	runtime.SetFinalizer(p, (*Program).Close)
	return p, OK, detail
}
func (p *Program) Close() {
	if p != nil && p.ptr != nil {
		C.go_query_program_free(p.ptr)
		p.ptr = nil
	}
	runtime.SetFinalizer(p, nil)
}

// Info returns copied compiler resource requirements.
func (p *Program) Info() map[string]uint64 {
	defer runtime.KeepAlive(p)
	i := C.go_query_info(p.ptr)
	return map[string]uint64{"program_size": uint64(i.program_size), "program_alignment": uint64(i.program_alignment),
		"scratch_size": uint64(i.scratch_size), "scratch_alignment": uint64(i.scratch_alignment), "states": uint64(i.states),
		"language_version": uint64(i.language_version), "level": uint64(i.level), "result_kind": uint64(i.result_kind),
		"expression_values": uint64(i.expression_values), "instructions": uint64(i.instructions), "variable_slots": uint64(i.variable_slots),
		"codec_scratch": uint64(i.codec_scratch), "pattern_bytes": uint64(i.pattern_bytes), "optimized_states": uint64(i.optimized_states),
		"expression_stack": uint64(i.expression_stack), "candidate_size": uint64(i.candidate_size), "candidate_alignment": uint64(i.candidate_alignment),
		"frame_states": uint64(i.frame_states), "decision_timing": uint64(i.decision_timing), "stable_input_required": uint64(i.stable_input_required),
		"constructed_values_required": uint64(i.constructed_values_required)}
}
func (p *Program) Render(explain bool) (string, Code) {
	defer runtime.KeepAlive(p)
	var size C.size_t
	raw := C.go_query_native(p.ptr)
	fn := func(output *C.char, capacity C.size_t) C.tlv_result_t {
		if explain {
			return C.tlv_query_program_explain(raw, output, capacity, &size)
		}
		return C.tlv_query_program_format(raw, output, capacity, &size)
	}
	if code := Code(fn(nil, 0)); code != OK {
		return "", code
	}
	output := C.malloc(size)
	if output == nil {
		return "", OutOfMemory
	}
	defer C.free(output)
	code := Code(fn((*C.char)(output), size))
	if code != OK {
		return "", code
	}
	return C.GoString((*C.char)(output)), OK
}
func (p *Program) Image() []byte {
	defer runtime.KeepAlive(p)
	i := C.go_query_info(p.ptr)
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(C.go_query_native(p.ptr))), int(i.program_size)))
}
func (p *Program) Variables() (map[string]int, Code) {
	defer runtime.KeepAlive(p)
	raw := C.go_query_native(p.ptr)
	result := map[string]int{}
	for i, count := C.size_t(0), C.tlv_query_program_variable_count(raw); i < count; i++ {
		var info C.tlv_query_variable_info_t
		if code := Code(C.tlv_query_program_variable(raw, i, &info)); code != OK {
			return nil, code
		}
		result[string(unsafe.Slice((*byte)(unsafe.Pointer(info.name)), int(info.name_size)))] = int(info._type)
	}
	return result, OK
}

// ProgramExecution owns stable C descriptors, windows, bindings and bounded workspace.
type ProgramExecution struct{ ptr *C.go_query_execution }

func (p *Program) Execution(depth, nodes, work int, retained bool) (*ProgramExecution, Code) {
	if depth < 0 || nodes <= 0 || work <= 0 {
		return nil, InvalidArg
	}
	var flag C.int
	if retained {
		flag = 1
	}
	var code C.tlv_result_t
	ptr := C.go_query_execution_create(p.ptr, C.size_t(depth), C.size_t(nodes), C.size_t(work), flag, &code)
	runtime.KeepAlive(p)
	if Code(code) != OK {
		return nil, Code(code)
	}
	q := &ProgramExecution{ptr}
	runtime.SetFinalizer(q, (*ProgramExecution).Close)
	return q, OK
}
func (q *ProgramExecution) Close() {
	if q != nil && q.ptr != nil {
		C.go_query_execution_free(q.ptr)
		q.ptr = nil
	}
	runtime.SetFinalizer(q, nil)
}
func (q *ProgramExecution) Reset() Code {
	defer runtime.KeepAlive(q)
	return Code(C.go_query_execution_reset(q.ptr))
}
func (q *ProgramExecution) SetInput(data []byte, discard int, final bool) Code {
	if discard < 0 {
		return InvalidArg
	}
	var flag C.int
	if final {
		flag = 1
	}
	code := Code(C.go_query_input(q.ptr, bytePointer(data), C.size_t(len(data)), C.size_t(discard), flag))
	runtime.KeepAlive(data)
	runtime.KeepAlive(q)
	return code
}
func (q *ProgramExecution) Bind(name string, kind int, number int64, data []byte) (Code, ProgramDiagnostic) {
	if strings.IndexByte(name, 0) >= 0 {
		return InvalidArg, ProgramDiagnostic{}
	}
	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))
	var d C.tlv_query_diagnostic_t
	code := Code(C.go_query_bind(q.ptr, n, C.tlv_query_result_kind_t(kind), C.int64_t(number), bytePointer(data), C.size_t(len(data)), &d))
	runtime.KeepAlive(data)
	runtime.KeepAlive(q)
	return code, programDiagnostic(d, code)
}

// ProgramMatch owns copied node bytes, independent of future windows/reset.
type ProgramMatch struct {
	Tag, Value    []byte
	Depth, Offset uint64
	Constructed   bool
}

func match(event *C.tlv_tree_event_t) ProgramMatch {
	return ProgramMatch{Tag: bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(event.element.tag.data)), int(event.element.tag.size))),
		Value: bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(event.element.value.data)), int(event.element.value.size))), Depth: uint64(event.depth), Offset: uint64(event.offset), Constructed: event.kind == C.TLV_TREE_BEGIN}
}

type queryVisitor struct {
	callback func(ProgramMatch) int
	panic    any
}

//export goQueryCallback
func goQueryCallback(handle C.uintptr_t, event *C.tlv_tree_event_t) (action C.int) {
	state := cgo.Handle(handle).Value().(*queryVisitor)
	defer func() {
		if value := recover(); value != nil {
			state.panic = value
			action = 2
		}
	}()
	return C.int(state.callback(match(event)))
}
func (q *ProgramExecution) Visit(callback func(ProgramMatch) int) (Code, ProgramDiagnostic) {
	state := &queryVisitor{callback: callback}
	handle := cgo.NewHandle(state)
	defer handle.Delete()
	var d C.tlv_query_diagnostic_t
	code := Code(C.query_visit_handle(q.ptr, C.uintptr_t(handle), &d))
	runtime.KeepAlive(q)
	if state.panic != nil {
		panic(state.panic)
	}
	return code, programDiagnostic(d, code)
}
func (q *ProgramExecution) Exists(early bool) (bool, Code, ProgramDiagnostic) {
	var found, flag C.int
	if early {
		flag = 1
	}
	var d C.tlv_query_diagnostic_t
	code := Code(C.go_query_exists(q.ptr, flag, &found, &d))
	runtime.KeepAlive(q)
	return found != 0, code, programDiagnostic(d, code)
}
func (q *ProgramExecution) Info() (map[string]uint64, Code) {
	defer runtime.KeepAlive(q)
	var i C.tlv_query_exec_info_t
	i.struct_size = C.size_t(C.sizeof_tlv_query_exec_info_t)
	code := Code(C.tlv_query_exec_info(C.go_query_exec(q.ptr), &i))
	return map[string]uint64{"elements": uint64(i.elements), "work": uint64(i.work), "skipped_subtrees": uint64(i.skipped_subtrees), "finished": uint64(i.finished), "full_validation": uint64(i.full_validation), "invalid": uint64(i.invalid)}, code
}
func (q *ProgramExecution) Control(ordinal int, pruning bool) Code {
	defer runtime.KeepAlive(q)
	if ordinal < 0 {
		flag := C.int(0)
		if pruning {
			flag = 1
		}
		return Code(C.tlv_query_exec_pruning(C.go_query_exec(q.ptr), flag))
	}
	return Code(C.tlv_query_exec_context(C.go_query_exec(q.ptr), C.size_t(ordinal)))
}
func (q *ProgramExecution) Result() (kind int, number int64, data []byte, code Code) {
	defer runtime.KeepAlive(q)
	var result C.tlv_query_result_t
	code = Code(C.tlv_query_exec_result(C.go_query_exec(q.ptr), &result))
	if code != OK {
		return
	}
	kind = int(result.kind)
	switch kind {
	case 1:
		number = int64(result.boolean)
	case 2:
		number = int64(result.integer)
	case 3, 4:
		if uint64(result.size) > uint64(^uint(0)>>1) {
			code = NativeSize
			return
		}
		data = bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(result.data)), int(result.size)))
	}
	return
}
func (q *ProgramExecution) Document(document *Document, context Node, capacity int) (Code, ProgramDiagnostic) {
	if capacity < 0 {
		return InvalidArg, ProgramDiagnostic{}
	}
	var d C.tlv_query_diagnostic_t
	code := Code(C.go_query_document(q.ptr, document.ptr, context.ptr, C.size_t(capacity), &d))
	runtime.KeepAlive(q)
	runtime.KeepAlive(document)
	return code, programDiagnostic(d, code)
}
func (q *ProgramExecution) NextDocument() (Node, Code) {
	defer runtime.KeepAlive(q)
	var node unsafe.Pointer
	code := Code(C.go_query_document_next(q.ptr, &node))
	return Node{node}, code
}
func (n Node) Identity() uint64 { return uint64(C.go_query_node_identity(n.ptr)) }
