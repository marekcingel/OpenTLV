// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

package opentlv

import (
	"fmt"
	"github.com/marekcingel/OpenTLV/bindings/go/internal/capi"
)

// Named errors support errors.Is, including through processing error wrappers.
// Their native codes are available for compatibility, but are not needed for matching.
var (
	ErrBufferTooShort   = StatusError{code: capi.BufferTooShort}
	ErrInvalidLength    = StatusError{code: capi.InvalidLength}
	ErrNullArg          = StatusError{code: capi.NullArg}
	ErrOutOfMemory      = StatusError{code: capi.OutOfMemory}
	ErrEndOfBuffer      = StatusError{code: capi.EndOfBuffer}
	ErrInvalidTag       = StatusError{code: capi.InvalidTag}
	ErrVisitor          = StatusError{code: capi.Visitor}
	ErrLimit            = StatusError{code: capi.Limit}
	ErrSchema           = StatusError{code: capi.Schema}
	ErrInvalidArg       = StatusError{code: capi.InvalidArg}
	ErrInvalidTagSize   = StatusError{code: capi.InvalidTagSize}
	ErrInvalidByteOrder = StatusError{code: capi.InvalidByteOrder}
	ErrOverflow         = StatusError{code: capi.Overflow}
	ErrInvalidValue     = StatusError{code: capi.InvalidValue}
	ErrUnsupportedType  = StatusError{code: capi.UnsupportedType}
	ErrSchemaMissing    = StatusError{code: capi.SchemaMissing}
	ErrNativeSize       = StatusError{code: capi.NativeSize}
	ErrNeedMoreData     = StatusError{code: capi.NeedMoreData}
)

// Is compares native error identity independently of diagnostic detail.
func (e StatusError) Is(target error) bool {
	switch t := target.(type) {
	case StatusError:
		return e.code == t.code
	case *StatusError:
		return t != nil && e.code == t.code
	}
	return false
}

// OptionalSize distinguishes absent native diagnostic information from zero.
type OptionalSize struct {
	Value   uint64
	Present bool
}

// DiagnosticContext is a copied native layer/key/value context entry.
type DiagnosticContext struct{ Layer, Key, Value string }

// Diagnostic owns a snapshot of C diagnostics. No input or native storage is
// borrowed. Optional fields retain native presence; absent detail is not inferred.
// Reader offsets are absolute in the input, including discarded windows.
// Writer offsets use the coordinate system of the native encoding operation.
// Operation and Severity retain the native enumerated values.
type Diagnostic struct {
	Message                                                   string
	Severity, Operation                                       int
	Offset                                                    uint64
	HasOffset                                                 bool
	Expected, Actual                                          string
	Tag, RawLength                                            []byte
	HasTag, HasRawLength                                      bool
	TagOffset, LengthOffset, ValueOffset                      OptionalSize
	DeclaredLength, Available, EnclosingEnd, Required, Length OptionalSize
	Contexts                                                  []DiagnosticContext
	Path                                                      [][]byte
}

// ParseError describes a native Reader or Document parsing failure.
// Offset is meaningful only when HasOffset is true. Unwrap exposes StatusError.
type ParseError struct {
	Diagnostic
	status StatusError
}

// Error renders the canonical status and the source offset when supplied by C.
func (e *ParseError) Error() string {
	if e.HasOffset {
		return fmt.Sprintf("%s at offset %d", e.status.Error(), e.Offset)
	}
	return e.status.Error()
}

// Unwrap preserves errors.Is and errors.As compatibility with StatusError.
func (e *ParseError) Unwrap() error { return e.status }

// WriteError describes a native measurement, encoding or Tree Writer failure.
type WriteError struct {
	Diagnostic
	status StatusError
}

// Error returns the canonical native failure description.
func (e *WriteError) Error() string { return e.status.Error() }

// Unwrap preserves errors.Is and errors.As compatibility with StatusError.
func (e *WriteError) Unwrap() error { return e.status }

func publicDiagnostic(d capi.Diagnostic) Diagnostic {
	size := func(v capi.OptionalSize) OptionalSize { return OptionalSize{v.Value, v.Present} }
	result := Diagnostic{Message: d.Code.String(), Severity: d.Severity, Operation: d.Operation,
		Offset: d.Offset.Value, HasOffset: d.Offset.Present, Expected: d.Expected, Actual: d.Actual,
		Tag: d.Tag, RawLength: d.RawLength, HasTag: d.HasTag, HasRawLength: d.HasRawLength,
		TagOffset: size(d.TagOffset), LengthOffset: size(d.LengthOffset), ValueOffset: size(d.ValueOffset),
		DeclaredLength: size(d.DeclaredLength), Available: size(d.Available), EnclosingEnd: size(d.EnclosingEnd),
		Required: size(d.Required), Length: size(d.Length), Path: d.Path}
	for _, c := range d.Contexts {
		result.Contexts = append(result.Contexts, DiagnosticContext{c.Layer, c.Key, c.Value})
	}
	return result
}

func parseError(code capi.Code, d capi.Diagnostic, base uint64) error {
	// These fields are positions in the native input window, not byte counts.
	for _, offset := range []*capi.OptionalSize{&d.Offset, &d.TagOffset, &d.LengthOffset, &d.ValueOffset, &d.EnclosingEnd} {
		if offset.Present {
			offset.Value += base
		}
	}
	d.Code = code
	return &ParseError{Diagnostic: publicDiagnostic(d), status: StatusError{code: code}}
}

func writeError(code capi.Code, d capi.Diagnostic) error {
	d.Code = code
	return &WriteError{Diagnostic: publicDiagnostic(d), status: StatusError{code: code}}
}
