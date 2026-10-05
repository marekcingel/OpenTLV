// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
package tests

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	tlv "github.com/marekcingel/OpenTLV/bindings/go"
)

func compiled(t *testing.T, text string, variables map[string]tlv.QueryType) *tlv.QueryProgram {
	t.Helper()
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	p, err := tlv.CompileQuery(text, tlv.ProgramOptions{Format: f, Variables: variables, Optimize: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func execution(t *testing.T, p *tlv.QueryProgram, retained bool) *tlv.QueryExecution {
	t.Helper()
	q, err := p.Execution(tlv.DefaultQueryLimits(), retained)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func TestCompiledProgramTypedBindingsAndImage(t *testing.T) {
	p := compiled(t, "count(//5A[@len >= $min])", map[string]tlv.QueryType{"min": tlv.QueryInteger})
	info, err := p.Info()
	if err != nil || info["variable_slots"] != 1 {
		t.Fatal(info, err)
	}
	image, err := p.Image()
	if err != nil {
		t.Fatal(err)
	}
	f, _ := tlv.Builtin(tlv.BER)
	options := tlv.ProgramOptions{Format: f, Variables: map[string]tlv.QueryType{"min": tlv.QueryInteger}, Optimize: true}
	loaded, err := tlv.LoadQuery(image, options)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	for _, n := range []int{0, 1, len(image) - 1} {
		_, err := tlv.LoadQuery(image[:n], options)
		var detail *tlv.ProgramError
		if !errors.As(err, &detail) {
			t.Fatal("missing bounded image diagnostic", n, err)
		}
	}
	q := execution(t, loaded, true)
	if err := q.Bind("min", tlv.QueryValue{Type: tlv.QueryInteger, Integer: 2}); err != nil {
		t.Fatal(err)
	}
	if err := q.SetInput([]byte{0x5a, 1, 1, 0x5a, 2, 2, 3}, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := q.Visit(func(tlv.QueryMatch) tlv.QueryVisit { t.Fatal("scalar emitted a node"); return tlv.QueryContinue }); err != nil {
		t.Fatal(err)
	}
	value, err := q.Result()
	if err != nil || value.Type != tlv.QueryInteger || value.Integer != 1 {
		t.Fatal(value, err)
	}
}

func TestCompiledStreamingContinuationOwnershipAndReentry(t *testing.T) {
	p := compiled(t, "//5A", nil)
	q := execution(t, p, false)
	input := []byte{0x5a, 1, 9, 0x5a, 1, 8}
	if err := q.SetInput(input[:3], 0, false); err != nil {
		t.Fatal(err)
	}
	input[2] = 99
	first, err := q.Next()
	if err != nil || !bytes.Equal(first.Element.Value(), []byte{9}) {
		t.Fatal(first, err)
	}
	if _, err := q.Next(); !errors.Is(err, tlv.ErrNeedMoreData) {
		t.Fatal(err)
	}
	input[2] = 9
	if err := q.SetInput(input, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := q.Visit(func(match tlv.QueryMatch) tlv.QueryVisit {
		if match.Offset != 3 {
			t.Fatal(match)
		}
		if !errors.Is(q.Reset(), tlv.ErrInvalidArg) || !errors.Is(q.Close(), tlv.ErrInvalidArg) {
			t.Fatal("callback reentry")
		}
		p.Close() // Existing execution keeps its immutable native program alive.
		runtime.GC()
		return tlv.QueryStop
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Next(); !errors.Is(err, tlv.ErrEndOfBuffer) {
		t.Fatal(err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := q.SetInput([]byte{0x5a, 0}, 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Next(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Element.Value(), []byte{9}) {
		t.Fatal("snapshot changed")
	}
}

func TestCompiledCallbackPanicAndPartialCoverage(t *testing.T) {
	q := execution(t, compiled(t, "//5A", nil), false)
	if err := q.SetInput([]byte{0x5a, 0, 0x5a}, 0, true); err != nil {
		t.Fatal(err)
	}
	found, err := q.Exists(true)
	if err != nil || !found {
		t.Fatal(found, err)
	}
	info, err := q.Info()
	if err != nil || info["full_validation"] != 0 || info["finished"] != 0 {
		t.Fatal(info, err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := q.SetInput([]byte{0x5a, 0}, 0, true); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() != "callback panic" {
				t.Fatal("panic lost across C")
			}
		}()
		_ = q.Visit(func(tlv.QueryMatch) tlv.QueryVisit { panic("callback panic") })
	}()
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
}

func TestCompiledDocumentRevisionAndClose(t *testing.T) {
	f, _ := tlv.Builtin(tlv.BER)
	d := document(t, []byte{0x70, 6, 0x5a, 1, 1, 0x5a, 1, 2}, f)
	q := execution(t, compiled(t, "//5A/preceding-sibling::*", nil), true)
	if err := q.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	node, err := q.NextDocument()
	if err != nil || !bytes.Equal(node.Value(), []byte{1}) {
		t.Fatal(node, err)
	}
	if _, err := node.Identity(); err != nil {
		t.Fatal(err)
	}
	if err := node.SetValue([]byte{7}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.NextDocument(); !errors.Is(err, tlv.ErrInvalidArg) {
		t.Fatal("revision", err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := q.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if _, err := q.NextDocument(); !errors.Is(err, tlv.ErrInvalidArg) {
		t.Fatal("closed document", err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
}
