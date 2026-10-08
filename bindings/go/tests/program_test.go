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

func TestQuerySchemaOwnedDiagnosticsAndBounds(t *testing.T) {
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	rules := []tlv.QueryRule{{Context: compiled(t, "//5A", nil), Assertion: compiled(t, "num(.) = 1", nil), Name: "one"}}
	limits := tlv.DefaultQuerySchemaLimits()
	emptyRoot, err := compiled(t, "value(//70)", nil).Execution(tlv.QueryLimits{Depth: 0, Nodes: 1, Work: 10000}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer emptyRoot.Close()
	if err := emptyRoot.EvaluateDocument(document(t, []byte{0x70, 0}, f), tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	value, err := emptyRoot.Result()
	if err != nil || value.Type != tlv.QueryBytes || len(value.Bytes) != 0 {
		t.Fatal(value, err)
	}
	good := []byte{0x70, 3, 0x5a, 1, 1}
	bad := []byte{0x70, 3, 0x5a, 1, 2}
	if err := tlv.ValidateQueryBuffer(rules, good, f, limits); err != nil {
		t.Fatal(err)
	}
	doc := document(t, good, f)
	if err := tlv.ValidateQueryDocument(rules, doc, limits); err != nil {
		t.Fatal(err)
	}
	var detail *tlv.QuerySchemaError
	err = tlv.ValidateQueryBuffer(rules, bad, f, limits)
	if !errors.As(err, &detail) || !errors.Is(err, tlv.ErrSchema) {
		t.Fatal(err)
	}
	if detail.Rule != 0 || detail.Kind != 7 || detail.Field != "one" || !detail.HasOffset || detail.Offset != 2 ||
		!bytes.Equal(detail.Tag, []byte{0x5a}) || len(detail.Path) != 1 || !bytes.Equal(detail.Path[0], []byte{0x70}) ||
		detail.Expected != "contextual Query assertion true" {
		t.Fatalf("lost diagnostic: %+v", detail)
	}
	broken := document(t, bad, f)
	var documentDetail *tlv.QuerySchemaError
	if err := tlv.ValidateQueryDocument(rules, broken, limits); !errors.As(err, &documentDetail) || documentDetail.HasOffset {
		t.Fatal(err)
	}
	_ = broken.Close()
	clear(bad)
	runtime.GC()
	if !bytes.Equal(documentDetail.Path[0], []byte{0x70}) || !bytes.Equal(detail.Tag, []byte{0x5a}) {
		t.Fatal("borrowed diagnostics")
	}
	limits.Contexts = 0
	var limit *tlv.ProgramError
	if err := tlv.ValidateQueryBuffer(rules, good, f, limits); !errors.As(err, &limit) || limit.Limit != "schema-contexts" {
		t.Fatal(err)
	}
	limits = tlv.DefaultQuerySchemaLimits()
	limits.Work = 1
	if err := tlv.ValidateQueryBuffer(rules, good, f, limits); !errors.Is(err, tlv.ErrLimit) {
		t.Fatal(err)
	}
	limits = tlv.DefaultQuerySchemaLimits()
	empty := []tlv.QueryRule{{Context: compiled(t, "//5B", nil), Assertion: compiled(t, "1 = 0", nil)}}
	if err := tlv.ValidateQueryBuffer(empty, good, f, limits); err != nil {
		t.Fatal(err)
	}
	reverse := []tlv.QueryRule{{Context: compiled(t, "//5A[2]", nil), Assertion: compiled(t, "exists(preceding::5A)", nil)}}
	siblings := []byte{0x70, 6, 0x5a, 1, 1, 0x5a, 1, 2}
	if err := tlv.ValidateQueryBuffer(reverse, siblings, f, limits); !errors.Is(err, tlv.ErrUnsupportedType) {
		t.Fatal(err)
	}
	if err := tlv.ValidateQueryDocument(reverse, document(t, siblings, f), limits); err != nil {
		t.Fatal(err)
	}
}

func TestQuerySchemaProviderLifetimeAndDocumentGuards(t *testing.T) {
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	doc := document(t, []byte{0x70, 3, 0x5a, 1, 1}, f)
	context := compiled(t, "//5A", nil)
	var predicate *tlv.QueryProgram
	options := tlv.ProgramOptions{Format: f, Providers: map[tlv.QueryConversion]tlv.QueryProvider{
		tlv.QueryNum: {ID: 201, Decode: func(value []byte, metadata *tlv.QueryMetadata) (tlv.QueryValue, tlv.CodecError) {
			if metadata == nil || !bytes.Equal(metadata.Tag, []byte{0x5a}) {
				t.Error("missing metadata")
			}
			if err := doc.Close(); !errors.Is(err, tlv.ErrInvalidState) {
				t.Error("close allowed", err)
			}
			root, err := doc.Element(0)
			if err != nil {
				t.Fatal(err)
			}
			if err := root.Erase(); !errors.Is(err, tlv.ErrInvalidState) {
				t.Error("mutation allowed", err)
			}
			context.Close()
			predicate.Close()
			runtime.GC()
			return tlv.QueryValue{Type: tlv.QueryInteger, Integer: int64(value[0])}, 0
		}},
	}}
	predicate, err = tlv.CompileQuery("num(.) = 1", options)
	if err != nil {
		t.Fatal(err)
	}
	defer predicate.Close()
	if err := tlv.ValidateQueryDocument([]tlv.QueryRule{{Context: context, Assertion: predicate}}, doc, tlv.DefaultQuerySchemaLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.Encode(); err != nil {
		t.Fatal(err)
	}
	panicOptions := tlv.ProgramOptions{Format: f, Providers: map[tlv.QueryConversion]tlv.QueryProvider{
		tlv.QueryNum: {ID: 202, Decode: func([]byte, *tlv.QueryMetadata) (tlv.QueryValue, tlv.CodecError) { panic("schema provider") }},
	}}
	throwing, err := tlv.CompileQuery("num(.) = 1", panicOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer throwing.Close()
	var failure *tlv.ProgramError
	err = tlv.ValidateQueryDocument([]tlv.QueryRule{{Context: compiled(t, "//5A", nil), Assertion: throwing}}, doc, tlv.DefaultQuerySchemaLimits())
	if !errors.As(err, &failure) || failure.Codec != 3 {
		t.Fatal(err)
	}
	if err := doc.Close(); err != nil {
		t.Fatal(err)
	}
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

func TestQueryCustomProvidersLifetimeImageAndErrors(t *testing.T) {
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	options := tlv.ProgramOptions{Format: f, Optimize: true, Providers: map[tlv.QueryConversion]tlv.QueryProvider{
		tlv.QueryNum: {ID: 101, Decode: func(value []byte, metadata *tlv.QueryMetadata) (tlv.QueryValue, tlv.CodecError) {
			if metadata == nil || metadata.Offset != 0 {
				t.Error("missing metadata")
			}
			return tlv.QueryValue{Type: tlv.QueryInteger, Integer: int64(value[0]) * 10}, 0
		}},
	}}
	p, err := tlv.CompileQuery("num(//5A)", options)
	if err != nil {
		t.Fatal(err)
	}
	image, err := p.Image()
	if err != nil {
		t.Fatal(err)
	}
	if unexpected, err := tlv.LoadQuery(image, tlv.ProgramOptions{Format: f, Optimize: true}); err == nil {
		unexpected.Close()
		t.Fatal("accepted mismatched provider")
	}
	loaded, err := tlv.LoadQuery(image, options)
	if err != nil {
		t.Fatal(err)
	}
	q := execution(t, loaded, true)
	p.Close()
	loaded.Close()
	runtime.GC()
	if err := q.SetInput([]byte{0x5a, 1, 3}, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := q.Visit(func(tlv.QueryMatch) tlv.QueryVisit { return tlv.QueryContinue }); err != nil {
		t.Fatal(err)
	}
	value, err := q.Result()
	if err != nil || value.Integer != 30 {
		t.Fatal(value, err)
	}
	for _, capacity := range []int{3, 2} {
		options.Providers = map[tlv.QueryConversion]tlv.QueryProvider{tlv.QueryText: {ID: 102, MaxResultBytes: capacity,
			Decode: func([]byte, *tlv.QueryMetadata) (tlv.QueryValue, tlv.CodecError) {
				return tlv.QueryValue{Type: tlv.QueryString, String: "a\x00b"}, 0
			}}}
		text, err := tlv.CompileQuery("text(//5A)", options)
		if err != nil {
			t.Fatal(err)
		}
		e := execution(t, text, true)
		text.Close()
		if err := e.SetInput([]byte{0x5a, 0}, 0, true); err != nil {
			t.Fatal(err)
		}
		err = e.Visit(func(tlv.QueryMatch) tlv.QueryVisit { return tlv.QueryContinue })
		if capacity == 2 {
			var failure *tlv.ProgramError
			if !errors.As(err, &failure) || failure.Codec != 2 {
				t.Fatal(err)
			}
		} else {
			value, resultErr := e.Result()
			if err != nil || resultErr != nil || value.String != "a\x00b" {
				t.Fatal(value, err, resultErr)
			}
		}
	}
}

func TestQueryProviderPanicAndReentryDoNotCrossC(t *testing.T) {
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	var active *tlv.QueryExecution
	for _, panicProvider := range []bool{false, true} {
		options := tlv.ProgramOptions{Format: f, Optimize: true, Providers: map[tlv.QueryConversion]tlv.QueryProvider{
			tlv.QueryNum: {ID: 103, Decode: func([]byte, *tlv.QueryMetadata) (tlv.QueryValue, tlv.CodecError) {
				if panicProvider {
					panic("provider panic")
				}
				if err := active.Reset(); err == nil {
					t.Error("allowed callback reentry")
				}
				return tlv.QueryValue{}, tlv.ErrCodecUnsupported
			}},
		}}
		p, err := tlv.CompileQuery("num(//5A)", options)
		if err != nil {
			t.Fatal(err)
		}
		active = execution(t, p, true)
		p.Close()
		if err := active.SetInput([]byte{0x5a, 0}, 0, true); err != nil {
			t.Fatal(err)
		}
		err = active.Visit(func(tlv.QueryMatch) tlv.QueryVisit { return tlv.QueryContinue })
		var failure *tlv.ProgramError
		expected := 4
		if panicProvider {
			expected = 3
		}
		if !errors.As(err, &failure) || failure.Codec != expected {
			t.Fatal(err)
		}
		if err := active.Reset(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueryRawFeedsImmediateRetainedAndMalformed(t *testing.T) {
	p := compiled(t, "//5A", nil)
	for _, retained := range []bool{false, true} {
		q := execution(t, p, retained)
		item, err := q.Feed(tlv.QueryEvent{Kind: tlv.QueryElement, Tag: []byte{0x5a}, Value: []byte{1}, Offset: 7})
		if err != nil {
			t.Fatal(err)
		}
		if retained {
			if item != nil {
				t.Fatal("early retained publication")
			}
		} else if item == nil || item.Offset != 7 {
			t.Fatal(item)
		}
		if err := q.SetInput([]byte{0x5a, 0}, 0, true); !errors.Is(err, tlv.ErrInvalidState) {
			t.Fatal(err)
		}
		if err := q.Finish(); err != nil {
			t.Fatal(err)
		}
		if retained {
			item, err := q.Next()
			if err != nil || item.Offset != 7 {
				t.Fatal(item, err)
			}
			if _, err := q.Next(); !errors.Is(err, tlv.ErrEndOfBuffer) {
				t.Fatal(err)
			}
		}
		if err := q.Reset(); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Feed(tlv.QueryEvent{Kind: tlv.QueryEnd}); !errors.Is(err, tlv.ErrInvalidArg) {
			t.Fatal(err)
		}
		info, err := q.Info()
		if err != nil || info["invalid"] != 1 {
			t.Fatal(info, err)
		}
		if err := q.Reset(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestQueryCompletedDocumentEditRetryAndOverlap(t *testing.T) {
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	wire := []byte{0x70, 6, 0x5a, 1, 1, 0x5a, 1, 2, 0x5a, 1, 3}
	d, err := tlv.Parse(wire, f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p := compiled(t, "//5A", nil)
	q := execution(t, p, true)
	if err := q.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	if applied, err := q.EditDocument(tlv.QueryReplace, nil, []byte{9}, 2); applied != 0 || !errors.Is(err, tlv.ErrBufferTooShort) {
		t.Fatal(applied, err)
	}
	encoded, err := d.Encode()
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatal(encoded, err)
	}
	if applied, err := q.EditDocument(tlv.QueryReplace, nil, []byte{9}, 3); applied != 3 || err != nil {
		t.Fatal(applied, err)
	}
	if _, err := q.NextDocument(); !errors.Is(err, tlv.ErrInvalidState) {
		t.Fatal(err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := q.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	if applied, err := q.EditDocument(tlv.QueryInsertAfter, []byte{0x5b}, []byte{4}, 3); applied != 3 || err != nil {
		t.Fatal(applied, err)
	}
	a := execution(t, compiled(t, "//70 | //5A", nil), true)
	if err := a.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	if applied, err := a.EditDocument(tlv.QueryRemove, nil, nil, 4); applied != 2 || err != nil {
		t.Fatal(applied, err)
	}
	encoded, err = d.Encode()
	if err != nil || !bytes.Equal(encoded, []byte{0x5b, 1, 4}) {
		t.Fatal(encoded, err)
	}
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
		if !errors.Is(q.Reset(), tlv.ErrInvalidState) || !errors.Is(q.Close(), tlv.ErrInvalidState) {
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
	f, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
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
	if _, err := q.NextDocument(); !errors.Is(err, tlv.ErrInvalidState) {
		t.Fatal("revision", err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := q.EvaluateDocument(d, tlv.Node{}, -1); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if _, err := q.NextDocument(); !errors.Is(err, tlv.ErrInvalidState) {
		t.Fatal("closed document", err)
	}
	if err := q.Reset(); err != nil {
		t.Fatal(err)
	}
}

func TestQuerySchemaDiagnosticPathTruncation(t *testing.T) {
	format, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	rules := []tlv.QueryRule{{Context: compiled(t, "//5A", nil), Assertion: compiled(t, "1 = 0", nil)}}
	wire := []byte{0x5a, 0}
	for level := 0; level < 35; level++ {
		tag := byte(0x30)
		if level == 34 {
			tag = 0x70
		}
		wire = append([]byte{tag, byte(len(wire))}, wire...)
	}
	var detail *tlv.QuerySchemaError
	if err := tlv.ValidateQueryBuffer(rules, wire, format, tlv.DefaultQuerySchemaLimits()); !errors.As(err, &detail) {
		t.Fatal(err)
	}
	clear(wire)
	if len(detail.Path) != 32 || detail.PathOmitted != 3 || !bytes.Equal(detail.Path[0], []byte{0x70}) {
		t.Fatalf("lost truncation metadata: %+v", detail)
	}
}
