// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
package tests

import (
	"errors"
	"fmt"
	tlv "github.com/marekcingel/OpenTLV/bindings/go"
	"testing"
)

func TestCanonicalDiagnosticNames(t *testing.T) {
	cases := []struct {
		value fmt.Stringer
		name  string
	}{
		{tlv.ReaderOperationHeader, "header"}, {tlv.WriterOperationEnd, "end"},
		{tlv.QueryErrorKindState, "state"}, {tlv.SchemaIssueMissing, "missing"},
		{tlv.SchemaDefinitionKindComponent, "component"}, {tlv.CodecOperationMeasure, "measure"},
		{tlv.CodecCauseReader, "reader"}, {tlv.CodecViolationUtf8, "utf8"},
		{tlv.SeverityWarning, "warning"}, {tlv.QueryErrorKind(9876), "unknown"},
	}
	for _, c := range cases {
		if got := c.value.String(); got != c.name {
			t.Fatalf("got %q, want %q", got, c.name)
		}
	}
}

func TestQueryCategoryAndCommonEvidenceWithoutReader(t *testing.T) {
	format, err := tlv.Builtin(tlv.BER)
	if err != nil {
		t.Skip("BER disabled")
	}
	_, err = tlv.CompileQuery("/", tlv.ProgramOptions{Format: format})
	var failure *tlv.ProgramError
	if !errors.As(err, &failure) {
		t.Fatal(err)
	}
	if failure.Kind != tlv.QueryErrorKindSyntax || failure.HasReader ||
		failure.Location.Domain != tlv.LocationExpression || !failure.HasOffset {
		t.Fatalf("lost Query evidence: %#v", failure)
	}
}
