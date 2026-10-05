// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
package opentlv

import (
	"github.com/marekcingel/OpenTLV/bindings/go/internal/capi"
	"runtime"
	"sync"
)

// QueryType identifies a closed native expression or binding category.
type QueryType int

const (
	QueryNodes QueryType = iota
	QueryBoolean
	QueryInteger
	QueryBytes
	QueryString
)

// ProgramError preserves Query spans, named limits, codec and original Reader detail.
type ProgramError struct {
	StatusError
	Kind                                 int
	Begin, End, SourceOffset, Configured uint64
	HasSourceOffset                      bool
	Expected, Limit                      string
	Codec                                int
	Reader                               Diagnostic
}

func (e *ProgramError) Unwrap() error { return e.StatusError }
func programError(code capi.Code, d capi.ProgramDiagnostic) error {
	if code == capi.OK {
		return nil
	}
	return &ProgramError{StatusError: StatusError{code: code}, Kind: d.Kind,
		Begin: d.Begin, End: d.End, SourceOffset: d.SourceOffset, HasSourceOffset: d.HasSourceOffset,
		Configured: d.Configured, Expected: d.Expected, Limit: d.Limit, Codec: d.Codec, Reader: publicDiagnostic(d.Reader)}
}

// ProgramOptions declares immutable compile-time names, types and explicit bounds.
// Format must be valid; Optimize is an explicit choice, including in a zero options value.
type ProgramOptions struct {
	Format                                                                Format
	Variables                                                             map[string]QueryType
	Names                                                                 map[string][]byte
	Optimize                                                              bool
	MaxText, MaxTokens, MaxNesting, MaxStates, MaxPattern, MaxResolvedTag int
}
type programState struct {
	mutex  sync.Mutex
	native *capi.Program
	format Format
}

// QueryProgram owns an immutable C program. Close prevents new executions; existing
// independent executions retain their own native reference. Copies share Close state.
type QueryProgram struct{ state *programState }

// CompileQuery delegates full syntax, typing and optimization to C, including embedded NUL diagnostics.
func CompileQuery(text string, options ProgramOptions) (*QueryProgram, error) {
	return buildProgram([]byte(text), options, false)
}

// LoadQuery validates and owns a copy of a same-release internal image with original compile options.
func LoadQuery(image []byte, options ProgramOptions) (*QueryProgram, error) {
	return buildProgram(image, options, true)
}
func buildProgram(data []byte, options ProgramOptions, image bool) (*QueryProgram, error) {
	if !options.Format.Valid() {
		return nil, programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	variables := map[string]int{}
	for name, kind := range options.Variables {
		variables[name] = int(kind)
	}
	native, code, diag := options.Format.native.CompileProgram(data, capi.ProgramOptions{Variables: variables, Names: options.Names,
		Optimize: options.Optimize, MaxText: options.MaxText, MaxTokens: options.MaxTokens, MaxNesting: options.MaxNesting,
		MaxStates: options.MaxStates, MaxPattern: options.MaxPattern, MaxResolvedTag: options.MaxResolvedTag}, image)
	if err := programError(code, diag); err != nil {
		return nil, err
	}
	result := &QueryProgram{state: &programState{native: native, format: options.Format}}
	return result, nil
}

// Close releases this program reference, once. It is nil-safe.
func (p *QueryProgram) Close() {
	if p == nil || p.state == nil {
		return
	}
	p.state.mutex.Lock()
	defer p.state.mutex.Unlock()
	if p.state.native != nil {
		p.state.native.Close()
		p.state.native = nil
	}
	runtime.SetFinalizer(p, nil)
}
func (p *QueryProgram) lock() error {
	if p == nil || p.state == nil {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	p.state.mutex.Lock()
	if p.state.native == nil {
		p.state.mutex.Unlock()
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	return nil
}

// Info copies all native compiler resource requirements; its map can be modified independently.
func (p *QueryProgram) Info() (map[string]uint64, error) {
	if err := p.lock(); err != nil {
		return nil, err
	}
	defer p.state.mutex.Unlock()
	return p.state.native.Info(), nil
}

// Variables copies unique referenced names/types; unused declarations are excluded.
func (p *QueryProgram) Variables() (map[string]QueryType, error) {
	if err := p.lock(); err != nil {
		return nil, err
	}
	defer p.state.mutex.Unlock()
	values, code := p.state.native.Variables()
	result := map[string]QueryType{}
	for name, kind := range values {
		result[name] = QueryType(kind)
	}
	return result, programError(code, capi.ProgramDiagnostic{})
}

// Format returns canonical Query spelling from C.
func (p *QueryProgram) Format() (string, error) { return p.render(false) }

// Explain returns implementation-specific native plan details.
func (p *QueryProgram) Explain() (string, error) { return p.render(true) }
func (p *QueryProgram) render(explain bool) (string, error) {
	if err := p.lock(); err != nil {
		return "", err
	}
	defer p.state.mutex.Unlock()
	value, code := p.state.native.Render(explain)
	return value, programError(code, capi.ProgramDiagnostic{})
}

// Image returns a copied version-limited native-layout image, not persistent serialization.
func (p *QueryProgram) Image() ([]byte, error) {
	if err := p.lock(); err != nil {
		return nil, err
	}
	defer p.state.mutex.Unlock()
	return p.state.native.Image(), nil
}

// QueryLimits bounds all published nodes, nesting and charged native work.
type QueryLimits struct{ Depth, Nodes, Work int }

// DefaultQueryLimits returns bounded wrapper convenience limits; callers can replace them explicitly.
func DefaultQueryLimits() QueryLimits { return QueryLimits{Depth: 64, Nodes: 1024, Work: 100000000} }

// QueryExecution is mutable exclusive state. Serialize access; it copies windows and
// bindings into C memory, and returns owned Go snapshots. Close is deterministic.
type QueryExecution struct {
	native     *capi.ProgramExecution
	program    *programState
	document   *Document
	busy       bool
	resultType QueryType
}

// Execution chooses bounded S0/S1 or explicit retained S0-S2/D storage, without backend fallback.
func (p *QueryProgram) Execution(limits QueryLimits, retained bool) (*QueryExecution, error) {
	if err := p.lock(); err != nil {
		return nil, err
	}
	defer p.state.mutex.Unlock()
	native, code := p.state.native.Execution(limits.Depth, limits.Nodes, limits.Work, retained)
	if code != capi.OK {
		return nil, programError(code, capi.ProgramDiagnostic{})
	}
	q := &QueryExecution{native: native, program: p.state, resultType: QueryType(p.state.native.Info()["result_kind"])}
	runtime.SetFinalizer(q, func(value *QueryExecution) { _ = value.Close() })
	return q, nil
}
func (q *QueryExecution) check() error {
	if q == nil || q.native == nil || q.busy || (q.document != nil && !q.document.valid()) {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	return nil
}

// Close releases workspace, pinned C windows and native program reference. Callback reentry is rejected.
func (q *QueryExecution) Close() error {
	if q == nil || q.native == nil {
		return nil
	}
	if q.busy {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	q.program.mutex.Lock()
	defer q.program.mutex.Unlock()
	q.native.Close()
	q.native = nil
	q.document = nil
	runtime.SetFinalizer(q, nil)
	return nil
}

// Reset clears terminal/suspended state, bindings and retained windows/snapshot.
func (q *QueryExecution) Reset() error {
	if q == nil || q.native == nil || q.busy {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	code := q.native.Reset()
	if code == capi.OK {
		q.document = nil
	}
	return programError(code, capi.ProgramDiagnostic{})
}

// SetInput copies an initial or legally replaced complete-extent window. Old bytes remain pinned until reset/close.
func (q *QueryExecution) SetInput(data []byte, discard int, final bool) error {
	if err := q.check(); err != nil {
		return err
	}
	return programError(q.native.SetInput(data, discard, final), capi.ProgramDiagnostic{})
}

// QueryValue is a tagged owning scalar. Type distinguishes false, zero and empty spans.
type QueryValue struct {
	Type    QueryType
	Boolean bool
	Integer int64
	Bytes   []byte
	String  string
}

// Bind copies a typed integer/bytes/UTF-8 string before input; it never interpolates text.
func (q *QueryExecution) Bind(name string, value QueryValue) error {
	if err := q.check(); err != nil {
		return err
	}
	data := value.Bytes
	if value.Type == QueryString {
		data = []byte(value.String)
	}
	code, diag := q.native.Bind(name, int(value.Type), value.Integer, data)
	return programError(code, diag)
}

// QueryMatch owns copied node bytes and traversal metadata.
type QueryMatch struct {
	Element       Element
	Depth, Offset uint64
	Constructed   bool
}

// QueryVisit controls callback continuation through the C engine.
type QueryVisit int

const (
	QueryContinue QueryVisit = iota
	QueryStop
	QueryVisitorError
)

// Visit emits ordered matches; STOP/NEED_MORE_DATA preserve continuation. Panics resume only after C returns.
func (q *QueryExecution) Visit(visitor func(QueryMatch) QueryVisit) error {
	if err := q.check(); err != nil {
		return err
	}
	if visitor == nil {
		return programError(capi.NullArg, capi.ProgramDiagnostic{})
	}
	q.busy = true
	defer func() { q.busy = false }()
	code, diag := q.native.Visit(func(match capi.ProgramMatch) int {
		return int(visitor(QueryMatch{Element: NewElement(match.Tag, match.Value), Depth: match.Depth, Offset: match.Offset, Constructed: match.Constructed}))
	})
	return programError(code, diag)
}

// Next pulls one owned Tree match, returning ErrEndOfBuffer at final exhaustion.
func (q *QueryExecution) Next() (QueryMatch, error) {
	if q == nil || q.resultType != QueryNodes {
		return QueryMatch{}, programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	var result QueryMatch
	found := false
	err := q.Visit(func(match QueryMatch) QueryVisit { result = match; found = true; return QueryStop })
	if err == nil && !found {
		err = programError(capi.EndOfBuffer, capi.ProgramDiagnostic{})
	}
	return result, err
}

// Exists drains by default; early success leaves explicit partial validation coverage.
func (q *QueryExecution) Exists(early bool) (bool, error) {
	if err := q.check(); err != nil {
		return false, err
	}
	found, code, diag := q.native.Exists(early)
	return found, programError(code, diag)
}

// Info reports deterministic work counters and structural validation coverage.
func (q *QueryExecution) Info() (map[string]uint64, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	value, code := q.native.Info()
	return value, programError(code, capi.ProgramDiagnostic{})
}

// Context selects a relative zero-based preorder identity on fresh execution.
func (q *QueryExecution) Context(ordinal int) error {
	if err := q.check(); err != nil {
		return err
	}
	if ordinal < 0 {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	return programError(q.native.Control(ordinal, false), capi.ProgramDiagnostic{})
}

// Pruning explicitly permits proven skipped subtrees with partial validation coverage.
func (q *QueryExecution) Pruning(enabled bool) error {
	if err := q.check(); err != nil {
		return err
	}
	return programError(q.native.Control(-1, enabled), capi.ProgramDiagnostic{})
}

// Result copies a finalized scalar; node programs use Next/NextDocument.
func (q *QueryExecution) Result() (QueryValue, error) {
	if err := q.check(); err != nil {
		return QueryValue{}, err
	}
	kind, number, data, code := q.native.Result()
	if code == capi.OK && QueryType(kind) == QueryNodes {
		code = capi.InvalidArg
	}
	return QueryValue{Type: QueryType(kind), Boolean: number != 0, Integer: number, Bytes: data, String: string(data)}, programError(code, capi.ProgramDiagnostic{})
}

// EvaluateDocument finalizes a retained execution against a Document revision.
// Negative capacity explicitly measures the canonical snapshot; nonnegative capacity is a hard bound.
func (q *QueryExecution) EvaluateDocument(document *Document, context Node, valueCapacity int) error {
	if err := q.check(); err != nil {
		return err
	}
	if !document.valid() {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	if context.owner != nil && (!context.Valid() || context.owner.documentState != document.documentState) {
		return programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	if valueCapacity < 0 {
		var code capi.Code
		valueCapacity, code = document.native.Encode(document.format.native, nil, true)
		if code != capi.OK {
			return programError(code, capi.ProgramDiagnostic{})
		}
	}
	q.document = document
	code, diag := q.native.Document(document.native, context.native, valueCapacity)
	return programError(code, diag)
}

// NextDocument returns a checked snapshot handle; edits are rejected by native revision validation.
func (q *QueryExecution) NextDocument() (Node, error) {
	if err := q.check(); err != nil {
		return Node{}, err
	}
	if q.document == nil {
		return Node{}, programError(capi.InvalidArg, capi.ProgramDiagnostic{})
	}
	node, code := q.native.NextDocument()
	if code != capi.OK {
		return Node{}, programError(code, capi.ProgramDiagnostic{})
	}
	return q.document.wrap(node), nil
}
