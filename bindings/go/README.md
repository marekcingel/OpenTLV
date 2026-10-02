# Go binding (experimental)

This module establishes the Go binding architecture (#472) and internal native
bridge (#473). It exposes
`opentlv.Version()` to verify the connection to the canonical C library.
Public Format and Element APIs are available (#474), along with Reader (#475),
Writer (#476), owned Document (#477), and idiomatic errors with owned diagnostic
snapshots (#478), Document Query and typed generic Value codecs (#479).

The module path is `github.com/marekcingel/OpenTLV/bindings/go`; its package
name is `opentlv`. It requires Go 1.22 or newer, cgo and a compatible C compiler.
Run Go commands from this directory, which contains its own `go.mod`.

## Package boundary

- The root `opentlv` package owns the public, idiomatic Go API.
- `internal/capi` exclusively owns cgo imports, C types, native calls and any
  unsafe pointer conversions. Its Go-facing signatures use Go types.
- `tests/` exercises the public package as a consumer and guards the native
  import boundary.
- `examples/` contains runnable consumer programs.

The internal bridge validates Fixed configuration and selects available native
presets (BER, indefinite BER, DER, CER, EMV, LLDP, Bluetooth LTV, DHCPv4 and NFC
Type 2). It delegates single-element reads, incremental-input status, encoded
size calculation and writes to the canonical C Reader/Writer. Native source
ranges and reader/writer diagnostics are projected into Go values. Disabled
presets return an unsupported status; the bridge contains no wire parser.

### Ownership and lifetime

- Byte slices are borrowed only during a synchronous cgo call. C never retains
  Go pointers across calls. `runtime.KeepAlive` covers conversion of native
  results after the call. Nil and empty slices are supported without indexing
  their first byte; a non-nil empty slice remains distinct where relevant.
- Reader/Writer calls build their descriptor, Fixed context and cursor on the C stack.
  Format configuration is immutable and reusable concurrently. These operations
  allocate no persistent native resources and require no `Close` or finalizer.
  Document instead owns a C-allocated descriptor and Fixed context for its entire
  lifetime, and copies all input before returning. Its finalizer is a fallback;
  use Close for deterministic cleanup.
- Parsed Values, source bytes and source-bound Tags borrow the original Go
  slice, without copying. Returned slices keep its backing array alive. The
  caller must keep those bytes unchanged while results are in use and avoid
  concurrent mutation during calls. Format-supplied Tags (such as LLDP's
  transformed identifier) are copied into Go memory, so no native pointer escapes.
- Diagnostic Tag/raw Length bytes and native text are copied into Go storage.
  Optional diagnostic fields retain their presence flags. The bridge preserves
  C status codes, including end of input and `NEED_MORE_DATA`; public Go errors
  belong to the later error API story.
- Writes borrow caller-provided output storage. Overlap with Tag or Value is
  rejected before entering C. Insufficient capacity reports the required size;
  other encoder failures retain the C buffer-modification contract.
- Source ranges remain relative to the returned element start. No temporary
  native Format pointer is retained in Source. The Reader retains its slice and
  position in Go and passes each unconsumed window to the bridge.

Document owns native allocations and provides explicit cleanup.

## Build and run

Build OpenTLV separately with CMake. The binding does not compile copies of the
C sources or invoke CMake during `go build`. Use matching library and headers,
including CMake-generated `tlv/version.h`, `tlv/export.h` and `tlv/config.h`.

For Linux or macOS, from the repository root:

```sh
cmake -S . -B build/go -DOPENTLV_BUILD_SHARED_LIBS=OFF \
  -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF \
  -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF
cmake --build build/go --target tlv
export CGO_ENABLED=1
export CGO_CPPFLAGS="-I$(pwd)/tlv/include -I$(pwd)/build/go/generated/include -DTLV_STATIC_DEFINE"
export CGO_LDFLAGS="-L$(pwd)/build/go/tlv"
cd bindings/go
go test ./...
GOEXPERIMENT=cgocheck2 go test ./...
go vet ./...
go run ./examples/version
```

For Windows PowerShell, use a GCC/MinGW toolchain compatible with Go cgo
(rather than an MSVC-built library):

```powershell
cmake -S . -B build/go -G "MinGW Makefiles" -DOPENTLV_BUILD_SHARED_LIBS=OFF `
  -DOPENTLV_BUILD_TESTS=OFF -DOPENTLV_BUILD_EXAMPLES=OFF `
  -DOPENTLV_BUILD_CXX=OFF -DOPENTLV_BUILD_CLI=OFF
cmake --build build/go --target tlv
$goRepo = (Get-Location).Path.Replace('\', '/')
$env:CGO_ENABLED = '1'
$env:CC = 'gcc'
$env:CGO_CPPFLAGS = "-I`"$goRepo/tlv/include`" -I`"$goRepo/build/go/generated/include`" -DTLV_STATIC_DEFINE"
$env:CGO_LDFLAGS = "-L`"$goRepo/build/go/tlv`""
Set-Location bindings/go
go test ./...
go vet ./...
go run ./examples/version
```

For another prebuilt library, supply its include and library directories through
`CGO_CPPFLAGS` and `CGO_LDFLAGS`; the bridge links `-ltlv`. Define
`TLV_STATIC_DEFINE` when linking statically. For shared linking, omit that define
and configure the platform's runtime library search path (for example `PATH`
on Windows). The library and compiler must match the Go target architecture.
For a 32-bit MinGW compiler, set `$env:GOARCH = '386'` before the Go commands;
the default `amd64` target needs a 64-bit compiler and library.
After replacing an external library or generated headers, use `go clean -cache`
before rebuilding: Go does not track changes to all external native inputs.

See the [official cgo documentation](https://pkg.go.dev/cmd/cgo) for compiler,
flag and pointer rules.

The Go Bindings workflow runs formatting, tests (including `cgocheck2`), vet and
the version example on Linux with static C libraries, both with default features
and with optional presets and Document disabled. The module introduces no
third-party Go dependencies.

## Future extraction

The module has no dependency on repository-relative C source paths. A future
standalone repository can keep the same public/private boundary and link a
separately distributed C library. Moving to another module path and choosing
independent release versions are separate migration decisions. Until then,
releases of this nested module would use the `bindings/go/` tag prefix.

## Format and Element

`NewFixed(FixedConfig{TagSize: 1, LengthSize: 1, ByteOrder: BigEndian})`
validates immutable configuration through C. `Order` defaults to `TLV` and
`LengthScope` to `ValueLength`; byte order must be explicit. `Builtin(BER)`
selects a linked preset. Disabled or unknown presets return an error, with no
fallback. Both constructors return `(Format, error)`; failed construction and
zero-value Formats are invalid (`Valid()` is false). `StatusError` supports
`errors.As` and preserves the native status number through `Code()`.

`NewElement(tag, value)` borrows the supplied `[]byte` slices. `Tag()` and
`Value()` preserve binary identity without normalization or Value decoding.
Keep borrowed bytes unchanged while results are used. `Clone()` copies Tag,
Value and any raw encoding into independent Go storage, retaining metadata.
Returned slices remain mutable; callers must synchronize any mutation.

`Source()` describes raw encoding where available: `Bytes`, the element's
`Offset` in the enclosing input, and Header/Tag/Length/Value/Trailer ranges
relative to the element start. `Range.Present` distinguishes absent fields from
present empty fields. `FormatTag` identifies a semantic Tag supplied by the
Format rather than borrowed from a wire Tag range. Logical elements created by
`NewElement` have no source bytes or ranges and report offset zero. Reader
populates source metadata; Document preserves an owned whole-input snapshot.
Formats own no native allocations and require no cleanup.

## Reader

`NewReader(data, format)` borrows a complete buffer. Iterate with `Next()`,
retrieve the current view with `Element()`, and check `Err()` after the loop.
Clean EOF is not an error. Invalid Formats produce `StatusError`; native parsing
failures produce `*ParseError` wrapping `StatusError`. A failed read leaves the
cursor unchanged and clears the current element. `Offset()` reports the absolute cursor position; each element has its
own absolute source offset. Retained elements borrow their original input even
after the next read. Use `Clone()` before overwriting that storage. Readers need
no `Close` and must not be used concurrently.

```go
reader := opentlv.NewReader(data, format)
for reader.Next() {
    element := reader.Element()
    fmt.Printf("%X @ %d\n", element.Tag(), element.Offset())
}
if err := reader.Err(); err != nil {
    return err
}
```

`NewIncrementalReader(data, format)` starts with non-final input. When `Next()`
returns false, `NeedsMoreData()` distinguishes a temporary pause from EOF;
`Err()` remains nil during that pause. Call `SetInput(window, discard, final)`
to extend or relocate the contiguous window, optionally removing an already
consumed prefix. The new window must retain all old bytes after that prefix,
followed by any additional input. Prefix identity is a caller precondition.
Offsets remain absolute after discarding. Final input cannot be reopened or
extended; an incomplete final element reports a parse error. An invalid update
leaves the reader unchanged. Terminal parse errors cannot be resumed.

The binding does not buffer an `io.Reader` or assemble chunks automatically.
Callers own window assembly and must preserve storage borrowed by retained
elements. Native failures expose owned diagnostic snapshots through `*ParseError`.

Run the independent Fixed-format example with `go run ./examples/reader`.

## Writer

`NewWriter(format)` allocates output as needed. `NewWriterBuffer(format, buffer)`
uses the entire slice length as fixed output capacity, starting empty.
`WriteElement(tag, value)` writes logical content; `Write(element)` does the
same for an Element and regenerates its framing using the selected Format.
`Measure(tag, value)` delegates exact sizing, including content-dependent
framing, to C. `Size()` and `Bytes()` expose the completed root prefix.

```go
writer := opentlv.NewWriter(format)
if err := writer.WriteElement([]byte{1}, []byte{42}); err != nil {
    return err
}
data := writer.Bytes()
```

`Begin(tag)`, `Value(bytes)`, `WriteElement` and `End()` support staged
construction, including nested parents. Begin requires a constructed identifier
recognized by Format; generic Fixed and other primitive-only Formats reject it.
For example, with BER, Begin([]byte{0x30}) opens a SEQUENCE. Value copies raw
Value bytes without interpretation; WriteElement encodes a child. End closes
through the canonical C Tree Writer. Tags are copied on Begin. Finish checks
that every parent is closed; Bytes excludes all unfinished parents.

Open parents use allocated Go staging storage even with a caller-provided root
buffer. Construction is staged rather than streamed. No native pointer survives
a call, and Writer requires no Close. C owns all wire framing and validation.
Writer is not safe for concurrent use.

Errors leave published output and logical open-parent state unchanged.
A `CapacityError` reports total `Required` and `Available` root buffer sizes;
`errors.As` also obtains its native `StatusError`. Use `SetBuffer` with a
larger slice to copy the completed prefix and retry a failed WriteElement or End.
Input may alias previously returned Bytes because encoding uses independent
temporary storage. Bytes borrows output; keep that storage unchanged while in use.

Document serialization is available through `WriteDocument` (#477).
Run the preset-independent example with `go run ./examples/writer`.

## Document

`Parse(data, format)` copies complete input into the canonical C Document.
`ParseWithOptions` accepts explicit `MaxDepth` and `MaxElements` limits;
zero is a literal limit. Parse uses C defaults. Disabled `OPENTLV_DOCUMENT`
returns an unsupported status rather than a fallback.

Call `defer doc.Close()` after successful parsing. Close is idempotent and
nil-safe. A finalizer is a fallback for forgotten cleanup. Document copies
share ownership; closing one closes all. Document is not safe for concurrent use.
Nodes keep the owning Document alive.

`Elements()` returns roots in encoding order, `Element(index)` selects a root,
and `Count()` includes descendants. Nodes expose `Children()`, `Parent()`,
`Constructed()`, `Tag()`, `Value()` and an `Element()` content snapshot.
Tags and primitive Values are independent Go copies. Constructed Values are
empty; use Children. Invalid nodes return nil from Tag/Value/Children and an
error from Element; `Valid()` checks the handle.

`node.SetValue(bytes)` replaces primitive content or parses replacement
children through C. `node.Erase()` removes a subtree.
`doc.Insert(parent, before, element)` inserts or appends copied content;
zero Nodes select roots and append position. Foreign and stale nodes are
rejected before native access. Every successful edit invalidates all existing
node handles, including unaffected siblings. Reacquire handles after edits.
Failed edits preserve the tree and handles.

`Source()` returns a copy of the original complete input, available until the
first successful edit or Close. The C Document does not store node wire ranges;
node Element snapshots have no Source metadata. `Encode()` regenerates framing
in the original Format, including normalization of non-minimal/indefinite
input. `EncodeAs(format)` uses a compatible destination without remapping Tags.
`writer.WriteDocument(doc)` appends this encoding in the Writer's Format,
including inside an open staged parent. Capacity failures leave Writer unchanged.

Run `go run ./examples/document` with Document enabled. Resumable
Tree Reader/Document Builder integration remains follow-up work.

## Query and Value codecs

`doc.Query("6F/A5/50")` returns all matching `[]Node` in document order from
the current mutable C Document. Paths are exact hexadecimal tags separated by
single slashes. Leading slashes, `//`, wildcards and predicates are rejected by
the C Query parser. No matches returns an empty slice. Successful edits and
Close invalidate query nodes; their previously copied Value snapshots survive.
Query failures return `*QueryError`, support `errors.Is` for native statuses,
and retain the C parser's byte offset in the query text when provided. Document
query traversal supplies no additional diagnostic context.

Typed `Codec[T]` values delegate conversion, validation and encoding measurement
to C. Use `Uint8Codec`, `Uint16BECodec`, `Uint16LECodec`, `Uint32BECodec`,
`Uint32LECodec`, `Int64Codec`, `BytesCodec`, `NumberCodec`, `TextCodec`,
`DigitsCodec`, `IPv4Codec` and `IPv4ListCodec`. Configurations are copied and
validated on use by C. Decode produces owned Go values. Encode returns owned
Value bytes, which can be supplied to NewElement or Node.SetValue.

`NumberCodec` supports uint64 binary BE/LE and packed numeric BCD; `DigitsCodec`
preserves leading zeros and trailing F padding. `TextCodec` explicitly selects
printable ASCII or alphanumeric ASCII and optional fixed width/zero padding.
IPv4 representations use `[4]byte` and `[][4]byte` in network octet order.
The zero Codec is unsupported. Generic codecs remain usable with protocol
components and Document disabled.

Value conversion errors are `CodecError` values in the separate C codec status
domain. Use `errors.Is(err, opentlv.ErrCodecInvalidValue)` or `errors.As` with
`CodecError`. C Value codecs provide no structured diagnostics, so none are
invented. This facade covers generic Value codecs; protocol-specific codecs,
custom native descriptors and application-object Structure codecs are not yet
exposed.

Run `go run ./examples/codec`, and with Document enabled,
`go run ./examples/query` for querying followed by typed Value decoding.

## Errors and diagnostics

Use `errors.Is(err, opentlv.ErrInvalidTag)` (or another named `Err` value)
for stable error matching. Use `errors.As` to obtain `*ParseError`,
`*WriteError`, the existing value `StatusError`, or `CapacityError`.
`StatusError.Code()` remains available for compatibility; callers do not need
native numeric codes. Wrapping with `fmt.Errorf("operation: %w", err)` preserves
matching and structured detail.

Native parsing failures from Reader and `Parse`/`ParseWithOptions` return
`*ParseError`.
Measurement, element encoding and Tree Writer failures return `*WriteError`.
Document encoding also returns `*WriteError`, but the current C Document encoding
API supplies only a status, so its optional detail is absent. Local argument
checks and Document mutation failures may return `StatusError` directly.
Fixed output capacity failures retain the existing `CapacityError` and match
`ErrBufferTooShort`. Clean Reader EOF and incremental `NEED_MORE_DATA` remain
flow control (`Err() == nil`), rather than terminal errors.

Diagnostics own copied byte slices, strings, native contexts (innermost first),
and any native path (outermost first). They remain valid after input mutation or
Document cleanup. `Message` uses the canonical C status description. `Expected`
and `Actual`, severity, operation, Tag and raw Length are projected from C;
Go does not infer missing context. `HasOffset`, `HasTag`, `HasRawLength` and
`OptionalSize.Present` distinguish absent fields from zero or empty values.
Reader offsets, field positions and enclosing end are absolute, including after
`SetInput` discards consumed bytes. Byte counts remain unchanged. Writer offsets
refer to the native encoding operation, including its staged parent workspace.
Schema, Query and Codec context is exposed when supplied by C; this story does
not introduce those processing facades.

```go
if err := reader.Err(); err != nil {
    if errors.Is(err, opentlv.ErrBufferTooShort) {
        fmt.Println("incomplete final input")
    }
    var parseErr *opentlv.ParseError
    if errors.As(err, &parseErr) && parseErr.HasOffset {
        fmt.Printf("parse error at offset %d\n", parseErr.Offset)
    }
}
```

Run `go run ./examples/errors` for a complete example using a generic Fixed
Format; it also works with optional protocol presets and Document disabled.
