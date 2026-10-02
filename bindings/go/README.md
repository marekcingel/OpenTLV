# Go binding (experimental)

This module establishes the Go binding architecture (#472) and internal native
bridge (#473). It exposes
`opentlv.Version()` to verify the connection to the canonical C library.
Reader, Writer, Format, Element, Document and error APIs are future work.

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
- Each call builds its descriptor, Fixed context and Reader on the C stack.
  Format configuration is immutable and reusable concurrently. These operations
  allocate no persistent native resources and require no `Close` or finalizer.
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
  native Format pointer is retained in Source. A future Reader facade can retain
  its slice and position in Go and pass each unconsumed window to the bridge.

Public Format/Element, Reader, Writer, Document, Query, Codec and error APIs
remain separate follow-up stories (#474–#479). Bridge operations for owned
Document resources and higher-level capabilities will be added with those
stories, including explicit cleanup for any persistent native allocations.

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
