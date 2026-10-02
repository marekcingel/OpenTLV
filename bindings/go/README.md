# Go binding (experimental)

This module establishes the Go binding architecture (#472). It exposes
`opentlv.Version()` to verify the connection to the canonical C library.
Reader, Writer, Format, Element, Document and error APIs are future work.

The module path is `github.com/marekcingel/OpenTLV/bindings/go`; its package
name is `opentlv`. It requires Go 1.22 or newer, cgo and a compatible C compiler.
Run Go commands from this directory, which contains its own `go.mod`.

## Package boundary

- The root `opentlv` package owns the public, idiomatic Go API.
- `internal/capi` exclusively owns cgo imports, C types, native calls and any
  future unsafe pointer conversions. Its Go-facing signatures use Go types.
- `tests/` exercises the public package as a consumer and guards the native
  import boundary.
- `examples/` contains runnable consumer programs.

Future APIs delegate processing to the C engine. They must document ownership,
borrowed input lifetimes and native resource cleanup before exposing resources.
Do not retain Go pointers in C storage without a design satisfying cgo's pointer
rules. The current version operation copies a static C string into Go memory
and retains no pointers or resources.

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

The Go Bindings workflow runs formatting, tests, vet and the version example on
Linux with a static C library. The module introduces no third-party Go dependencies.

## Future extraction

The module has no dependency on repository-relative C source paths. A future
standalone repository can keep the same public/private boundary and link a
separately distributed C library. Moving to another module path and choosing
independent release versions are separate migration decisions. Until then,
releases of this nested module would use the `bindings/go/` tag prefix.
