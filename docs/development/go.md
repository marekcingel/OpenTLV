# Go binding development

Use the [Go user guide](../guides/go.md) for Format selection, processing,
ownership and errors. The [binding README](../../bindings/go/README.md)
describes native build integration, the `internal/capi` boundary and extraction
of the nested Go module.

After configuring cgo against matching native headers and library, run from
`bindings/go`:

```sh
gofmt -l .
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
GOEXPERIMENT=cgocheck2 go test -count=1 ./...
```

Formatting passes when `gofmt -l .` prints no filenames. Race detection needs a
supported Go target and C toolchain; CI uses Linux amd64. It checks Go memory
accesses, while `cgocheck2` checks the Go/C pointer boundary. Neither replaces
native C sanitizer coverage.

The [Go workflow](../../.github/workflows/go.yml) tests default and minimal
native configurations, with optional presets and Document disabled in the
latter. It runs formatting, vet, tests, race checks, `cgocheck2` and applicable
public examples. Document and Query examples require Document; generic Reader,
Writer, errors and codecs remain usable without protocol components.

Keep cgo, unsafe access and native handles inside `internal/capi`. Consumer
examples use only the public package and standard library; architecture tests
enforce that boundary. New capabilities should update the
[binding matrix](../concepts/bindings.md), [example inventory](../guides/examples.md)
and documentation inventories in the same change.
