# OpenTLV documentation

Read, write and inspect binary TLV data with C, C++, Rust, Python, Lua, Go,
the `otlv` CLI or WebAssembly tools. Choose your entry point and complete a
small task before learning the deeper contracts.

## Start with your API or tool

| Your entry point | First task | Continue with |
| --- | --- | --- |
| C or C++ | [Build and run the first program](getting-started/README.md) | [C++ examples](guides/cxx-examples.md), [Reader](guides/reader.md) |
| Rust | [Rust setup and usage](guides/rust.md) | [Shared quick start](getting-started/README.md#quick-start) |
| Python | [Python setup and usage](guides/python.md) | [Shared quick start](getting-started/README.md#quick-start) |
| Lua | [Lua setup and usage](guides/lua.md) | [Shared quick start](getting-started/README.md#quick-start) |
| Go | [Go setup and usage](guides/go.md) | [Shared quick start](getting-started/README.md#quick-start) |
| Terminal | [Inspect a small input](cli/README.md#first-inspection) | [CLI commands](cli/README.md#commands) |
| Browser | [TLV playground](playground/index.md) | [WebAssembly integration](development/webassembly.md) |

Binding guides explain their public language APIs; native C interoperability is
an advanced topic in the [binding contracts](concepts/bindings.md).

## Learn progressively

1. [Install or integrate](getting-started/README.md) and run a first example.
2. [Understand Element, Reader/Writer and Document](concepts/learning-model.md).
3. [Choose borrowed processing or owned editing](guides/processing.md).
4. [Read and traverse](guides/reader.md), [write](guides/writer.md),
   [edit](guides/document.md) or [diagnose](guides/diagnostics.md) your data.
5. Add [Query](guides/queries.md), [Schema](guides/schemas.md) or
   [Codec](guides/codecs.md) when the task needs it.
6. Select [wire formats](formats/README.md) and [standard capabilities](formats/support.md).
7. Learn [memory contracts](guides/memory.md), [architecture](concepts/architecture.md)
   and [custom formats](formats/custom/README.md).
8. Explore the planned [runtime model](concepts/runtime-model.md) and [roadmap](../ROADMAP.md).

You can branch directly to a task; this is a suggested order, not required reading.
For complete runnable programs see [executable examples](guides/examples.md).

## Look up exact details

[API reference](reference/README.md) owns exact declarations and behavior.
[Format support](formats/support.md) owns implemented native/tool capabilities;
[binding status](concepts/bindings.md) records language coverage.
[Compiler requirements](reference/compilers.md) and
[component selection](guides/select-components.md) cover integration constraints.
The [roadmap](../ROADMAP.md) owns future plans.

## Contribute

Developer onboarding is separate: start with [Contributing](../CONTRIBUTING.md),
then [development workflow](development/workflow.md),
[documentation conventions](development/documentation-layout.md) and
[the documentation audit](development/documentation-audit.md).

[Changelog](../CHANGELOG.md) ? [Security policy](../SECURITY.md) ? [License](../LICENSE)
