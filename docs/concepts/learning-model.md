# From bytes to useful data

Prerequisite: complete a [first program](../getting-started/README.md#quick-start)
or inspect bytes with the [CLI](../cli/README.md#first-inspection).

## Element: the data you read

An Element exposes an identifier (Tag) and Value bytes. Its logical length is the
number of Value bytes. For the Fixed input `01 02 48 69`:

```text
01       02           48 69
Tag      wire length  Value: "Hi"
Element: Tag = 01, Value size = 2
```

Format tells Reader how to locate these fields. Some formats omit an explicit
Tag or Length field. Layout records source ranges; it is metadata about the
encoded input, rather than a second representation of Element identity.

## Reader and Writer: process one element at a time

Use Reader to inspect input and Writer to create output. Start with the
[Reader example](../guides/reader.md) or [Writer guide](../guides/writer.md).

```text
input bytes --Reader + Format--> borrowed Element
Element     --Writer + Format--> output bytes
```

Keep input alive and unchanged while using borrowed Tags and Values. Keep
borrowed Format configuration alive for the operations using it. Check each
operation's result before using its output. Reader does no I/O; your application
provides input. Streaming input windows and nested traversal are advanced
options in the Reader guide.

Writer generates destination framing. Re-encoding equivalent content does not
promise identical original bytes. Exact preservation of unchanged source uses
[the explicit source-preservation contract](format-contract.md).

## Document: own and edit a message

Choose [Document](../guides/document.md) when you need to retain or edit data.
It owns an allocating tree instead of borrowing all values from the input.

```text
input --parse--> owned Document --edit--> Document --encode--> output
```

Reader and Document are processing choices, not mandatory consecutive stages.
Their handles and editing rules are explained in the Document guide.

## Optional operations

| Need | Operation | Continue with |
| --- | --- | --- |
| Select elements by path | Query | [Queries](../guides/queries.md) |
| Check permitted composition | Schema | [Schemas](../guides/schemas.md) |
| Interpret Value bytes | Codec | [Codecs](../guides/codecs.md) |
| Explain a failure | Diagnostics | [Diagnostics](../guides/diagnostics.md) |

```text
Element / Document --Query--> selected elements
Element structure  --Schema--> validation result
Value bytes        --Codec--> application value
```

These are optional consumers of shared data, not stages every parser must run.
A Definition registry supplies identifier names; protocol modules may compose
Format, definitions, schemas and codecs without adding policy to generic core.

## Continue at your own depth

Next, [choose a processing API](../guides/processing.md) for your task. Then
[choose a format](../formats/README.md#choose-a-format) matching the wire data.
For detailed lifetimes see [memory ownership](../guides/memory.md); for extension
work see [custom formats](../formats/custom/README.md). The
[architecture overview](architecture.md) explains the complete current model.
[Runtime models](runtime-model.md) describe planned work separately.
