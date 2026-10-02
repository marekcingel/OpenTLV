# Choose a processing API

Choose according to input lifetime, nesting and whether data must be edited.
All paths use the same Format and canonical C execution engine. A Schema or
Codec is optional: unknown Values can stay opaque.

## Read, select or edit

| API | Storage and allocation in C | Input and nesting | Query / mutation | Use it for |
| --- | --- | --- | --- | --- |
| Single-element read | Borrowed input; no allocation | One complete element; no child traversal | Caller can inspect the Tag; no mutation | Decode at a known boundary |
| Sequential Reader | Borrowed input; no allocation | Adjacent complete Elements; resumable contiguous windows | Flat Visitor; no mutation | Records, options and root streams |
| Tree Reader | Borrowed input and caller-owned frames; no allocation | Preorder items or balanced events; resumable windows, depth/count limits and subtree skip | Borrowed Query matcher; no mutation | Pull nested data with explicit control |
| Visitor | Temporary borrowed views; caller's Reader/frames | Push adapter over sequential or Tree Reader; STOP preserves continuation | Query can filter tree visits; no mutation | Process each item in a callback |
| Borrowed Query | Query owns its parsed path; matcher uses traversal state | Tree Reader or complete-buffer convenience; retain matcher across pauses | Select matching views; no mutation | Extract fields without materializing a tree |
| Document | Owns copied Tags/Values and nodes; allocates | Complete parse or resumable Document Builder fed by Tree Reader | Node traversal, Query, insert/erase/replace | Retain and edit data independently of input |

See [Reader and traversal](reader.md), [Query](queries.md),
[Document](document.md) and [memory ownership](memory.md). Managed bindings may
copy views or allocate convenience storage; their
[capability and ownership reference](../concepts/bindings.md) states differences.

Resumable reading publishes complete Elements, not partial headers or Values.
The caller preserves the unconsumed suffix and assembles a contiguous window
containing the next complete element. Keep all bytes borrowed by retained
results alive and unchanged, even after discarding them from the active window.
Tree traversal needs the selected Format to classify constructed identifiers;
it does not automatically choose a different child Format.

## Write or regenerate

| API | Storage and allocation in C | Nesting and publication | Use it for |
| --- | --- | --- | --- |
| Single-element write | Caller output; no allocation | Encodes one logical Element; its Value is opaque | Emit at a known boundary |
| Sequential Writer | Caller output; no allocation | Publishes complete adjacent encodings | Build a flat stream or write already assembled Values |
| Writer Builder / C++ scoped construction | Caller output, frames and bounded scratch | Stages open parents; publishes after close; callback result collects failures | Express nested construction ergonomically |
| Tree Writer | Caller output, frames, workspace and optional Tag storage; no hidden allocation | Begin/Element/End operations or structural events; complete parents staged before publication | Transform balanced traversal or control construction explicitly |
| Document encoding | Owned tree plus caller output (binding conveniences may allocate output) | Regenerates framing through Writer/Tree Writer in selected Format | Serialize edited content or a compatible destination Format |

See [Writer and scoped construction](writer.md). Incremental construction means
multiple begin/write/end calls; staged Tree Writer is not a streaming sink.
Insufficient workspace is a capacity error, not implicit growth in C. Output
publication and failure effects follow the individual Writer contracts.

Re-encoding regenerates Tag/Length framing; it does not preserve unusual source
encodings or remap identifier identity. Use explicit
[copy and preservation](copy.md) when an unchanged source representation must
be retained. Schema validates contextual structure; Codec converts Value bytes
to typed values. Neither is a prerequisite for basic Reader/Writer processing.
