# Using OpenTLV from Python

Start with setup below, then run the [Python quick start](../getting-started/README.md#quick-start)
for input, expected output and the public API. You can use this guide without
studying native C implementation contracts.

The `opentlv` package is an experimental Python binding for OpenTLV. It binds
`Reader`, `Writer`, `Document`/`Node`, `Element`, `Tag`, `Format`,
`LengthSchema`/`StructureSchema` and the `OpenTLVError` exception hierarchy,
plus a narrow `codec` submodule (see [Codec](#codec)). For layout and build
details, see [Python bindings](../development/python.md).

## Setup

`Format.LLDP` selects [LLDP framing](../formats/lldp/README.md) when the native
extension was built with `OPENTLV_LLDP=ON`. It is absent when the option is OFF;
`_opentlv.HAS_LLDP` reports the compiled selection.

The BER, CER and DER presets likewise follow `OPENTLV_FORMAT_BER`,
`OPENTLV_FORMAT_CER` and `OPENTLV_FORMAT_DER`, with corresponding `HAS_BER`,
`HAS_CER` and `HAS_DER` flags. Disabled presets are absent from `Format`.
Without BER, pass an explicit format to Reader, Writer, Document,
`encoded_size()` and schema validation; omitting it raises `ValueError`.
`FixedFormat` remains available for Reader and Writer in every build.
EMV amount functions raise `NotImplementedError` when `OPENTLV_EMV`
is disabled. The Python binding still requires `OPENTLV_DOCUMENT=ON`.

Neither package is published to PyPI yet. Install both by path from a
checkout of the repository, in one `pip install` call so the `opentlv`
package's dependency on `opentlv-core` resolves to the local build:

```sh
pip install ./bindings/python/opentlv-core ./bindings/python/opentlv
```

This requires Python 3.11 or newer, CMake 3.26 or newer and a C99 compiler;
see [Build](../development/python.md#build).

```python
import opentlv

print(opentlv.__version__)
```

Runnable round-trip version:
[quick_start.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/quick_start.py)
(`python examples/quick_start.py` from `bindings/python/opentlv`).

## Reading

`Reader` is a Python iterator over `Element` values. Each `Element` has a `Tag`
and a `value` that is a `memoryview` of retained immutable input storage.
Sequential Reader treats constructed Values as opaque. Use `TreeReader` for
canonical preorder traversal, limits and subtree skipping. Both Readers support
incremental windows and Visitors; `QueryMatcher` adds resumable Query processing.
See the [Reader and Query facade contract](../concepts/bindings.md#rust-and-python-reader-and-query-facades).

```python
import opentlv

data = bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])
for element in opentlv.Reader(data):
    print(element.tag, bytes(element.value))
```

`data` may be `bytes`, `bytearray`, `memoryview`, or any other
buffer-protocol object. Immutable bytes are retained without copying; other
inputs are snapshotted into immutable bytes. Returned views keep their storage
alive across Reader destruction and input replacement. `Reader(data)` uses
`opentlv.Format.BER`; pass `format=` for
another wire format, for example `opentlv.Reader(data, opentlv.Format.BER)`,
or an `opentlv.FixedFormat(tag_size, length_size, byte_order="big")` for a
runtime-configurable fixed-width tag and length (equivalent to the C
`tlv_fixed_format_t`).

Runnable version, parsing a nested BER document and handling truncated
input:
[parse.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/parse.py)
(`python examples/parse.py`).

## Writing

`Writer` encodes into a buffer it owns and grows as needed, so `write` never
fails for lack of space, only for an error the format itself reports (for
example an unsupported tag size).

```python
import opentlv

writer = opentlv.Writer()
writer.write(opentlv.Tag(b"\x50"), b"VISA")
data = writer.bytes()
```

`write` accepts a `Tag` or raw `bytes` for the tag, and any buffer-protocol
object for the value; `write_element` appends a decoded `Element`, for example
one produced by a `Reader`, so reading and re-writing round-trips. Like
`Reader`, `Writer(format=...)` selects the wire format.
`opentlv.encoded_size(tag, value_length, format=...)` computes an element's
encoded size without writing it.

Runnable versions:
[write.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/write.py)
builds a nested BER document bottom-up (`python examples/write.py`);
[writer.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/writer.py)
shows the growable buffer handling a value far larger than its initial
capacity, and a genuine format error (`python examples/writer.py`).

## Validating

`LengthSchema` is a per-tag length table whose lookup and length constraints
delegate to the canonical C Schema API:

```python
from opentlv import LengthRule, LengthSchema, Tag

tag = Tag(b"\x9f\x02")
schema = LengthSchema([LengthRule(tag, min_length=6, max_length=6)])
schema.validate_length(tag, 6)
```

`StructureSchema` validates framing, nesting, lengths, occurrence counts and
child membership against a table of `StructureRule`s, running the C
library's validator (`tlv_schema_validate`):

```python
from opentlv import Format, StructureRule, StructureSchema, Tag

tag = Tag(b"\x9f\x02")
schema = StructureSchema([StructureRule(tag, min_occurs=1, max_occurs=1,
                                         min_length=6, max_length=6)])
schema.validate(data, format=Format.BER)
```

A `StructureRule` is optional (0 to unrestricted occurrences) and accepts any
length, kind and children by default; pass keyword arguments (`min_length`,
`max_length`, `min_occurs`, `max_occurs`, `kind`, `children`) to restrict it,
where Rust's builder methods (`.length()`, `.occurs()`, `.kind()`) become
keyword arguments on the constructor instead. `children` nests another
`StructureSchema` for the value's own elements and implies `Kind.CONSTRUCTED`;
which tags are constructed depends on `format` (BER, CER and DER nest by
their constructed bit; Fixed formats never nest, so
`children` only applies to BER, CER or DER data). `schema.validate()` raises
`SchemaMissingError` for an absent required field, `SchemaError` for other
rule violations (an unknown tag when `allow_unknown` is `False`, too many
occurrences, a kind mismatch), or `InvalidLengthError` for a length failure,
each carrying the failing `offset`.

Runnable version, validating the document `parse.py` reads, and rejecting an
incomplete one:
[validate.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/validate.py)
(`python examples/validate.py`).

## Generic Definition registries

`Definition(tag, name=None)` describes an identifier independently of Schema or
Codec. `DefinitionRegistry(definitions).find(tag)` calls the canonical C lookup
and returns the first matching record or `None`. Records own immutable identifier
bytes and names, so returned definitions survive the registry.

## Codec

`NumberCodec(NumberEncoding.BIG_ENDIAN, width=2)` converts unsigned numeric
Values through C. `LITTLE_ENDIAN` and `BCD` are also supported; BCD requires
`digits` precision. Width zero selects minimal encoding. `decode`, `encode`,
`encoded_size` and `encode_into` expose conversion, measurement and caller-owned
output. Conversion errors raise `codec.CodecError`; integers outside uint64
raise `OverflowError` during representation adaptation.

`opentlv.codec` also binds `tlv_emv_codec_amount` for EMV format n12 amounts:

```python
from opentlv import codec

codec.encode_amount(12345)            # b"\x00\x00\x00\x01\x23\x45"
codec.decode_amount(b"\x00\x00\x00\x01\x23\x45")  # 12345
```

Other public C codecs (dates, Track 2, AFL, CVM results and cryptogram
information, among others) remain binding gaps. They must be exposed by wrapping
the public C descriptors rather than reimplementing their conversion logic.
`codec.CodecError` is separate from `OpenTLVError`, matching C's separate codec
error domain; its `.code` contains the raw `tlv_codec_result_t` value.

Runnable version, decoding and encoding an EMV "Amount, Authorised" element:
[codec.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/codec.py)
(`python examples/codec.py`).

## Documents

`Reader` retains immutable input or snapshots mutable buffers, and `Writer`
uses managed output storage. `Document` is a separate, allocating convenience
layer for changing an existing message. It
parses input into an owned tree of `Node`s that can be searched, changed,
extended and shortened, then encoded again:

```python
from opentlv import Document, Tag

with Document(data) as document:
    node = document.first
    node.value = b"\xcc"                      # replace a value
    document.insert(Tag(b"\x02"), b"\xaa")     # append a new top-level element
    encoded = document.encode()
```

Navigate with `document.first`/`for node in document` (top-level nodes, in
encoding order), `node.first_child`/`for child in node` (a constructed
node's children), `node.next`/`node.parent`, or search with
`document.find(tag, parent=...)`, `node.find(tag)` or
`document.find_path("6F/A5/50")`, a [path query](queries.md) (a `/`-separated
path of hexadecimal tags).
`document.insert(tag, value, parent=..., before=...)` inserts a new element;
assigning `node.value` replaces one. For both, a value of a tag the
document's reader format treats as constructed (BER, CER and DER, by their
constructed bit) is parsed as nested elements, the same way parsing does.
`node.erase()` removes a node and its descendants. Every modification either
succeeds completely or leaves the document unchanged, and raises an
`OpenTLVError` subclass on failure, the same as `Reader`/`Writer`.

A document owns every tag and value it holds — the only part of OpenTLV that
allocates beyond a Python object's own memory — so close it deterministically
with `close()` or a `with` block instead of waiting for garbage collection
when that matters, for example for a large document. A node stays valid
until it or an ancestor is erased, its parent Value is replaced, or its
document is closed. Invalid access raises `ValueError` before native access.
Replacing a node's own Value leaves that node usable; its old children become
invalid only after successful replacement. Unrelated handles remain valid.

Runnable versions:
[document.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/document.py)
replaces a value and appends an element in an existing message
(`python examples/document.py`);
[query.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/query.py)
addresses a deeply nested element by path instead of navigating node by node,
including a malformed query and a query with no match
(`python examples/query.py`).

## Error handling

Every reading or writing failure raises a subclass of `opentlv.OpenTLVError`,
one per C `TLV_ERR_*` code (`BufferTooShortError`, `InvalidLengthError`,
`SchemaError`, and so on), so callers can catch a specific error type or the
base class. `OpenTLVError.code` is the raw result code, and `str(error)` is
the C `tlv_strerror` text. When the C API reports structured diagnostic
detail for the failure, `offset`, `expected`, `actual`, `operation` and `tag`
carry it, for both a `Reader` and a `Writer` failure; `length`, `required`
and `available` carry additional detail only a `Writer` failure reports.
Fields the failure does not report are `None`.

```python
try:
    list(opentlv.Reader(truncated))
except opentlv.BufferTooShortError as error:
    print(f"{error} at offset {error.offset} ({error.operation})")
```

`Reader` yields elements until the first error, then raises `StopIteration` on
every further call instead of retrying: the underlying C reader does not
advance past malformed input.

## Relationship to the C API

`opentlv-core` (imported as `_opentlv`) is a native extension written
directly against the CPython C API (no pybind11, cffi or Cython) and the
CPython Limited API, declaring and calling the public OpenTLV C API;
`opentlv` wraps it and contains no C API calls of its own, the same split as
the Rust `opentlv-sys`/`opentlv` crates. `Reader` and `TreeReader` retain native C cursors for incremental input and
canonical traversal. `Writer` delegates each write to C and updates its Python
position only after success. With `buffer=...`, output capacity is fixed;
without it, the owned bytearray grows on a native capacity diagnostic.
`StructureSchema`
serializes its Python-owned rules (including nested `children` schemas) into
an ephemeral C rule tree for the duration of one `structure_validate()` call,
built and freed with plain `malloc`/`free`, rather than keeping a persistent
native handle across calls the way it would for a schema reused many times;
`LengthSchema` likewise marshals its rules and delegates lookup and length
constraints to `tlv_schema_find` and `tlv_schema_validate_length`. Rule flags
and length multiples use the same C semantics. `codec.decode_amount`/
`encode_amount` wrap `tlv_codec_decode`/`tlv_codec_encode` directly, passed
the public `tlv_emv_codec_amount` descriptor. `opentlv.Document` wraps a
`tlv_document_t*` in a `PyCapsule` that frees it (`tlv_document_free()`) when
the capsule is garbage collected or `close()` drops Python's only reference
to it. `Node` retains its Document and validates shared ownership tokens before
using its internal pointer. This protects aliases and descendants from use after
erasure, replacement or close. Remaining parity gaps are listed in the
[binding capability matrix](../concepts/bindings.md#capability-implementation-matrix).

## Tree measurement, preservation and materialization

`TreeWriter.measure(items, capacity, format, ...)` accepts preorder tuples
`(Element, depth, constructed)`. It calls C measurement and returns the staged
encoded bytes; their length is the exact size. Workspace errors expose
`required_data` and `required_scratch` lower bounds. A retry needs a fresh source.
`Reader.read_source()` results expose `preserve()` and `preserve_into(storage)`;
`Writer.preserve(decoded)` appends the unchanged original representation.
All equality checks and byte copying are performed by C.

`DocumentBuilder(reader)` consumes a fresh TreeReader incrementally.
`DocumentBuilder(reader, next_subtree=True)` consumes only its next subtree.
Call `consume()` until a Document is returned; `NeedMoreDataError` permits
`reader.set_input(...)` and retry. Use a `with` block or `close()` to discard an
unfinished build. Active builders prevent other cursor traversal operations.

`Document.encode(format)` and `Node.encode(format)` support conversion to a
compatible builtin destination Format without changing the stored tree.
`encoded_size_as(format)` measures the same destination encoding.

## Compiled Query

`QueryProgram(text, format=..., variables={"minimum": int}, names=...)` owns an
immutable compiled C program. `QueryProgram.load(image, ...)` validates a
same-release image using its original options; `image()`, `format()` and
`explain()` expose copies or descriptions. `info` reports native requirements.
Declarations accept `int`, `bytes` and `str`; bind actual values through an
independent execution rather than interpolating Query text.

`program.execution(max_depth=..., max_nodes=..., max_work=..., retained=True)`
owns bounded native state. `retained=False` selects S0/S1 storage. Execute through
the public TreeReader pull/Visitor adapter, or evaluate a Document; results,
diagnostics, limits and continuation delegate to C. Match snapshots own their
bytes. Reset separates input/binding lifetimes; callback exceptions require
reset before reuse. Programs and executions support deterministic `close()`.
The [consumer tests](../../bindings/python/opentlv/tests/test_program.py) and
[common corpus runner](../../tests/query/python_facade.py) exercise these APIs.

Arbitrary Query provider callbacks and schema-aware Query edits are not exposed
by this facade; builtin generic codecs and ASN.1 capabilities are selected by
the Format. See the [release requirements](../development/query-release.md).

## Next step

Use [the basic model](../concepts/learning-model.md) to choose borrowed processing
or owned editing, then [processing choices](processing.md) for your next task.
