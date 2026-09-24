# Using OpenTLV from Python

The `opentlv` package is an experimental Python binding for OpenTLV. It binds
`Reader`, `Writer`, `Document`/`Node`, `Entry`, `Tag`, `Format`,
`LengthSchema`/`StructureSchema` and the `OpenTLVError` exception hierarchy,
plus a narrow `codec` submodule (see [Codec](#codec)). For layout and build
details, see [Python bindings](../development/python.md).

## Setup

Neither package is published to PyPI yet. Install both by path from a
checkout of the repository, in one `pip install` call so the `opentlv`
package's dependency on `opentlv-native` resolves to the local build:

```sh
pip install ./bindings/python/opentlv-native ./bindings/python/opentlv
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

`Reader` is a Python iterator over `Entry` values. Each `Entry` has a `Tag`
and a `value` that is a zero-copy `memoryview` slice of your input.
Constructed entries are not expanded automatically; create a new `Reader`
over `entry.value` to descend.

```python
import opentlv

data = bytes([0x01, 0x02, 0xAA, 0xBB, 0x02, 0x00])
for entry in opentlv.Reader(data):
    print(entry.tag, bytes(entry.value))
```

`data` may be `bytes`, `bytearray`, `memoryview`, or any other
buffer-protocol object; the reader borrows it rather than copying it, so it
must stay valid and unchanged for as long as the reader or its entries are
used. `Reader(data)` uses `opentlv.Format.DEFAULT`; pass `format=` for
another wire format, for example `opentlv.Reader(data, opentlv.Format.BER)`.

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
object for the value; `write_entry` appends a decoded `Entry`, for example
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

`LengthSchema` is a pure Python per-tag length table (`validate_length` is a
dict lookup and bounds check, so it never calls into C):

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
their constructed bit; the default and fixed-1-byte formats never nest, so
`children` only applies to BER, CER or DER data). `schema.validate()` raises
`SchemaMissingError` for an absent required field, `SchemaError` for other
rule violations (an unknown tag when `allow_unknown` is `False`, too many
occurrences, a kind mismatch), or `InvalidLengthError` for a length failure,
each carrying the failing `offset`.

Runnable version, validating the document `parse.py` reads, and rejecting an
incomplete one:
[validate.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/validate.py)
(`python examples/validate.py`).

## Codec

`opentlv.codec` binds the one concrete value codec the public OpenTLV C API
exports, `tlv_emv_codec_amount`, for EMV format n12 amounts:

```python
from opentlv import codec

codec.encode_amount(12345)            # b"\x00\x00\x00\x01\x23\x45"
codec.decode_amount(b"\x00\x00\x00\x01\x23\x45")  # 12345
```

This does not extend to the rest of Rust's `Codec`/`Value` model (dates,
Track 2, AFL, CVM results, cryptogram info, and so on): the C functions that
decode those (`emv_value_decode`/`emv_value_encode`) are declared only in a
private header under `tlv/src/`, not in `tlv/include/`, so binding them would
mean reimplementing that EMV decoding logic in Python instead of calling
into C for it, unlike every other type this package binds. A `CodecError`
(not an `OpenTLVError` subclass — `tlv_codec_result_t` is a separate error
domain from `tlv_result_t`) carries the raw `tlv_codec_result_t` code as
`.code`.

Runnable version, decoding and encoding an EMV "Amount, Authorised" entry:
[codec.py](https://github.com/marekcingel/OpenTLV/blob/main/bindings/python/opentlv/examples/codec.py)
(`python examples/codec.py`).

## Documents

`Reader` and `Writer` are zero-copy and never allocate; `Document` is a
separate, allocating convenience layer for changing an existing message. It
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
until it is erased, its value is replaced, or its document is closed or
freed; using it afterwards is the same use-after-free hazard the C API
itself has, not something this binding guards against.

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

`Reader` yields entries until the first error, then raises `StopIteration` on
every further call instead of retrying: the underlying C reader does not
advance past malformed input.

## Relationship to the C API

`opentlv-native` (imported as `opentlv_native`) is a native extension written
directly against the CPython C API (no pybind11, cffi or Cython) and the
CPython Limited API, declaring and calling the public OpenTLV C API;
`opentlv` wraps it and contains no C API calls of its own, the same split as
the Rust `opentlv-native`/`opentlv` crates. `opentlv-native` exposes element
parsing (`tlv_read_diag`) and encoding (`tlv_write_diag`) as two stateless
calls, `read(data, offset, format)` and `write(buffer, offset, tag, value,
format)`; `opentlv.Reader` and `opentlv.Writer` keep their position in pure
Python and call them repeatedly, the same sequential behavior
`tlv_reader_next()`/`tlv_writer_write()` give other bindings, without needing
to represent the C `tlv_reader_t`/`tlv_writer_t` structs on the Python side.
Unlike the C writer, which reports `TLV_ERR_BUFFER_TOO_SHORT` for a
caller-provided buffer that is too small, `opentlv.Writer` owns a growable
`bytearray` and retries once after growing it to the exact required size
(`required` on the resulting diagnostic), the same size
`tlv_encoded_size()`/`opentlv.encoded_size()` reports. `StructureSchema`
serializes its Python-owned rules (including nested `children` schemas) into
an ephemeral C rule tree for the duration of one `structure_validate()` call,
built and freed with plain `malloc`/`free`, rather than keeping a persistent
native handle across calls the way it would for a schema reused many times;
`LengthSchema` needs no such call at all, since its lookup and bounds check
carry no wire-format semantics worth delegating to C. `codec.decode_amount`/
`encode_amount` wrap `tlv_codec_decode`/`tlv_codec_encode` directly, passed
the public `tlv_emv_codec_amount` descriptor. `opentlv.Document` wraps a
`tlv_document_t*` in a `PyCapsule` that frees it (`tlv_document_free()`) when
the capsule is garbage collected or `close()` drops Python's only reference
to it; `opentlv.Node` wraps a borrowed `tlv_node_t*` as a plain integer,
which needs no capsule of its own since nodes are freed with their document,
not individually, and holds a reference to its `Document` so the capsule
stays alive for as long as a node from it is reachable. This completes every
type in the [language bindings conceptual
model](../concepts/bindings.md) this package's scope covers.
