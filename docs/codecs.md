# C value codecs

`tlv/codec.h` defines `tlv_codec_t`, an optional pair of decode and encode
callbacks with a borrowed, immutable context pointer. Codecs convert raw value
bytes and application-defined C representations. They do not receive tags,
formats, readers, or writers. Applications choose and invoke codecs explicitly;
reading an element never invokes one automatically.

Each codec documents the type and alignment of its representation. Decode takes
raw bytes plus a caller-owned destination object and its capacity in bytes.
Encode takes a C object and its size in bytes plus a caller-owned byte buffer.
No heap allocation or registration is required. A missing callback reports
`TLV_CODEC_ERR_UNSUPPORTED` for that direction.

For example, an application can define a zero-copy decoder:

```c
#include "tlv/codec.h"
#include "tlv/types.h"

static tlv_codec_result_t decode_bytes(const void* context,
    const uint8_t* data, size_t size, void* value, size_t capacity)
{
    tlv_buffer_t* bytes = (tlv_buffer_t*)value;
    (void)context;
    if (capacity < sizeof(*bytes)) return TLV_CODEC_ERR_BUFFER_TOO_SHORT;
    bytes->data = data;
    bytes->length = size;
    return TLV_CODEC_OK;
}

static const tlv_codec_t bytes_codec = {NULL, decode_bytes, NULL};
```

After a successful `tlv_read()`, explicitly convert its value:

```c
tlv_buffer_t bytes;
tlv_codec_result_t result = tlv_codec_decode(&bytes_codec,
    view.value.data, view.value.length, &bytes, sizeof(bytes));
```

The resulting `bytes` borrows the original input. Keep that storage alive and
unmodified while using it. Other codecs can decode into scalars or structs,
including representations containing caller-provided buffers. Callers must
supply the documented type and alignment; the generic interface cannot check
C types. Callbacks must validate lengths and capacities before accessing storage.

For an application-defined encoder, query and encode explicitly:

```c
size_t required, written;
tlv_codec_result_t result = tlv_codec_encode(&my_codec,
    &value, sizeof(value), NULL, 0, &required);
if (result == TLV_CODEC_OK && required <= sizeof(raw)) {
    result = tlv_codec_encode(&my_codec, &value, sizeof(value),
        raw, sizeof(raw), &written);
    /* On success, pass raw and written to tlv_write(). */
}
```

An encode callback must support the `NULL, 0` destination query, validate the
object, and report its exact encoded size without writing. Decode consumes the
entire supplied value. Empty decode input may be `NULL, 0`; the representation
pointer is always required. Input and output must not overlap unless the codec
supports it. On failure destination contents are unspecified and encode's
`written` is zero. The descriptor, context, and buffers remain caller-owned.

`tlv_codec_result_t` and `tlv_codec_strerror()` report conversion errors
independently from parser/writer `tlv_result_t` errors. The existing C++ codec
trait and registry are separate APIs and are unchanged.
