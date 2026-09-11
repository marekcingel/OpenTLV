# C core types

Include `<tlv/types.h>` for format-independent types and the common
`tlv_result_t` error codes from `<tlv/error.h>`.

- `tlv_buffer_t` is a read-only, non-owning range (`data`, `length`). A null
  pointer is valid only for an empty range.
- `tlv_tag_t` stores raw tag bytes in wire order and their actual `size`.
  It performs no integer conversion or profile-specific validation.
- `tlv_view_t` stores a tag inline and a borrowed `value` buffer. The caller
  must keep the value storage alive while using the view. Copying the view
  copies the tag and pointer, not the value bytes.

All types support zero initialization and require no dynamic allocation.
An empty tag has size zero; individual formats decide whether it is valid.

Define `TLV_TAG_MAX_SIZE` at compile time to change the default capacity of
8 bytes, for example with the compiler option `-DTLV_TAG_MAX_SIZE=16`
(`/DTLV_TAG_MAX_SIZE=16` with MSVC). The allowed range is 1–255 because the
actual size is stored in a `uint8_t`. Use the same definition in the library
and every consumer: changing capacity changes the layout and ABI of tags and
views. This is a preprocessor setting, not a CMake cache option.

The reader returns `tlv_view_t`: it copies the tag into inline storage and
borrows the value directly from the input buffer. The writer accepts
`tlv_tag_t`, and the C++ layer uses the same type for tags and codec keys.
Tag and length restrictions depend on the selected format; the default format
uses one tag byte, while BER and DER support multi-byte tags.
See [memory ownership and lifetime](memory.md) for shared buffer rules.
