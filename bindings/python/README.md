# opentlv (experimental)

Python bindings for [OpenTLV](https://github.com/marekcingel/OpenTLV), a
portable C99 library for reading, writing and validating TLV data.

This package is infrastructure only: `opentlv._opentlv` is a native extension
that calls the public OpenTLV C API directly, currently exposing only the
linked library version. See
[Python bindings](https://marekcingel.github.io/OpenTLV/development/python/)
for build instructions and scope.
