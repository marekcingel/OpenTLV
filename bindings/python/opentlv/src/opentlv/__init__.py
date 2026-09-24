"""Python bindings for OpenTLV.

This package wraps ``opentlv_native``, the native extension that registers
the public OpenTLV C API as Python callables. It is infrastructure only: the
idiomatic Reader/Writer API described in the OpenTLV language bindings
conceptual model has not been built on top of it yet.
"""

from opentlv_native import version_string

__version__ = version_string()

__all__ = ["__version__"]
