"""Python bindings for OpenTLV.

This package is a thin wrapper over ``opentlv._opentlv``, a native extension
that calls the public OpenTLV C API directly. It is infrastructure only: the
idiomatic Reader/Writer API described in the OpenTLV language bindings
conceptual model has not been built on top of it yet.
"""

from ._opentlv import version_string

__version__ = version_string()

__all__ = ["__version__"]
