# opentlv-native (experimental)

Native Python bindings to the [OpenTLV](https://github.com/marekcingel/OpenTLV)
C API: a native extension, built directly against the CPython C API and the
CPython Limited API, that registers the C functions as plain Python callables
with no added safety checks or Pythonic ergonomics. Imported as
`opentlv_native` (the distribution name uses a hyphen, the import name an
underscore, as is conventional for Python packages):

```python
import opentlv_native

print(opentlv_native.version_string())
```

Not meant to be used directly; use the `opentlv` package instead. See
[Python bindings](https://marekcingel.github.io/OpenTLV/development/python/).
