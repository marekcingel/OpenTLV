/* Py_LIMITED_API is defined on the command line by the CMake build
 * (Python_add_library(... USE_SABI 3.11 ...)). */
#include <Python.h>

#include <tlv/version.h>

static PyObject* opentlv_native_version_string(PyObject* module, PyObject* Py_UNUSED(args)) {
    (void)module;
    return PyUnicode_FromString(tlv_version_string());
}

static PyMethodDef opentlv_native_methods[] = {
    {"version_string", opentlv_native_version_string, METH_NOARGS,
     "Return the version of the linked OpenTLV C library, for example \"0.6.0\"."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef opentlv_native_module = {
    PyModuleDef_HEAD_INIT,
    "opentlv_native",
    "Raw declarations of the OpenTLV C API, registered directly as Python callables. "
    "Low-level; use the opentlv package instead.",
    -1,
    opentlv_native_methods,
};

PyMODINIT_FUNC PyInit_opentlv_native(void) {
    return PyModule_Create(&opentlv_native_module);
}
