/* Py_LIMITED_API is defined on the command line by the CMake build
 * (Python_add_library(... USE_SABI 3.11 ...)). */
#include <Python.h>

#include <tlv/version.h>

static PyObject* opentlv_version_string(PyObject* module, PyObject* Py_UNUSED(args)) {
    (void)module;
    return PyUnicode_FromString(tlv_version_string());
}

static PyMethodDef opentlv_methods[] = {
    {"version_string", opentlv_version_string, METH_NOARGS,
     "Return the version of the linked OpenTLV C library, for example \"0.6.0\"."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef opentlv_module = {
    PyModuleDef_HEAD_INIT,
    "_opentlv",
    "Native extension backing the opentlv package; wraps the public OpenTLV C API.",
    -1,
    opentlv_methods,
};

PyMODINIT_FUNC PyInit__opentlv(void) {
    return PyModule_Create(&opentlv_module);
}
