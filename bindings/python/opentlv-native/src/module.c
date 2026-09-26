/* Py_LIMITED_API is defined on the command line by the CMake build
 * (Python_add_library(... USE_SABI 3.11 ...)). */
#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include <tlv/builtins/asn1/ber.h>
#include <tlv/builtins/asn1/cer.h>
#include <tlv/builtins/asn1/der.h>
#include <tlv/builtins/emv/emv_codec.h>
#include <tlv/builtins/fixed/default.h>
#include <tlv/builtins/fixed/fixed.h>
#include <tlv/codec/codec.h>
#include <tlv/document/document.h>
#include <tlv/error.h>
#include <tlv/length.h>
#include <tlv/query/query.h>
#include <tlv/reader/reader.h>
#include <tlv/schema/schema.h>
#include <tlv/version.h>
#include <tlv/writer/writer.h>

static PyObject* opentlv_native_error = NULL;
static PyObject* opentlv_native_codec_error = NULL;

/* Mirrors opentlv.Format: 0 default, 1 ber, 2 cer, 3 der. */
static const tlv_reader_format_t* reader_format_for(int format_id) {
    switch (format_id) {
        case 0: return &tlv_reader_format_default;
        case 1: return &tlv_reader_format_ber;
        case 2: return &tlv_reader_format_cer;
        case 3: return &tlv_reader_format_der;
        default: return NULL;
    }
}

static const tlv_writer_format_t* writer_format_for(int format_id) {
    switch (format_id) {
        case 0: return &tlv_writer_format_default;
        case 1: return &tlv_writer_format_ber;
        case 2: return &tlv_writer_format_cer;
        case 3: return &tlv_writer_format_der;
        default: return NULL;
    }
}

/* The default format has no nesting: every value is opaque. */
static tlv_is_constructed_fn is_constructed_for(int format_id) {
    switch (format_id) {
        case 1: return tlv_ber_is_constructed;
        case 2: return tlv_cer_is_constructed;
        case 3: return tlv_der_is_constructed;
        default: return NULL;
    }
}

static PyObject* opentlv_native_version_string(PyObject* module, PyObject* Py_UNUSED(args)) {
    (void)module;
    return PyUnicode_FromString(tlv_version_string());
}

static PyObject* opentlv_native_strerror(PyObject* module, PyObject* args) {
    (void)module;
    int code;
    if (!PyArg_ParseTuple(args, "i", &code)) {
        return NULL;
    }
    return PyUnicode_FromString(tlv_strerror((tlv_result_t)code));
}

/* "tag", "length", "value" or "trailer"; NULL for an unset operation. */
static const char* reader_operation_name(tlv_reader_operation_t operation) {
    switch (operation) {
        case TLV_READER_OP_TAG: return "tag";
        case TLV_READER_OP_LENGTH: return "length";
        case TLV_READER_OP_VALUE: return "value";
        case TLV_READER_OP_TRAILER: return "trailer";
        default: return NULL;
    }
}

/* "tag", "length" or "value"; NULL for an unset operation. */
static const char* writer_operation_name(tlv_writer_operation_t operation) {
    switch (operation) {
        case TLV_WRITER_OP_TAG: return "tag";
        case TLV_WRITER_OP_LENGTH: return "length";
        case TLV_WRITER_OP_VALUE: return "value";
        default: return NULL;
    }
}

/* Sets dict[key] = value, or leaves an exception set and returns -1 if
 * `value` is NULL (an allocation failed) or the dict assignment fails.
 * Always consumes one reference to `value`. */
static int dict_set(PyObject* dict, const char* key, PyObject* value) {
    if (value == NULL) {
        return -1;
    }
    int rc = PyDict_SetItemString(dict, key, value);
    Py_DECREF(value);
    return rc;
}

static int dict_set_str_or_none(PyObject* dict, const char* key, const char* value) {
    return dict_set(dict, key, value != NULL ? PyUnicode_FromString(value) : Py_NewRef(Py_None));
}

static int dict_set_size_or_none(PyObject* dict, const char* key, int has, size_t value) {
    return dict_set(dict, key, has ? PyLong_FromSize_t(value) : Py_NewRef(Py_None));
}

static int dict_set_bytes_or_none(PyObject* dict, const char* key, int has, const uint8_t* data,
                                  size_t size) {
    return dict_set(dict, key,
                    has ? PyBytes_FromStringAndSize((const char*)data, (Py_ssize_t)size)
                        : Py_NewRef(Py_None));
}

/* Raises opentlv_native.Error with a single dict argument. Every raise site
 * fills whichever keys its diagnostic supports; the rest are left absent, and
 * opentlv._from_native() treats a missing key the same as an explicit None.
 * If building the dict itself fails, an exception (typically MemoryError) is
 * already set, and is left in place instead of being overwritten. */
static void raise_error(PyObject* fields) {
    if (fields == NULL) {
        return;
    }
    PyErr_SetObject(opentlv_native_error, fields);
    Py_DECREF(fields);
}

static void raise_code_only(tlv_result_t code) {
    PyObject* fields = PyDict_New();
    if (fields == NULL) {
        return;
    }
    if (dict_set(fields, "code", PyLong_FromLong((long)code)) < 0) {
        Py_DECREF(fields);
        return;
    }
    raise_error(fields);
}

static void raise_reader_error(tlv_result_t code, const tlv_reader_diagnostic_t* diag) {
    PyObject* fields = PyDict_New();
    if (fields == NULL) {
        return;
    }
    int         has_offset = diag != NULL && diag->diagnostic.has_offset;
    size_t      offset = has_offset ? diag->diagnostic.offset : 0;
    const char* expected = diag != NULL ? diag->diagnostic.expected : NULL;
    const char* actual = diag != NULL ? diag->diagnostic.actual : NULL;
    const char* operation = diag != NULL ? reader_operation_name(diag->operation) : NULL;
    int         has_tag = diag != NULL && diag->has_tag;

    if (dict_set(fields, "code", PyLong_FromLong((long)code)) < 0 ||
        dict_set_size_or_none(fields, "offset", has_offset, offset) < 0 ||
        dict_set_str_or_none(fields, "expected", expected) < 0 ||
        dict_set_str_or_none(fields, "actual", actual) < 0 ||
        dict_set_str_or_none(fields, "operation", operation) < 0 ||
        dict_set_bytes_or_none(fields, "tag", has_tag, has_tag ? diag->tag.data : NULL,
                               has_tag ? diag->tag.size : 0) < 0) {
        Py_DECREF(fields);
        return;
    }
    raise_error(fields);
}

static void raise_writer_error(tlv_result_t code, const tlv_writer_diagnostic_t* diag) {
    PyObject* fields = PyDict_New();
    if (fields == NULL) {
        return;
    }
    int         has_offset = diag != NULL && diag->diagnostic.has_offset;
    size_t      offset = has_offset ? diag->diagnostic.offset : 0;
    const char* expected = diag != NULL ? diag->diagnostic.expected : NULL;
    const char* actual = diag != NULL ? diag->diagnostic.actual : NULL;
    const char* operation = diag != NULL ? writer_operation_name(diag->operation) : NULL;
    int         has_tag = diag != NULL && diag->has_tag;
    int         has_length = diag != NULL && diag->has_length;
    size_t      length = has_length ? diag->length : 0;
    int         has_required = diag != NULL && diag->has_required;
    size_t      required = has_required ? diag->required : 0;
    int         has_available = diag != NULL && diag->has_available;
    size_t      available = has_available ? diag->available : 0;

    if (dict_set(fields, "code", PyLong_FromLong((long)code)) < 0 ||
        dict_set_size_or_none(fields, "offset", has_offset, offset) < 0 ||
        dict_set_str_or_none(fields, "expected", expected) < 0 ||
        dict_set_str_or_none(fields, "actual", actual) < 0 ||
        dict_set_str_or_none(fields, "operation", operation) < 0 ||
        dict_set_bytes_or_none(fields, "tag", has_tag, has_tag ? diag->tag.data : NULL,
                               has_tag ? diag->tag.size : 0) < 0 ||
        dict_set_size_or_none(fields, "length", has_length, length) < 0 ||
        dict_set_size_or_none(fields, "required", has_required, required) < 0 ||
        dict_set_size_or_none(fields, "available", has_available, available) < 0) {
        Py_DECREF(fields);
        return;
    }
    raise_error(fields);
}

/* Raises opentlv_native.Error with "code" and "offset" only; used by every
 * failure that reports just a code plus a byte offset (schema validation,
 * document parsing, query parsing). */
static void raise_code_and_offset(tlv_result_t code, size_t offset) {
    PyObject* fields = PyDict_New();
    if (fields == NULL) {
        return;
    }
    if (dict_set(fields, "code", PyLong_FromLong((long)code)) < 0 ||
        dict_set(fields, "offset", PyLong_FromSize_t(offset)) < 0) {
        Py_DECREF(fields);
        return;
    }
    raise_error(fields);
}

static void free_structure_schema(tlv_structure_schema_t* schema);

/* Frees a rule's own allocations (its copied tag bytes and, recursively, its
 * children schema), but not the rule struct itself: it lives inside its
 * parent schema's rules array. */
static void free_structure_rule_contents(const tlv_structure_rule_t* rule) {
    free((void*)rule->entry.tag.data);
    free_structure_schema((tlv_structure_schema_t*)rule->children);
}

static void free_structure_schema(tlv_structure_schema_t* schema) {
    if (schema == NULL) {
        return;
    }
    for (size_t i = 0; i < schema->count; i++) {
        free_structure_rule_contents(&schema->rules[i]);
    }
    free((void*)schema->rules);
    free(schema);
}

static tlv_structure_schema_t* build_structure_schema(PyObject* schema_obj);

/* Fills `out` from a (tag: bytes, min_length: int, max_length: int,
 * min_occurs: int, max_occurs: int, kind: int, children: schema | None)
 * tuple. Returns 1 on success; on failure an exception is set and `out` has
 * no allocation left to free (any partial allocation is cleaned up here). */
static int build_structure_rule(PyObject* rule_obj, tlv_structure_rule_t* out) {
    memset(out, 0, sizeof(*out));
    if (!PyTuple_Check(rule_obj) || PyTuple_Size(rule_obj) != 7) {
        PyErr_SetString(PyExc_TypeError, "each structure rule must be a 7-element tuple; use "
                                         "StructureRule instead of building one directly");
        return 0;
    }
    PyObject* tag_obj = PyTuple_GetItem(rule_obj, 0);
    PyObject* min_length_obj = PyTuple_GetItem(rule_obj, 1);
    PyObject* max_length_obj = PyTuple_GetItem(rule_obj, 2);
    PyObject* min_occurs_obj = PyTuple_GetItem(rule_obj, 3);
    PyObject* max_occurs_obj = PyTuple_GetItem(rule_obj, 4);
    PyObject* kind_obj = PyTuple_GetItem(rule_obj, 5);
    PyObject* children_obj = PyTuple_GetItem(rule_obj, 6);

    char*      tag_data = NULL;
    Py_ssize_t tag_size = 0;
    if (PyBytes_AsStringAndSize(tag_obj, &tag_data, &tag_size) < 0) {
        return 0;
    }
    uint8_t* tag_copy = NULL;
    if (tag_size > 0) {
        tag_copy = malloc((size_t)tag_size);
        if (tag_copy == NULL) {
            PyErr_NoMemory();
            return 0;
        }
        memcpy(tag_copy, tag_data, (size_t)tag_size);
    }

    size_t min_length = PyLong_AsSize_t(min_length_obj);
    size_t max_length = PyErr_Occurred() ? 0 : PyLong_AsSize_t(max_length_obj);
    size_t min_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(min_occurs_obj);
    size_t max_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(max_occurs_obj);
    long   kind = PyErr_Occurred() ? 0 : PyLong_AsLong(kind_obj);
    if (PyErr_Occurred()) {
        free(tag_copy);
        return 0;
    }

    tlv_structure_schema_t* children = NULL;
    if (children_obj != Py_None) {
        children = build_structure_schema(children_obj);
        if (children == NULL) {
            free(tag_copy);
            return 0;
        }
    }

    out->entry.tag.data = tag_copy;
    out->entry.tag.size = (size_t)tag_size;
    out->entry.min_length = min_length;
    out->entry.max_length = max_length;
    out->entry.flags = 0;
    out->entry.name = NULL;
    out->min_occurs = min_occurs;
    out->max_occurs = max_occurs;
    out->kind = (tlv_schema_kind_t)kind;
    out->children = children;
    return 1;
}

/* Builds a schema from an (allow_unknown: bool, rules: sequence[rule tuple])
 * pair, as opentlv.StructureSchema._to_native() produces. Returns a
 * malloc'd tree that free_structure_schema() must free, or NULL with an
 * exception set. */
static tlv_structure_schema_t* build_structure_schema(PyObject* schema_obj) {
    if (!PyTuple_Check(schema_obj) || PyTuple_Size(schema_obj) != 2) {
        PyErr_SetString(PyExc_TypeError, "schema must be an (allow_unknown, rules) pair");
        return NULL;
    }
    PyObject* allow_unknown_obj = PyTuple_GetItem(schema_obj, 0);
    PyObject* rules_obj = PyTuple_GetItem(schema_obj, 1);
    int       allow_unknown = PyObject_IsTrue(allow_unknown_obj);
    if (allow_unknown < 0) {
        return NULL;
    }
    Py_ssize_t count = PySequence_Size(rules_obj);
    if (count < 0) {
        return NULL;
    }

    tlv_structure_schema_t* schema = malloc(sizeof(*schema));
    if (schema == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    schema->rules = NULL;
    schema->count = 0;
    schema->allow_unknown = allow_unknown;
    schema->groups = NULL;
    schema->group_count = 0;
    schema->order = TLV_SCHEMA_ORDER_ANY;
    if (count > 0) {
        tlv_structure_rule_t* rules = calloc((size_t)count, sizeof(*rules));
        if (rules == NULL) {
            PyErr_NoMemory();
            free(schema);
            return NULL;
        }
        schema->rules = rules;
    }

    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject* rule_obj = PySequence_GetItem(rules_obj, i);
        if (rule_obj == NULL) {
            schema->count = (size_t)i;
            free_structure_schema(schema);
            return NULL;
        }
        int ok = build_structure_rule(rule_obj, (tlv_structure_rule_t*)&schema->rules[i]);
        Py_DECREF(rule_obj);
        if (!ok) {
            schema->count = (size_t)i;
            free_structure_schema(schema);
            return NULL;
        }
        schema->count = (size_t)(i + 1);
    }
    return schema;
}

/* structure_validate(data, format, schema, max_depth, max_elements) -> None
 *
 * Validates `data` against `schema` (an opentlv.StructureSchema serialized
 * with _to_native()) using wire format `format`. Raises
 * opentlv_native.Error with "code" and "offset" on the first violation or
 * wire-level error. */
static PyObject* opentlv_native_structure_validate(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer;
    int        format_id;
    PyObject*  schema_obj;
    Py_ssize_t max_depth, max_elements;
    if (!PyArg_ParseTuple(args, "y*iOnn", &buffer, &format_id, &schema_obj, &max_depth,
                          &max_elements)) {
        return NULL;
    }
    const tlv_reader_format_t* format = reader_format_for(format_id);
    if (format == NULL) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return NULL;
    }
    if (max_depth < 0 || max_elements < 0) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "max_depth and max_elements must not be negative");
        return NULL;
    }

    tlv_structure_schema_t* schema = build_structure_schema(schema_obj);
    if (schema == NULL) {
        PyBuffer_Release(&buffer);
        return NULL;
    }

    size_t       error_offset = 0;
    tlv_result_t code = tlv_schema_validate((const uint8_t*)buffer.buf, (size_t)buffer.len, format,
                                            is_constructed_for(format_id), schema,
                                            (size_t)max_depth, (size_t)max_elements, &error_offset);
    free_structure_schema(schema);
    PyBuffer_Release(&buffer);
    if (code != TLV_OK) {
        raise_code_and_offset(code, error_offset);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* opentlv_native_codec_strerror(PyObject* module, PyObject* args) {
    (void)module;
    int code;
    if (!PyArg_ParseTuple(args, "i", &code)) {
        return NULL;
    }
    return PyUnicode_FromString(tlv_codec_strerror((tlv_codec_result_t)code));
}

/* Raises opentlv_native.CodecError with a single int argument: the
 * tlv_codec_result_t code. This is a separate error domain from
 * opentlv_native.Error: tlv_codec_result_t conversion errors are
 * independent of the tlv_result_t framing errors that raises. */
static void raise_codec_error(tlv_codec_result_t code) {
    PyObject* codec_args = Py_BuildValue("(i)", (int)code);
    if (codec_args == NULL) {
        return;
    }
    PyErr_SetObject(opentlv_native_codec_error, codec_args);
    Py_DECREF(codec_args);
}

/* emv_decode_amount(data) -> int
 *
 * Decodes 6 bytes of BCD (EMV format n12) into an unscaled minor-unit
 * amount, using the public `tlv_emv_codec_amount` codec: the one concrete
 * tlv_codec_t the OpenTLV C API exports. Raises opentlv_native.CodecError
 * on failure. */
static PyObject* opentlv_native_emv_decode_amount(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer buffer;
    if (!PyArg_ParseTuple(args, "y*", &buffer)) {
        return NULL;
    }
    uint64_t           value = 0;
    tlv_codec_result_t code = tlv_codec_decode(&tlv_emv_codec_amount, (const uint8_t*)buffer.buf,
                                               (size_t)buffer.len, &value, sizeof(value));
    PyBuffer_Release(&buffer);
    if (code != TLV_CODEC_OK) {
        raise_codec_error(code);
        return NULL;
    }
    return PyLong_FromUnsignedLongLong((unsigned long long)value);
}

/* emv_encode_amount(value) -> bytes
 *
 * Encodes an unscaled minor-unit amount as 6 bytes of BCD (EMV format n12),
 * using the public `tlv_emv_codec_amount` codec. Raises
 * opentlv_native.CodecError on failure, for example if `value` does not fit
 * the format's 12-digit range. */
static PyObject* opentlv_native_emv_encode_amount(PyObject* module, PyObject* args) {
    (void)module;
    unsigned long long value_arg;
    if (!PyArg_ParseTuple(args, "K", &value_arg)) {
        return NULL;
    }
    uint64_t value = (uint64_t)value_arg;
    uint8_t  data[16]; /* the amount codec always writes exactly 6 bytes; generous headroom */
    size_t   written = 0;
    tlv_codec_result_t code = tlv_codec_encode(&tlv_emv_codec_amount, &value, sizeof(value), data,
                                               sizeof(data), &written);
    if (code != TLV_CODEC_OK) {
        raise_codec_error(code);
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char*)data, (Py_ssize_t)written);
}

#define DOCUMENT_CAPSULE_NAME "opentlv_native.Document"

static void document_capsule_destructor(PyObject* capsule) {
    tlv_document_t* document =
        (tlv_document_t*)PyCapsule_GetPointer(capsule, DOCUMENT_CAPSULE_NAME);
    if (document != NULL) {
        tlv_document_free(document);
    }
}

/* Returns the document a capsule holds, or NULL with an exception set if
 * `capsule_obj` is not one of our document capsules. */
static tlv_document_t* document_from_capsule(PyObject* capsule_obj) {
    return (tlv_document_t*)PyCapsule_GetPointer(capsule_obj, DOCUMENT_CAPSULE_NAME);
}

/* PyArg_ParseTuple "O&" converter: None -> NULL, an int from node_to_py() ->
 * that pointer. Returns 1 on success, 0 with an exception set on failure. */
static int py_to_node(PyObject* obj, void* out) {
    tlv_node_t** node_out = (tlv_node_t**)out;
    if (obj == Py_None) {
        *node_out = NULL;
        return 1;
    }
    void* ptr = PyLong_AsVoidPtr(obj);
    if (ptr == NULL && PyErr_Occurred()) {
        return 0;
    }
    *node_out = (tlv_node_t*)ptr;
    return 1;
}

static PyObject* node_to_py(tlv_node_t* node) {
    if (node == NULL) {
        Py_RETURN_NONE;
    }
    return PyLong_FromVoidPtr(node);
}

/* Builds document options from Python-supplied format IDs and limits.
 * Returns 1 on success; on failure an exception is set and `*out` is
 * unusable. */
static int build_document_options(int reader_format_id, int writer_format_id, Py_ssize_t max_depth,
                                  Py_ssize_t max_elements, tlv_document_options_t* out) {
    const tlv_reader_format_t* reader_format = reader_format_for(reader_format_id);
    const tlv_writer_format_t* writer_format = writer_format_for(writer_format_id);
    if (reader_format == NULL || writer_format == NULL) {
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return 0;
    }
    if (max_depth < 0 || max_elements < 0) {
        PyErr_SetString(PyExc_ValueError, "max_depth and max_elements must not be negative");
        return 0;
    }
    tlv_result_t code = tlv_document_options_init(out, reader_format, writer_format,
                                                  is_constructed_for(reader_format_id));
    if (code != TLV_OK) {
        raise_code_only(code);
        return 0;
    }
    out->max_depth = (size_t)max_depth;
    out->max_elements = (size_t)max_elements;
    return 1;
}

/* document_create(reader_format, writer_format, max_depth, max_elements) -> capsule
 *
 * Creates an empty document. Raises opentlv_native.Error on failure. */
static PyObject* opentlv_native_document_create(PyObject* module, PyObject* args) {
    (void)module;
    int        reader_format_id, writer_format_id;
    Py_ssize_t max_depth, max_elements;
    if (!PyArg_ParseTuple(args, "iinn", &reader_format_id, &writer_format_id, &max_depth,
                          &max_elements)) {
        return NULL;
    }
    tlv_document_options_t options;
    if (!build_document_options(reader_format_id, writer_format_id, max_depth, max_elements,
                                &options)) {
        return NULL;
    }
    tlv_document_t* document = NULL;
    tlv_result_t    code = tlv_document_create(&options, &document);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    PyObject* capsule = PyCapsule_New(document, DOCUMENT_CAPSULE_NAME, document_capsule_destructor);
    if (capsule == NULL) {
        tlv_document_free(document);
        return NULL;
    }
    return capsule;
}

/* document_parse(data, reader_format, writer_format, max_depth, max_elements) -> capsule
 *
 * Parses `data` into a new owned document. Raises opentlv_native.Error with
 * "code" and "offset" on failure. */
static PyObject* opentlv_native_document_parse(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer;
    int        reader_format_id, writer_format_id;
    Py_ssize_t max_depth, max_elements;
    if (!PyArg_ParseTuple(args, "y*iinn", &buffer, &reader_format_id, &writer_format_id, &max_depth,
                          &max_elements)) {
        return NULL;
    }
    tlv_document_options_t options;
    if (!build_document_options(reader_format_id, writer_format_id, max_depth, max_elements,
                                &options)) {
        PyBuffer_Release(&buffer);
        return NULL;
    }
    tlv_document_t* document = NULL;
    size_t          error_offset = 0;
    tlv_result_t code = tlv_document_parse((const uint8_t*)buffer.buf, (size_t)buffer.len, &options,
                                           &document, &error_offset);
    PyBuffer_Release(&buffer);
    if (code != TLV_OK) {
        raise_code_and_offset(code, error_offset);
        return NULL;
    }
    PyObject* capsule = PyCapsule_New(document, DOCUMENT_CAPSULE_NAME, document_capsule_destructor);
    if (capsule == NULL) {
        tlv_document_free(document);
        return NULL;
    }
    return capsule;
}

static PyObject* opentlv_native_document_count(PyObject* module, PyObject* args) {
    (void)module;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    return PyLong_FromSize_t(tlv_document_count(document));
}

static PyObject* opentlv_native_document_first(PyObject* module, PyObject* args) {
    (void)module;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    return node_to_py(tlv_document_first(document));
}

/* document_find(capsule, parent, tag) -> int | None */
static PyObject* opentlv_native_document_find(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*   capsule;
    tlv_node_t* parent;
    Py_buffer   tag_buf;
    if (!PyArg_ParseTuple(args, "OO&y*", &capsule, py_to_node, &parent, &tag_buf)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        PyBuffer_Release(&tag_buf);
        return NULL;
    }
    tlv_tag_t   tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    tlv_node_t* found = tlv_document_find(document, parent, tag);
    PyBuffer_Release(&tag_buf);
    return node_to_py(found);
}

/* document_find_path(capsule, query_text) -> int | None */
static PyObject* opentlv_native_document_find_path(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*   capsule;
    const char* text;
    if (!PyArg_ParseTuple(args, "Os", &capsule, &text)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    tlv_query_t  query;
    size_t       error_offset = 0;
    tlv_result_t code = tlv_query_parse(text, &query, &error_offset);
    if (code != TLV_OK) {
        raise_code_and_offset(code, error_offset);
        return NULL;
    }
    return node_to_py(tlv_document_find_path(document, &query));
}

/* document_insert(capsule, parent, before, tag, value) -> int (the new node) */
static PyObject* opentlv_native_document_insert(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*   capsule;
    tlv_node_t* parent;
    tlv_node_t* before;
    Py_buffer   tag_buf, value_buf;
    if (!PyArg_ParseTuple(args, "OO&O&y*y*", &capsule, py_to_node, &parent, py_to_node, &before,
                          &tag_buf, &value_buf)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        return NULL;
    }
    tlv_tag_t    tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    tlv_node_t*  node = NULL;
    tlv_result_t code = tlv_document_insert(
        document, parent, before, tag, (const uint8_t*)value_buf.buf, (size_t)value_buf.len, &node);
    PyBuffer_Release(&tag_buf);
    PyBuffer_Release(&value_buf);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return node_to_py(node);
}

static PyObject* opentlv_native_document_encoded_size(PyObject* module, PyObject* args) {
    (void)module;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = tlv_document_encoded_size(document, &size);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

static PyObject* opentlv_native_document_encode(PyObject* module, PyObject* args) {
    (void)module;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = tlv_document_encoded_size(document, &size);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    PyObject* result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (result == NULL) {
        return NULL;
    }
    char*  buf = PyBytes_AsString(result);
    size_t written = 0;
    code = tlv_document_encode(document, (uint8_t*)buf, size, &written);
    if (code != TLV_OK) {
        Py_DECREF(result);
        raise_code_only(code);
        return NULL;
    }
    if (written != size) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_RuntimeError, "tlv_document_encode wrote a different size than "
                                            "tlv_document_encoded_size reported");
        return NULL;
    }
    return result;
}

static PyObject* opentlv_native_node_first_child(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    return node_to_py(tlv_node_first_child(node));
}

static PyObject* opentlv_native_node_next(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    return node_to_py(tlv_node_next(node));
}

static PyObject* opentlv_native_node_parent(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    return node_to_py(tlv_node_parent(node));
}

static PyObject* opentlv_native_node_next_same_tag(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    return node_to_py(tlv_node_next_same_tag(node));
}

static PyObject* opentlv_native_node_tag(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    tlv_tag_t tag = tlv_node_tag(node);
    return PyBytes_FromStringAndSize((const char*)tag.data, (Py_ssize_t)tag.size);
}

static PyObject* opentlv_native_node_is_constructed(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    return PyBool_FromLong(tlv_node_is_constructed(node));
}

static PyObject* opentlv_native_node_value(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    const uint8_t* data = tlv_node_value_data(node);
    size_t         size = tlv_node_value_size(node);
    return PyBytes_FromStringAndSize((const char*)data, (Py_ssize_t)size);
}

static PyObject* opentlv_native_node_set_value(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    Py_buffer   value_buf;
    if (!PyArg_ParseTuple(args, "O&y*", py_to_node, &node, &value_buf)) {
        return NULL;
    }
    tlv_result_t code =
        tlv_node_set_value(node, (const uint8_t*)value_buf.buf, (size_t)value_buf.len);
    PyBuffer_Release(&value_buf);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* opentlv_native_node_erase(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    tlv_node_erase(node);
    Py_RETURN_NONE;
}

static PyObject* opentlv_native_node_encoded_size(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = tlv_node_encoded_size(node, &size);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

static PyObject* opentlv_native_node_encode(PyObject* module, PyObject* args) {
    (void)module;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&", py_to_node, &node)) {
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = tlv_node_encoded_size(node, &size);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    PyObject* result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (result == NULL) {
        return NULL;
    }
    char*  buf = PyBytes_AsString(result);
    size_t written = 0;
    code = tlv_node_encode(node, (uint8_t*)buf, size, &written);
    if (code != TLV_OK) {
        Py_DECREF(result);
        raise_code_only(code);
        return NULL;
    }
    if (written != size) {
        Py_DECREF(result);
        PyErr_SetString(
            PyExc_RuntimeError,
            "tlv_node_encode wrote a different size than tlv_node_encoded_size reported");
        return NULL;
    }
    return result;
}

/* read(data, offset, format) -> (tag: bytes, value_offset: int, value_length: int, consumed: int)
 *
 * Parses one element at `offset` in `data` using wire format `format` (an
 * opentlv.Format value) and raises opentlv_native.Error on failure. `data` is
 * any buffer-protocol object; `value_offset`/`value_length` describe the
 * value as a range within `data`, so the caller can slice it without
 * copying. */
static PyObject* opentlv_native_read(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer;
    Py_ssize_t offset;
    int        format_id;
    if (!PyArg_ParseTuple(args, "y*ni", &buffer, &offset, &format_id)) {
        return NULL;
    }
    const tlv_reader_format_t* format = reader_format_for(format_id);
    if (format == NULL) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return NULL;
    }
    if (offset < 0 || offset > buffer.len) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "offset is out of range for data");
        return NULL;
    }

    const uint8_t*          base = (const uint8_t*)buffer.buf;
    size_t                  size = (size_t)(buffer.len - offset);
    tlv_view_t              entry;
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diag;
    tlv_reader_diagnostic_init(&diag);

    tlv_result_t code = tlv_read_diag(base + offset, size, format, &entry, &consumed, &diag);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_reader_error(code, &diag);
        return NULL;
    }

    size_t value_length = 0;
    code = tlv_length_to_size(entry.value.length, &value_length);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_code_only(code);
        return NULL;
    }
    Py_ssize_t value_offset =
        value_length == 0 ? 0 : (Py_ssize_t)((const uint8_t*)entry.value.data - base);

    PyObject* tag_obj =
        PyBytes_FromStringAndSize((const char*)entry.tag.data, (Py_ssize_t)entry.tag.size);
    PyBuffer_Release(&buffer);
    if (tag_obj == NULL) {
        return NULL;
    }
    PyObject* consumed_obj = PyLong_FromSize_t(consumed);
    if (consumed_obj == NULL) {
        Py_DECREF(tag_obj);
        return NULL;
    }

    return Py_BuildValue("(NnnN)", tag_obj, value_offset, (Py_ssize_t)value_length, consumed_obj);
}

/* write(buffer, offset, tag, value, format) -> written: int
 *
 * Encodes one element at `offset` in `buffer` using wire format `format` and
 * raises opentlv_native.Error on failure, including insufficient capacity
 * (`code` 1, `required` set to the exact size needed). `buffer` must be a
 * writable buffer-protocol object (for example a bytearray); `tag` and
 * `value` may be any buffer-protocol object. */
static PyObject* opentlv_native_write(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer, tag_buf, value_buf;
    Py_ssize_t offset;
    int        format_id;
    if (!PyArg_ParseTuple(args, "w*ny*y*i", &buffer, &offset, &tag_buf, &value_buf, &format_id)) {
        return NULL;
    }
    const tlv_writer_format_t* format = writer_format_for(format_id);
    if (format == NULL) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return NULL;
    }
    if (offset < 0 || offset > buffer.len) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        PyErr_SetString(PyExc_ValueError, "offset is out of range for buffer");
        return NULL;
    }

    tlv_tag_t               tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    uint8_t*                dest = (uint8_t*)buffer.buf + offset;
    size_t                  capacity = (size_t)(buffer.len - offset);
    size_t                  written = 0;
    tlv_writer_diagnostic_t diag;
    tlv_writer_diagnostic_init(&diag);

    tlv_result_t code = tlv_write_diag(dest, capacity, format, tag, (const uint8_t*)value_buf.buf,
                                       (size_t)value_buf.len, &written, &diag);
    PyBuffer_Release(&tag_buf);
    PyBuffer_Release(&value_buf);
    PyBuffer_Release(&buffer);
    if (code != TLV_OK) {
        raise_writer_error(code, &diag);
        return NULL;
    }
    return PyLong_FromSize_t(written);
}

/* encoded_size(tag, value_length, format) -> int
 *
 * Returns the encoded size of an element with `tag` and a value of
 * `value_length` bytes in wire format `format`, without writing anything.
 * Raises opentlv_native.Error on failure. */
static PyObject* opentlv_native_encoded_size(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  tag_buf;
    Py_ssize_t value_length;
    int        format_id;
    if (!PyArg_ParseTuple(args, "y*ni", &tag_buf, &value_length, &format_id)) {
        return NULL;
    }
    const tlv_writer_format_t* format = writer_format_for(format_id);
    if (format == NULL) {
        PyBuffer_Release(&tag_buf);
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return NULL;
    }
    if (value_length < 0) {
        PyBuffer_Release(&tag_buf);
        PyErr_SetString(PyExc_ValueError, "value_length must not be negative");
        return NULL;
    }

    tlv_tag_t    tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    size_t       size = 0;
    tlv_result_t code = tlv_encoded_size(tag, (size_t)value_length, format, &size);
    PyBuffer_Release(&tag_buf);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

/* Builds and validates a tlv_fixed_config_t from Python-parsed arguments.
 * Returns 1 on success; on failure a ValueError is set and *out is unusable. */
static int fixed_config_from_args(Py_ssize_t tag_size, Py_ssize_t length_size, int big_endian,
                                  tlv_fixed_config_t* out) {
    if (tag_size < 1) {
        PyErr_SetString(PyExc_ValueError, "tag_size must be at least 1");
        return 0;
    }
    if (length_size < 1 || length_size > 8) {
        PyErr_SetString(PyExc_ValueError, "length_size must be between 1 and 8");
        return 0;
    }
    out->tag_size = (size_t)tag_size;
    out->length_size = (size_t)length_size;
    out->order = big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
    return 1;
}

/* read_fixed(data, offset, tag_size, length_size, big_endian)
 *     -> (tag: bytes, value_offset: int, value_length: int, consumed: int)
 *
 * Like read(), but for the configurable fixed-width format: tag_size and
 * length_size are byte widths (length_size 1..8), and big_endian selects the
 * length field's byte order. Raises opentlv_native.Error on failure. */
static PyObject* opentlv_native_read_fixed(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer;
    Py_ssize_t offset, tag_size, length_size;
    int        big_endian;
    if (!PyArg_ParseTuple(args, "y*nnnp", &buffer, &offset, &tag_size, &length_size, &big_endian)) {
        return NULL;
    }
    tlv_fixed_config_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&buffer);
        return NULL;
    }
    tlv_reader_format_t format;
    tlv_result_t        init_code = tlv_fixed_reader_format_init(&format, &config);
    if (init_code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_code_only(init_code);
        return NULL;
    }
    if (offset < 0 || offset > buffer.len) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "offset is out of range for data");
        return NULL;
    }

    const uint8_t*          base = (const uint8_t*)buffer.buf;
    size_t                  size = (size_t)(buffer.len - offset);
    tlv_view_t              entry;
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diag;
    tlv_reader_diagnostic_init(&diag);

    tlv_result_t code = tlv_read_diag(base + offset, size, &format, &entry, &consumed, &diag);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_reader_error(code, &diag);
        return NULL;
    }

    size_t value_length = 0;
    code = tlv_length_to_size(entry.value.length, &value_length);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_code_only(code);
        return NULL;
    }
    Py_ssize_t value_offset =
        value_length == 0 ? 0 : (Py_ssize_t)((const uint8_t*)entry.value.data - base);

    PyObject* tag_obj =
        PyBytes_FromStringAndSize((const char*)entry.tag.data, (Py_ssize_t)entry.tag.size);
    PyBuffer_Release(&buffer);
    if (tag_obj == NULL) {
        return NULL;
    }
    PyObject* consumed_obj = PyLong_FromSize_t(consumed);
    if (consumed_obj == NULL) {
        Py_DECREF(tag_obj);
        return NULL;
    }

    return Py_BuildValue("(NnnN)", tag_obj, value_offset, (Py_ssize_t)value_length, consumed_obj);
}

/* write_fixed(buffer, offset, tag, value, tag_size, length_size, big_endian) -> written: int
 *
 * Like write(), but for the configurable fixed-width format. Raises
 * opentlv_native.Error on failure, including insufficient capacity. */
static PyObject* opentlv_native_write_fixed(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer, tag_buf, value_buf;
    Py_ssize_t offset, tag_size, length_size;
    int        big_endian;
    if (!PyArg_ParseTuple(args, "w*ny*y*nnp", &buffer, &offset, &tag_buf, &value_buf, &tag_size,
                          &length_size, &big_endian)) {
        return NULL;
    }
    tlv_fixed_config_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        return NULL;
    }
    tlv_writer_format_t format;
    tlv_result_t        init_code = tlv_fixed_writer_format_init(&format, &config);
    if (init_code != TLV_OK) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        raise_code_only(init_code);
        return NULL;
    }
    if (offset < 0 || offset > buffer.len) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        PyErr_SetString(PyExc_ValueError, "offset is out of range for buffer");
        return NULL;
    }

    tlv_tag_t               tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    uint8_t*                dest = (uint8_t*)buffer.buf + offset;
    size_t                  capacity = (size_t)(buffer.len - offset);
    size_t                  written = 0;
    tlv_writer_diagnostic_t diag;
    tlv_writer_diagnostic_init(&diag);

    tlv_result_t code = tlv_write_diag(dest, capacity, &format, tag, (const uint8_t*)value_buf.buf,
                                       (size_t)value_buf.len, &written, &diag);
    PyBuffer_Release(&tag_buf);
    PyBuffer_Release(&value_buf);
    PyBuffer_Release(&buffer);
    if (code != TLV_OK) {
        raise_writer_error(code, &diag);
        return NULL;
    }
    return PyLong_FromSize_t(written);
}

/* encoded_size_fixed(tag, value_length, tag_size, length_size, big_endian) -> int
 *
 * Like encoded_size(), but for the configurable fixed-width format. Raises
 * opentlv_native.Error on failure. */
static PyObject* opentlv_native_encoded_size_fixed(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  tag_buf;
    Py_ssize_t value_length, tag_size, length_size;
    int        big_endian;
    if (!PyArg_ParseTuple(args, "y*nnnp", &tag_buf, &value_length, &tag_size, &length_size,
                          &big_endian)) {
        return NULL;
    }
    tlv_fixed_config_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&tag_buf);
        return NULL;
    }
    tlv_writer_format_t format;
    tlv_result_t        init_code = tlv_fixed_writer_format_init(&format, &config);
    if (init_code != TLV_OK) {
        PyBuffer_Release(&tag_buf);
        raise_code_only(init_code);
        return NULL;
    }
    if (value_length < 0) {
        PyBuffer_Release(&tag_buf);
        PyErr_SetString(PyExc_ValueError, "value_length must not be negative");
        return NULL;
    }

    tlv_tag_t    tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    size_t       size = 0;
    tlv_result_t code = tlv_encoded_size(tag, (size_t)value_length, &format, &size);
    PyBuffer_Release(&tag_buf);
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

static PyMethodDef opentlv_native_methods[] = {
    {"version_string", opentlv_native_version_string, METH_NOARGS,
     "Return the version of the linked OpenTLV C library, for example \"0.6.0\"."},
    {"strerror", opentlv_native_strerror, METH_VARARGS,
     "Return the readable description of a tlv_result_t code."},
    {"read", opentlv_native_read, METH_VARARGS,
     "Parse one element at an offset in a buffer using a wire format."},
    {"write", opentlv_native_write, METH_VARARGS,
     "Encode one element at an offset in a writable buffer using a wire format."},
    {"encoded_size", opentlv_native_encoded_size, METH_VARARGS,
     "Compute the encoded size of an element without writing it."},
    {"read_fixed", opentlv_native_read_fixed, METH_VARARGS,
     "Parse one element at an offset in a buffer using the configurable fixed-width format."},
    {"write_fixed", opentlv_native_write_fixed, METH_VARARGS,
     "Encode one element at an offset in a writable buffer using the configurable "
     "fixed-width format."},
    {"encoded_size_fixed", opentlv_native_encoded_size_fixed, METH_VARARGS,
     "Compute the encoded size of an element in the configurable fixed-width format."},
    {"structure_validate", opentlv_native_structure_validate, METH_VARARGS,
     "Validate a buffer against a serialized structural schema."},
    {"codec_strerror", opentlv_native_codec_strerror, METH_VARARGS,
     "Return the readable description of a tlv_codec_result_t code."},
    {"emv_decode_amount", opentlv_native_emv_decode_amount, METH_VARARGS,
     "Decode 6 bytes of BCD (EMV format n12) into an unscaled minor-unit amount."},
    {"emv_encode_amount", opentlv_native_emv_encode_amount, METH_VARARGS,
     "Encode an unscaled minor-unit amount as 6 bytes of BCD (EMV format n12)."},
    {"document_create", opentlv_native_document_create, METH_VARARGS, "Create an empty document."},
    {"document_parse", opentlv_native_document_parse, METH_VARARGS,
     "Parse a buffer into a new owned document."},
    {"document_count", opentlv_native_document_count, METH_VARARGS,
     "Return the number of elements in a document, including nested ones."},
    {"document_first", opentlv_native_document_first, METH_VARARGS,
     "Return the first top-level node of a document, or None."},
    {"document_find", opentlv_native_document_find, METH_VARARGS,
     "Find the first direct child of a node (or the top level) with a tag."},
    {"document_find_path", opentlv_native_document_find_path, METH_VARARGS,
     "Find the first element addressed by a path query, for example \"6F/A5/50\"."},
    {"document_insert", opentlv_native_document_insert, METH_VARARGS,
     "Insert a new element into a document and return its node."},
    {"document_encoded_size", opentlv_native_document_encoded_size, METH_VARARGS,
     "Compute the encoded size of a whole document."},
    {"document_encode", opentlv_native_document_encode, METH_VARARGS, "Encode a whole document."},
    {"node_first_child", opentlv_native_node_first_child, METH_VARARGS,
     "Return the first child of a constructed node, or None."},
    {"node_next", opentlv_native_node_next, METH_VARARGS,
     "Return the next sibling of a node, or None."},
    {"node_parent", opentlv_native_node_parent, METH_VARARGS,
     "Return the parent of a node, or None for a top-level node."},
    {"node_next_same_tag", opentlv_native_node_next_same_tag, METH_VARARGS,
     "Return the next sibling with the same tag as a node, or None."},
    {"node_tag", opentlv_native_node_tag, METH_VARARGS, "Return the tag of a node."},
    {"node_is_constructed", opentlv_native_node_is_constructed, METH_VARARGS,
     "Return whether a node's value holds nested elements."},
    {"node_value", opentlv_native_node_value, METH_VARARGS,
     "Return the value bytes of a node (empty for a constructed node)."},
    {"node_set_value", opentlv_native_node_set_value, METH_VARARGS, "Replace the value of a node."},
    {"node_erase", opentlv_native_node_erase, METH_VARARGS,
     "Remove a node and all of its descendants from its document."},
    {"node_encoded_size", opentlv_native_node_encoded_size, METH_VARARGS,
     "Compute the encoded size of one element with its descendants."},
    {"node_encode", opentlv_native_node_encode, METH_VARARGS,
     "Encode one element with its descendants."},
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
    PyObject* module = PyModule_Create(&opentlv_native_module);
    if (module == NULL) {
        return NULL;
    }

    /* Raised with a single dict argument carrying "code" and whichever
     * diagnostic keys the failing call supports; see raise_error() above.
     * Internal transport to the opentlv package, which maps it to a typed,
     * documented exception. */
    opentlv_native_error = PyErr_NewException("opentlv_native.Error", NULL, NULL);
    if (opentlv_native_error == NULL) {
        Py_DECREF(module);
        return NULL;
    }
    if (PyModule_AddObjectRef(module, "Error", opentlv_native_error) < 0) {
        Py_DECREF(module);
        return NULL;
    }

    /* Raised with a single int argument: the tlv_codec_result_t code. */
    opentlv_native_codec_error = PyErr_NewException("opentlv_native.CodecError", NULL, NULL);
    if (opentlv_native_codec_error == NULL) {
        Py_DECREF(module);
        return NULL;
    }
    if (PyModule_AddObjectRef(module, "CodecError", opentlv_native_codec_error) < 0) {
        Py_DECREF(module);
        return NULL;
    }

    return module;
}
