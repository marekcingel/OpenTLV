/* Py_LIMITED_API is defined on the command line by the CMake build
 * (Python_add_library(... USE_SABI 3.11 ...)). */
#include <Python.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "format.h"
#include "reader.h"
#include "schema.h"
#include "writer.h"
#include <tlv/config.h>
#if OPENTLV_EMV
#include <tlv/builtins/emv/emv_codec.h>
#endif
#include <tlv/formats/fixed.h>
#include <tlv/codec/codec.h>
#include <tlv/codec/number.h>
#include <tlv/document/document.h>
#include <tlv/error.h>
#include <tlv/definition.h>
#include <tlv/size.h>
#include <tlv/query/query.h>
#include <tlv/reader/reader.h>
#include <tlv/schema/schema.h>
#include <tlv/version.h>
#include <tlv/writer/writer.h>

static PyObject* opentlv_native_error = NULL;
static PyObject* opentlv_native_codec_error = NULL;

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
        case TLV_READER_OP_HEADER: return "header";
        default: return NULL;
    }
}

/* "tag", "length" or "value"; NULL for an unset operation. */
static const char* writer_operation_name(tlv_writer_operation_t operation) {
    switch (operation) {
        case TLV_WRITER_OP_TAG: return "tag";
        case TLV_WRITER_OP_LENGTH: return "length";
        case TLV_WRITER_OP_VALUE: return "value";
        case TLV_WRITER_OP_TRAILER: return "trailer";
        case TLV_WRITER_OP_HEADER: return "header";
        case TLV_WRITER_OP_COPY: return "copy";
        case TLV_WRITER_OP_PRESERVE: return "preserve";
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
                               has_tag ? diag->tag.size : 0) < 0 ||
        dict_set_bytes_or_none(fields, "raw_length", diag && diag->has_raw_length,
                               diag ? diag->raw_length.data : NULL,
                               diag ? diag->raw_length.size : 0) < 0 ||
        dict_set(fields, "declared_length",
                 diag && diag->has_declared_length
                     ? PyLong_FromUnsignedLongLong(diag->declared_length)
                     : Py_NewRef(Py_None)) < 0 ||
        dict_set_size_or_none(fields, "available", diag && diag->has_available,
                              diag ? diag->available : 0) < 0 ||
        dict_set_size_or_none(fields, "tag_offset", diag && diag->has_tag_offset,
                              diag ? diag->tag_offset : 0) < 0 ||
        dict_set_size_or_none(fields, "length_offset", diag && diag->has_length_offset,
                              diag ? diag->length_offset : 0) < 0 ||
        dict_set_size_or_none(fields, "value_offset", diag && diag->has_value_offset,
                              diag ? diag->value_offset : 0) < 0 ||
        dict_set_size_or_none(fields, "enclosing_end", diag && diag->has_enclosing_end,
                              diag ? diag->enclosing_end : 0) < 0 ||
        dict_set(fields, "required",
                 diag && diag->has_required ? PyLong_FromUnsignedLongLong(diag->required)
                                            : Py_NewRef(Py_None)) < 0) {
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

/* Frees a rule's owned field schema, copied tag bytes and, recursively, its
 * children schema, but not the rule struct itself: it lives inside its
 * parent schema's rules array. */
static void free_structure_rule_contents(const tlv_structure_rule_t* rule) {
    if (rule->entry) {
        free((void*)rule->entry->tag.data);
        free((void*)rule->entry->name);
    }
    free((void*)rule->entry);
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
    for (size_t i = 0; i < schema->group_count; ++i) free((void*)schema->groups[i].name);
    free((void*)schema->groups);
    free(schema);
}

static tlv_structure_schema_t* build_structure_schema(PyObject* schema_obj);
/* Own UTF-8 names rather than retaining pointers into temporary Python values. */
static char* schema_name_copy(PyObject* value) {
    if (value == Py_None) return NULL;
    PyObject* encoded = PyUnicode_AsUTF8String(value);
    if (!encoded) return NULL;
    char*      bytes = NULL;
    Py_ssize_t length = 0;
    if (PyBytes_AsStringAndSize(encoded, &bytes, &length) < 0) {
        Py_DECREF(encoded);
        return NULL;
    }
    if (memchr(bytes, 0, (size_t)length)) {
        Py_DECREF(encoded);
        PyErr_SetString(PyExc_ValueError, "schema names cannot contain NUL");
        return NULL;
    }
    char* copy = malloc((size_t)length + 1);
    if (copy)
        memcpy(copy, bytes, (size_t)length + 1);
    else
        PyErr_NoMemory();
    Py_DECREF(encoded);
    return copy;
}

/* Fills `out` from a (tag: bytes, min_length: int, max_length: int,
 * min_occurs: int, max_occurs: int, kind: int, children: schema | None,
 * flags: int, length_multiple: int, group: int, name: str | None)
 * tuple. Returns 1 on success; on failure an exception is set and `out` has
 * no allocation left to free (any partial allocation is cleaned up here). */
static int build_structure_rule(PyObject* rule_obj, tlv_structure_rule_t* out) {
    memset(out, 0, sizeof(*out));
    if (!PyTuple_Check(rule_obj) || PyTuple_Size(rule_obj) != 11) {
        PyErr_SetString(PyExc_TypeError, "each structure rule must be an 11-element tuple; use "
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

    size_t        min_length = PyLong_AsSize_t(min_length_obj);
    size_t        max_length = PyErr_Occurred() ? 0 : PyLong_AsSize_t(max_length_obj);
    size_t        min_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(min_occurs_obj);
    size_t        max_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(max_occurs_obj);
    long          kind = PyErr_Occurred() ? 0 : PyLong_AsLong(kind_obj);
    unsigned long flags =
        PyErr_Occurred() ? 0 : PyLong_AsUnsignedLong(PyTuple_GetItem(rule_obj, 7));
    size_t        multiple = PyErr_Occurred() ? 0 : PyLong_AsSize_t(PyTuple_GetItem(rule_obj, 8));
    unsigned long group =
        PyErr_Occurred() ? 0 : PyLong_AsUnsignedLong(PyTuple_GetItem(rule_obj, 9));
    if (!PyErr_Occurred() && (flags > UINT32_MAX || group > UINT32_MAX || kind < 0 || kind > 2))
        PyErr_SetString(PyExc_ValueError, "invalid rule flags, group or kind");
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

    tlv_schema_entry_t* entry = calloc(1, sizeof(*entry));
    if (!entry) {
        free(tag_copy);
        free_structure_schema(children);
        PyErr_NoMemory();
        return 0;
    }
    out->entry = entry;
    entry->tag.data = tag_copy;
    entry->tag.size = (size_t)tag_size;
    entry->min_length = min_length;
    entry->max_length = max_length;
    entry->flags = (uint32_t)flags;
    entry->length_multiple = multiple;
    entry->name = schema_name_copy(PyTuple_GetItem(rule_obj, 10));
    out->min_occurs = min_occurs;
    out->max_occurs = max_occurs;
    out->kind = (tlv_schema_kind_t)kind;
    out->children = children;
    out->group = (uint32_t)group;
    if (PyErr_Occurred()) {
        free_structure_rule_contents(out);
        memset(out, 0, sizeof(*out));
        return 0;
    }
    return 1;
}

/* Builds a schema from (allow_unknown, rules, order, groups),
 * as opentlv.StructureSchema._to_native() produces. Returns a
 * malloc'd tree that free_structure_schema() must free, or NULL with an
 * exception set. */
static tlv_structure_schema_t* build_structure_schema(PyObject* schema_obj) {
    if (!PyTuple_Check(schema_obj) || PyTuple_Size(schema_obj) != 4) {
        PyErr_SetString(PyExc_TypeError,
                        "schema must contain allow_unknown, rules, order and groups");
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
    if ((size_t)count > SIZE_MAX / sizeof(tlv_structure_rule_t)) {
        PyErr_NoMemory();
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
    long      order = PyLong_AsLong(PyTuple_GetItem(schema_obj, 2));
    PyObject* group_objects = PyTuple_GetItem(schema_obj, 3);
    if (PyErr_Occurred() || (order != 0 && order != 1) || !PyTuple_Check(group_objects)) {
        if (!PyErr_Occurred()) PyErr_SetString(PyExc_ValueError, "invalid schema order or groups");
        free_structure_schema(schema);
        return NULL;
    }
    schema->order = (tlv_schema_order_t)order;
    size_t group_count = (size_t)PyTuple_Size(group_objects);
    if (group_count > SIZE_MAX / sizeof(tlv_structure_group_t)) {
        free_structure_schema(schema);
        return (tlv_structure_schema_t*)PyErr_NoMemory();
    }
    tlv_structure_group_t* groups = group_count ? calloc(group_count, sizeof(*groups)) : NULL;
    if (group_count && !groups) {
        free_structure_schema(schema);
        return (tlv_structure_schema_t*)PyErr_NoMemory();
    }
    schema->groups = groups;
    schema->group_count = group_count;
    for (size_t i = 0; i < group_count; ++i) {
        PyObject* item = PyTuple_GetItem(group_objects, (Py_ssize_t)i);
        if (!PyTuple_Check(item) || PyTuple_Size(item) != 4) {
            PyErr_SetString(PyExc_TypeError, "group must contain id, occurrence bounds and name");
            free_structure_schema(schema);
            return NULL;
        }
        unsigned long id = PyLong_AsUnsignedLong(PyTuple_GetItem(item, 0));
        groups[i].min_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(PyTuple_GetItem(item, 1));
        groups[i].max_occurs = PyErr_Occurred() ? 0 : PyLong_AsSize_t(PyTuple_GetItem(item, 2));
        if (!PyErr_Occurred() && id > UINT32_MAX)
            PyErr_SetString(PyExc_OverflowError, "group id exceeds uint32");
        if (PyErr_Occurred()) {
            free_structure_schema(schema);
            return NULL;
        }
        groups[i].id = (uint32_t)id;
        groups[i].name = schema_name_copy(PyTuple_GetItem(item, 3));
        if (PyErr_Occurred()) {
            free_structure_schema(schema);
            return NULL;
        }
    }
    return schema;
}

/* Copy every borrowed field before the schema and input are released. */
static PyObject* schema_diagnostic_value(const tlv_schema_diagnostic_t* diagnostic) {
    PyObject* path = PyTuple_New((Py_ssize_t)diagnostic->path.length);
    if (!path) return NULL;
    for (size_t i = 0; i < diagnostic->path.length; ++i) {
        tlv_tag_t tag = diagnostic->path.tags[i];
        PyObject* value = PyBytes_FromStringAndSize((const char*)tag.data, (Py_ssize_t)tag.size);
        if (!value) {
            Py_DECREF(path);
            return NULL;
        }
        PyTuple_SetItem(path, (Py_ssize_t)i, value);
    }
    PyObject* tag = PyBytes_FromStringAndSize((const char*)diagnostic->tag.data,
                                              (Py_ssize_t)diagnostic->tag.size);
    PyObject* offset = diagnostic->diagnostic.has_offset
                           ? PyLong_FromSize_t(diagnostic->diagnostic.offset)
                           : Py_NewRef(Py_None);
    PyObject* occurs = diagnostic->has_occurs
                           ? Py_BuildValue("(KKK)", (unsigned long long)diagnostic->min_occurs,
                                           (unsigned long long)diagnostic->max_occurs,
                                           (unsigned long long)diagnostic->occurs)
                           : Py_NewRef(Py_None);
    PyObject* length = diagnostic->has_length
                           ? Py_BuildValue("(KKK)", (unsigned long long)diagnostic->min_length,
                                           (unsigned long long)diagnostic->max_length,
                                           (unsigned long long)diagnostic->actual_length)
                           : Py_NewRef(Py_None);
    PyObject* form = diagnostic->has_form ? Py_BuildValue("(ii)", (int)diagnostic->expected_form,
                                                          diagnostic->actual_constructed)
                                          : Py_NewRef(Py_None);
    /* N consumes each reference, including on failure. */
    return Py_BuildValue(
        "(iiisNNNziNNNKI)", (int)diagnostic->diagnostic.code, (int)diagnostic->diagnostic.severity,
        (int)diagnostic->kind, tlv_schema_issue_kind_string(diagnostic->kind), tag, path, offset,
        diagnostic->field, diagnostic->is_group, occurs, length, form,
        (unsigned long long)diagnostic->length_multiple, (unsigned int)diagnostic->length_flags);
}

static PyObject* schema_diagnostic_report(const Py_buffer* buffer, const tlv_format_t* format,
                                          const tlv_structure_schema_t* schema, size_t max_depth,
                                          size_t max_elements, size_t capacity,
                                          tlv_schema_unknown_policy_t unknown) {
    tlv_schema_diagnostic_t* storage = capacity ? calloc(capacity, sizeof(*storage)) : NULL;
    if (capacity && !storage) return PyErr_NoMemory();
    tlv_schema_diagnostic_report_t report = {storage, capacity, 0};
    size_t                         offset = 0;
    tlv_result_t                   code =
        tlv_schema_validate_all_diag(buffer->buf, (size_t)buffer->len, format, schema, max_depth,
                                     max_elements, unknown, &report, &offset);
    PyObject* result = NULL;
    if (code == TLV_OK || code == TLV_ERR_SCHEMA) {
        size_t    stored = report.count < capacity ? report.count : capacity;
        PyObject* items = PyTuple_New((Py_ssize_t)stored);
        if (items) {
            for (size_t i = 0; i < stored; ++i) {
                PyObject* item = schema_diagnostic_value(&storage[i]);
                if (!item) {
                    Py_CLEAR(items);
                    break;
                }
                PyTuple_SetItem(items, (Py_ssize_t)i, item);
            }
            if (items) result = Py_BuildValue("(NN)", PyLong_FromSize_t(report.count), items);
        }
    } else
        raise_code_and_offset(code, offset);
    free(storage);
    return result;
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
    PyObject*  format_obj;
    PyObject*  schema_obj;
    Py_ssize_t max_depth, max_elements;
    Py_ssize_t report_capacity = -1;
    int        unknown = 0;
    if (!PyArg_ParseTuple(args, "y*OOnn|ni", &buffer, &format_obj, &schema_obj, &max_depth,
                          &max_elements, &report_capacity, &unknown)) {
        return NULL;
    }
    tlv_fixed_format_t  fixed;
    tlv_format_t        descriptor;
    const tlv_format_t* format = NULL;
    if (PyTuple_Check(format_obj)) {
        Py_ssize_t tag_size, length_size;
        int        big_endian;
        if (!PyArg_ParseTuple(format_obj, "nnp", &tag_size, &length_size, &big_endian)) {
            PyBuffer_Release(&buffer);
            return NULL;
        }
        if (tag_size < 0 || length_size < 0) {
            PyBuffer_Release(&buffer);
            PyErr_SetString(PyExc_ValueError, "negative format width");
            return NULL;
        }
        fixed.tag_size = (size_t)tag_size;
        fixed.length_size = (size_t)length_size;
        fixed.length_order = big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
        fixed.element_order = TLV_ELEMENT_ORDER_TLV;
        fixed.length_scope = TLV_LENGTH_SCOPE_VALUE;
        tlv_result_t rc = tlv_fixed_format_init(&descriptor, &fixed);
        if (rc != TLV_OK) {
            PyBuffer_Release(&buffer);
            raise_code_only(rc);
            return NULL;
        }
        format = &descriptor;
    } else {
        long format_id = PyLong_AsLong(format_obj);
        if (PyErr_Occurred()) {
            PyBuffer_Release(&buffer);
            return NULL;
        }
        if (format_id >= 0 && format_id <= INT_MAX)
            format = opentlv_python_format_for((int)format_id);
    }
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
    if (PyTuple_Size(args) > 5 &&
        (report_capacity < 0 ||
         (size_t)report_capacity > SIZE_MAX / sizeof(tlv_schema_diagnostic_t))) {
        PyBuffer_Release(&buffer);
        PyErr_SetString(PyExc_ValueError, "invalid report capacity");
        return NULL;
    }

    tlv_structure_schema_t* schema = build_structure_schema(schema_obj);
    if (schema == NULL) {
        PyBuffer_Release(&buffer);
        return NULL;
    }

    size_t error_offset = 0;
    if (report_capacity >= 0) {
        PyObject* result = schema_diagnostic_report(&buffer, format, schema, (size_t)max_depth,
                                                    (size_t)max_elements, (size_t)report_capacity,
                                                    (tlv_schema_unknown_policy_t)unknown);
        free_structure_schema(schema);
        PyBuffer_Release(&buffer);
        return result;
    }
    tlv_result_t code =
        tlv_schema_validate((const uint8_t*)buffer.buf, (size_t)buffer.len, format, schema,
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

/* Names do not participate in lookup; the facade retains them in its records. */
static PyObject* opentlv_native_definition_find(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *tags, *wanted;
    if (!PyArg_ParseTuple(args, "OO", &tags, &wanted)) return NULL;
    if (!PyTuple_Check(tags) || !PyBytes_Check(wanted)) {
        PyErr_SetString(PyExc_TypeError, "immutable tag tuple and bytes required");
        return NULL;
    }
    size_t count = (size_t)PyTuple_Size(tags);
    if (count > SIZE_MAX / sizeof(tlv_definition_t)) return PyErr_NoMemory();
    tlv_definition_t* entries = count ? calloc(count, sizeof(*entries)) : NULL;
    if (count && !entries) return PyErr_NoMemory();
    for (size_t i = 0; i < count; ++i) {
        PyObject* tag = PyTuple_GetItem(tags, (Py_ssize_t)i);
        if (!PyBytes_Check(tag)) {
            free(entries);
            PyErr_SetString(PyExc_TypeError, "immutable tag bytes required");
            return NULL;
        }
        entries[i].tag = tlv_tag((const uint8_t*)PyBytes_AsString(tag), (size_t)PyBytes_Size(tag));
    }
    tlv_tag_t tag = tlv_tag((const uint8_t*)PyBytes_AsString(wanted), (size_t)PyBytes_Size(wanted));
    tlv_definition_registry_t registry = {entries, count};
    const tlv_definition_t*   found = tlv_definition_find(&registry, &tag);
    PyObject* result = found ? PyLong_FromSize_t((size_t)(found - entries)) : Py_NewRef(Py_None);
    free(entries);
    return result;
}

static PyObject* opentlv_native_number_codec(PyObject* module, PyObject* args) {
    (void)module;
    int        operation, encoding;
    Py_ssize_t width;
    PyObject*  digits_obj;
    PyObject*  input;
    PyObject*  output = Py_None;
    if (!PyArg_ParseTuple(args, "iinOO|O", &operation, &encoding, &width, &digits_obj, &input,
                          &output))
        return NULL;
    if (width < 0) {
        PyErr_SetString(PyExc_ValueError, "negative codec width");
        return NULL;
    }
    unsigned long digits = PyLong_AsUnsignedLong(digits_obj);
    if (PyErr_Occurred()) return NULL;
    if (digits > UINT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "digits exceed unsigned int");
        return NULL;
    }
    tlv_number_codec_config_t config = {(tlv_number_encoding_t)encoding, (size_t)width,
                                        (unsigned int)digits};
    uint64_t                  value = 0;
    tlv_codec_result_t        code;
    if (operation == 0) {
        Py_buffer data;
        if (PyObject_GetBuffer(input, &data, PyBUF_SIMPLE) < 0) return NULL;
        code = tlv_number_decode(&config, data.buf, (size_t)data.len, &value, sizeof(value));
        PyBuffer_Release(&data);
        if (code != TLV_CODEC_OK) {
            raise_codec_error(code);
            return NULL;
        }
        return PyLong_FromUnsignedLongLong(value);
    }
    value = PyLong_AsUnsignedLongLong(input);
    if (PyErr_Occurred()) return NULL;
    size_t written = 0;
    if (operation == 3) {
        Py_buffer buffer;
        if (PyObject_GetBuffer(output, &buffer, PyBUF_WRITABLE) < 0) return NULL;
        code = tlv_number_encode(&config, &value, sizeof(value), buffer.buf, (size_t)buffer.len,
                                 &written);
        PyBuffer_Release(&buffer);
        if (code != TLV_CODEC_OK) {
            raise_codec_error(code);
            return NULL;
        }
        return PyLong_FromSize_t(written);
    }
    if (operation != 1 && operation != 2) {
        PyErr_SetString(PyExc_ValueError, "unknown codec operation");
        return NULL;
    }
    code = tlv_number_encode(&config, &value, sizeof(value), NULL, 0, &written);
    if (code != TLV_CODEC_OK) {
        raise_codec_error(code);
        return NULL;
    }
    if (operation == 2) return PyLong_FromSize_t(written);
    /* Numeric C representations never exceed nine bytes; size query already validates. */
    uint8_t bytes[9];
    code = tlv_number_encode(&config, &value, sizeof(value), bytes, sizeof(bytes), &written);
    if (code != TLV_CODEC_OK) {
        raise_codec_error(code);
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char*)bytes, (Py_ssize_t)written);
}

#if OPENTLV_EMV
/* emv_decode_amount(data) -> int
 *
 * Decodes 6 bytes of BCD (EMV format n12) into an unscaled minor-unit
 * amount, using the public `tlv_emv_codec_amount` codec. Raises opentlv_native.CodecError
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

#endif

#define DOCUMENT_CAPSULE_NAME "opentlv_native.Document"

static void document_capsule_destructor(PyObject* capsule) {
    tlv_document_t* document =
        (tlv_document_t*)PyCapsule_GetPointer(capsule, DOCUMENT_CAPSULE_NAME);
    if (document != NULL) {
        tlv_document_free(document);
    }
    PyObject* owner = PyCapsule_GetContext(capsule);
    Py_XDECREF(owner);
}

/* Keep Format storage alive for documents built from a cursor-owned descriptor. */
PyObject* opentlv_python_document_wrap(tlv_document_t* document, PyObject* owner) {
    PyObject* capsule = PyCapsule_New(document, DOCUMENT_CAPSULE_NAME, document_capsule_destructor);
    if (!capsule) {
        tlv_document_free(document);
        return NULL;
    }
    if (owner) {
        if (PyCapsule_SetContext(capsule, owner) < 0) {
            Py_DECREF(capsule);
            return NULL;
        }
        Py_INCREF(owner);
    }
    return capsule;
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

/* Builds document options from a Python-supplied format ID and limits.
 * Returns 1 on success; on failure an exception is set and `*out` is
 * unusable. */
static int build_document_options(int format_id, Py_ssize_t max_depth, Py_ssize_t max_elements,
                                  tlv_document_options_t* out) {
    const tlv_format_t* format = opentlv_python_format_for(format_id);
    if (format == NULL) {
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return 0;
    }
    if (max_depth < 0 || max_elements < 0) {
        PyErr_SetString(PyExc_ValueError, "max_depth and max_elements must not be negative");
        return 0;
    }
    tlv_result_t code = tlv_document_options_init(out, format);
    if (code != TLV_OK) {
        raise_code_only(code);
        return 0;
    }
    out->max_depth = (size_t)max_depth;
    out->max_elements = (size_t)max_elements;
    return 1;
}

/* document_create(format, max_depth, max_elements) -> capsule
 *
 * Creates an empty document. Raises opentlv_native.Error on failure. */
static PyObject* opentlv_native_document_create(PyObject* module, PyObject* args) {
    (void)module;
    int        format_id;
    Py_ssize_t max_depth, max_elements;
    if (!PyArg_ParseTuple(args, "inn", &format_id, &max_depth, &max_elements)) {
        return NULL;
    }
    tlv_document_options_t options;
    if (!build_document_options(format_id, max_depth, max_elements, &options)) {
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

/* document_parse(data, format, max_depth, max_elements) -> capsule
 *
 * Parses `data` into a new owned document. Raises opentlv_native.Error with
 * "code" and "offset" on failure. */
static PyObject* opentlv_native_document_parse(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer;
    int        format_id;
    Py_ssize_t max_depth, max_elements;
    if (!PyArg_ParseTuple(args, "y*inn", &buffer, &format_id, &max_depth, &max_elements)) {
        return NULL;
    }
    tlv_document_options_t options;
    if (!build_document_options(format_id, max_depth, max_elements, &options)) {
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
    int       format_id = -1;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O|i", &capsule, &format_id)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    const tlv_format_t* destination = format_id == -1 ? NULL : opentlv_python_format_for(format_id);
    if (format_id != -1 && !destination) {
        PyErr_SetString(PyExc_ValueError, "unsupported destination Format");
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = (destination ? tlv_document_encoded_size_as(document, destination, &size)
                                     : tlv_document_encoded_size(document, &size));
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

static PyObject* opentlv_native_document_encode(PyObject* module, PyObject* args) {
    (void)module;
    int       format_id = -1;
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O|i", &capsule, &format_id)) {
        return NULL;
    }
    tlv_document_t* document = document_from_capsule(capsule);
    if (document == NULL) {
        return NULL;
    }
    const tlv_format_t* destination = format_id == -1 ? NULL : opentlv_python_format_for(format_id);
    if (format_id != -1 && !destination) {
        PyErr_SetString(PyExc_ValueError, "unsupported destination Format");
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = (destination ? tlv_document_encoded_size_as(document, destination, &size)
                                     : tlv_document_encoded_size(document, &size));
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    if (size > PY_SSIZE_T_MAX) {
        raise_code_only(TLV_ERR_NATIVE_SIZE);
        return NULL;
    }
    PyObject* result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (result == NULL) {
        return NULL;
    }
    char*  buf = PyBytes_AsString(result);
    size_t written = 0;
    code =
        (destination ? tlv_document_encode_as(document, destination, (uint8_t*)buf, size, &written)
                     : tlv_document_encode(document, (uint8_t*)buf, size, &written));
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
    int         format_id = -1;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&|i", py_to_node, &node, &format_id)) {
        return NULL;
    }
    const tlv_format_t* destination = format_id == -1 ? NULL : opentlv_python_format_for(format_id);
    if (format_id != -1 && !destination) {
        PyErr_SetString(PyExc_ValueError, "unsupported destination Format");
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = (destination ? tlv_node_encoded_size_as(node, destination, &size)
                                     : tlv_node_encoded_size(node, &size));
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    return PyLong_FromSize_t(size);
}

static PyObject* opentlv_native_node_encode(PyObject* module, PyObject* args) {
    (void)module;
    int         format_id = -1;
    tlv_node_t* node;
    if (!PyArg_ParseTuple(args, "O&|i", py_to_node, &node, &format_id)) {
        return NULL;
    }
    const tlv_format_t* destination = format_id == -1 ? NULL : opentlv_python_format_for(format_id);
    if (format_id != -1 && !destination) {
        PyErr_SetString(PyExc_ValueError, "unsupported destination Format");
        return NULL;
    }
    size_t       size = 0;
    tlv_result_t code = (destination ? tlv_node_encoded_size_as(node, destination, &size)
                                     : tlv_node_encoded_size(node, &size));
    if (code != TLV_OK) {
        raise_code_only(code);
        return NULL;
    }
    if (size > PY_SSIZE_T_MAX) {
        raise_code_only(TLV_ERR_NATIVE_SIZE);
        return NULL;
    }
    PyObject* result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)size);
    if (result == NULL) {
        return NULL;
    }
    char*  buf = PyBytes_AsString(result);
    size_t written = 0;
    code = (destination ? tlv_node_encode_as(node, destination, (uint8_t*)buf, size, &written)
                        : tlv_node_encode(node, (uint8_t*)buf, size, &written));
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

/* read(data, offset, format) -> (tag: bytes, length_offset: int, length_size: int, value_offset:
 * int, value_length: int, consumed: int)
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
    const tlv_format_t* format = opentlv_python_format_for(format_id);
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
    tlv_element_t           element;
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diag;
    tlv_reader_diagnostic_init(&diag);

    tlv_source_t source;
    tlv_result_t code =
        tlv_read_source_diag(base + offset, size, format, &element, &consumed, &source, &diag);
    if (code != TLV_OK) {
        raise_reader_error(code, &diag);
        PyBuffer_Release(&buffer);
        return NULL;
    }

    size_t value_length = 0;
    code = tlv_size_to_native(element.value.size, &value_length);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_code_only(code);
        return NULL;
    }
    Py_ssize_t value_offset =
        value_length == 0 ? 0 : (Py_ssize_t)((const uint8_t*)element.value.data - base);

    Py_ssize_t length_offset =
        source.length.size ? (Py_ssize_t)(source.data + source.length.offset - base) : 0;
    PyObject* tag_obj =
        PyBytes_FromStringAndSize((const char*)element.tag.data, (Py_ssize_t)element.tag.size);
    PyBuffer_Release(&buffer);
    if (tag_obj == NULL) {
        return NULL;
    }
    PyObject* consumed_obj = PyLong_FromSize_t(consumed);
    if (consumed_obj == NULL) {
        Py_DECREF(tag_obj);
        return NULL;
    }

    return Py_BuildValue("(NnnnnN)", tag_obj, length_offset, (Py_ssize_t)source.length.size,
                         value_offset, (Py_ssize_t)value_length, consumed_obj);
}

/* Copy an unvalidated range with the sequential Writer capacity/diagnostic contract. */
static PyObject* opentlv_native_copy_encoded(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  buffer, encoded;
    Py_ssize_t offset;
    if (!PyArg_ParseTuple(args, "w*ny*", &buffer, &offset, &encoded)) return NULL;
    if (offset < 0 || offset > buffer.len) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&encoded);
        PyErr_SetString(PyExc_ValueError, "offset is out of range for buffer");
        return NULL;
    }
    /* Raw copying deliberately does not use a Format. */
    tlv_writer_t writer = {NULL, (uint8_t*)buffer.buf, (size_t)buffer.len, (size_t)offset};
    tlv_writer_diagnostic_t diag;
    tlv_writer_diagnostic_init(&diag);
    tlv_result_t code = tlv_writer_copy_encoded_diag(&writer, (const uint8_t*)encoded.buf,
                                                     (size_t)encoded.len, &diag);
    PyBuffer_Release(&buffer);
    PyBuffer_Release(&encoded);
    if (code != TLV_OK) {
        raise_writer_error(code, &diag);
        return NULL;
    }
    return PyLong_FromSize_t(writer.pos - (size_t)offset);
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
    const tlv_format_t* format = opentlv_python_format_for(format_id);
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
        if (diag.diagnostic.has_offset) {
            if (diag.diagnostic.offset > SIZE_MAX - (size_t)offset)
                diag.diagnostic.has_offset = 0;
            else
                diag.diagnostic.offset += (size_t)offset;
        }
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
    const tlv_format_t* format = opentlv_python_format_for(format_id);
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

static PyObject* opentlv_native_element_encoded_size(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer tag_buf, value_buf;

    int format_id;
    if (!PyArg_ParseTuple(args, "y*y*i", &tag_buf, &value_buf, &format_id)) {
        return NULL;
    }
    const tlv_format_t* format = opentlv_python_format_for(format_id);
    if (format == NULL) {
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        PyErr_SetString(PyExc_ValueError, "unknown format");
        return NULL;
    }

    tlv_tag_t           tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    size_t              size = 0;
    const tlv_element_t element = {tag, {(const uint8_t*)value_buf.buf, (tlv_size_t)value_buf.len}};
    tlv_writer_diagnostic_t diag;
    tlv_result_t            code = tlv_element_encoded_size_diag(&element, format, &size, &diag);
    if (code != TLV_OK) raise_writer_error(code, &diag);
    PyBuffer_Release(&tag_buf);
    PyBuffer_Release(&value_buf);
    if (code != TLV_OK) return NULL;
    return PyLong_FromSize_t(size);
}

/* Builds and validates a tlv_fixed_format_t from Python-parsed arguments.
 * Returns 1 on success; on failure a ValueError is set and *out is unusable. */
static int fixed_config_from_args(Py_ssize_t tag_size, Py_ssize_t length_size, int big_endian,
                                  tlv_fixed_format_t* out) {
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
    out->length_order = big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
    out->element_order = TLV_ELEMENT_ORDER_TLV;
    out->length_scope = TLV_LENGTH_SCOPE_VALUE;
    return 1;
}

/* read_fixed(data, offset, tag_size, length_size, big_endian)
 *     -> (tag: bytes, length_offset: int, length_size: int, value_offset: int, value_length: int,
 * consumed: int)
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
    tlv_fixed_format_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&buffer);
        return NULL;
    }
    tlv_format_t format;
    tlv_result_t init_code = tlv_fixed_format_init(&format, &config);
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
    tlv_element_t           element;
    size_t                  consumed = 0;
    tlv_reader_diagnostic_t diag;
    tlv_reader_diagnostic_init(&diag);

    tlv_source_t source;
    tlv_result_t code =
        tlv_read_source_diag(base + offset, size, &format, &element, &consumed, &source, &diag);
    if (code != TLV_OK) {
        raise_reader_error(code, &diag);
        PyBuffer_Release(&buffer);
        return NULL;
    }

    size_t value_length = 0;
    code = tlv_size_to_native(element.value.size, &value_length);
    if (code != TLV_OK) {
        PyBuffer_Release(&buffer);
        raise_code_only(code);
        return NULL;
    }
    Py_ssize_t value_offset =
        value_length == 0 ? 0 : (Py_ssize_t)((const uint8_t*)element.value.data - base);

    Py_ssize_t length_offset =
        source.length.size ? (Py_ssize_t)(source.data + source.length.offset - base) : 0;
    PyObject* tag_obj =
        PyBytes_FromStringAndSize((const char*)element.tag.data, (Py_ssize_t)element.tag.size);
    PyBuffer_Release(&buffer);
    if (tag_obj == NULL) {
        return NULL;
    }
    PyObject* consumed_obj = PyLong_FromSize_t(consumed);
    if (consumed_obj == NULL) {
        Py_DECREF(tag_obj);
        return NULL;
    }

    return Py_BuildValue("(NnnnnN)", tag_obj, length_offset, (Py_ssize_t)source.length.size,
                         value_offset, (Py_ssize_t)value_length, consumed_obj);
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
    tlv_fixed_format_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&buffer);
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        return NULL;
    }
    tlv_format_t format;
    tlv_result_t init_code = tlv_fixed_format_init(&format, &config);
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
        if (diag.diagnostic.has_offset) {
            if (diag.diagnostic.offset > SIZE_MAX - (size_t)offset)
                diag.diagnostic.has_offset = 0;
            else
                diag.diagnostic.offset += (size_t)offset;
        }
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
    tlv_fixed_format_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&tag_buf);
        return NULL;
    }
    tlv_format_t format;
    tlv_result_t init_code = tlv_fixed_format_init(&format, &config);
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

static PyObject* opentlv_native_element_encoded_size_fixed(PyObject* module, PyObject* args) {
    (void)module;
    Py_buffer  tag_buf, value_buf;
    Py_ssize_t tag_size, length_size;
    int        big_endian;
    if (!PyArg_ParseTuple(args, "y*y*nnp", &tag_buf, &value_buf, &tag_size, &length_size,
                          &big_endian)) {
        return NULL;
    }
    tlv_fixed_format_t config;
    if (!fixed_config_from_args(tag_size, length_size, big_endian, &config)) {
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        return NULL;
    }
    tlv_format_t format;
    tlv_result_t init_code = tlv_fixed_format_init(&format, &config);
    if (init_code != TLV_OK) {
        PyBuffer_Release(&tag_buf);
        PyBuffer_Release(&value_buf);
        raise_code_only(init_code);
        return NULL;
    }

    tlv_tag_t           tag = tlv_tag((const uint8_t*)tag_buf.buf, (size_t)tag_buf.len);
    size_t              size = 0;
    const tlv_element_t element = {tag, {(const uint8_t*)value_buf.buf, (tlv_size_t)value_buf.len}};
    tlv_writer_diagnostic_t diag;
    tlv_result_t            code = tlv_element_encoded_size_diag(&element, &format, &size, &diag);
    if (code != TLV_OK) raise_writer_error(code, &diag);
    PyBuffer_Release(&tag_buf);
    PyBuffer_Release(&value_buf);
    if (code != TLV_OK) return NULL;
    return PyLong_FromSize_t(size);
}

void opentlv_python_raise_reader(tlv_result_t code, const tlv_reader_diagnostic_t* diagnostic) {
    raise_reader_error(code, diagnostic);
}

void opentlv_python_raise_writer(tlv_result_t code, const tlv_writer_diagnostic_t* diagnostic) {
    raise_writer_error(code, diagnostic);
}

static PyMethodDef opentlv_native_methods[] = {
    {"length_schema", opentlv_python_length_schema, METH_VARARGS,
     "Find or validate a length rule through the canonical C schema engine."},
    {"source_preserve", opentlv_python_source_preserve, METH_VARARGS,
     "Preserve retained immutable source bytes after C semantic equality checks."},
    {"document_builder_create", opentlv_python_builder_create, METH_VARARGS,
     "Materialize a whole stream or next subtree through the C builder."},
    {"document_builder_consume", opentlv_python_builder_consume, METH_O,
     "Resume materialization and transfer a completed document."},
    {"tree_writer_measure", opentlv_python_tree_writer_measure, METH_VARARGS,
     "Measure and stage a preorder source through C."},
    {"tree_writer_create", opentlv_python_tree_writer_create, METH_VARARGS,
     "Create bounded canonical tree output."},
    {"tree_writer_action", opentlv_python_tree_writer_action, METH_VARARGS,
     "Operate the canonical C Tree Writer."},
    {"cursor_create", opentlv_python_cursor_create, METH_VARARGS,
     "Create a canonical C Reader cursor."},
    {"cursor_event", opentlv_python_cursor_event, METH_O, "Pull a structural tree event."},
    {"tree_writer_tags", opentlv_python_tree_writer_tags, METH_VARARGS,
     "Configure bounded Tag storage."},
    {"tree_writer_event", opentlv_python_tree_writer_event, METH_VARARGS,
     "Consume a structural event."},
    {"cursor_next", opentlv_python_cursor_next, METH_O, "Pull complete content and source ranges."},
    {"cursor_input", opentlv_python_cursor_input, METH_VARARGS, "Replace a cursor input window."},
    {"cursor_status", opentlv_python_cursor_status, METH_O,
     "Return consumed bytes, absolute offset and final exhaustion."},
    {"cursor_skip", opentlv_python_cursor_skip, METH_O, "Skip the pending subtree."},
    {"cursor_visit", opentlv_python_cursor_visit, METH_VARARGS,
     "Visit through the C traversal engine."},
    {"query_create", opentlv_python_query_create, METH_O, "Parse or copy a canonical Query."},
    {"query_steps", opentlv_python_query_steps, METH_O, "Return query path tags."},
    {"query_matches", opentlv_python_query_matches, METH_VARARGS,
     "Feed a preorder item to the C matcher."},
    {"query_visit", opentlv_python_query_visit, METH_VARARGS,
     "Visit matches through the C Query engine."},
    {"version_string", opentlv_native_version_string, METH_NOARGS,
     "Return the version of the linked OpenTLV C library, for example \"0.6.0\"."},
    {"strerror", opentlv_native_strerror, METH_VARARGS,
     "Return the readable description of a tlv_result_t code."},
    {"read", opentlv_native_read, METH_VARARGS,
     "Parse one element at an offset in a buffer using a wire format."},
    {"write", opentlv_native_write, METH_VARARGS,
     "Encode one element at an offset in a writable buffer using a wire format."},
    {"copy_encoded", opentlv_native_copy_encoded, METH_VARARGS,
     "Copy raw bytes into caller storage without format conversion."},
    {"element_encoded_size", opentlv_native_element_encoded_size, METH_VARARGS,
     "Measure exact output storage using semantic content."},
    {"element_encoded_size_fixed", opentlv_native_element_encoded_size_fixed, METH_VARARGS,
     "Measure exact output storage for a fixed format Element."},
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
    {"definition_find", opentlv_native_definition_find, METH_VARARGS,
     "Find the first generic C Definition."},
    {"number_codec", opentlv_native_number_codec, METH_VARARGS,
     "Configured C numeric Value codec."},
    {"codec_strerror", opentlv_native_codec_strerror, METH_VARARGS,
     "Return the readable description of a tlv_codec_result_t code."},
#if OPENTLV_EMV
    {"emv_decode_amount", opentlv_native_emv_decode_amount, METH_VARARGS,
     "Decode 6 bytes of BCD (EMV format n12) into an unscaled minor-unit amount."},
    {"emv_encode_amount", opentlv_native_emv_encode_amount, METH_VARARGS,
     "Encode an unscaled minor-unit amount as 6 bytes of BCD (EMV format n12)."},
#endif
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
    if (opentlv_python_register_formats(module) < 0) {
        Py_DECREF(module);
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
