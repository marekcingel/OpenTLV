#define PY_SSIZE_T_CLEAN
#include "reader.h"
#include "format.h"
#include "writer.h"
#include <tlv/formats/fixed.h>
#include <tlv/reader/tree.h>
#include <tlv/reader/visitor.h>
#include <tlv/query/query.h>
#include <stdlib.h>
#include <string.h>

#define CURSOR_NAME "opentlv.reader"
#define BUILDER_NAME "opentlv.document_builder"
#define SOURCE_NAME "opentlv.source"
typedef struct source_state {
    tlv_source_t source;
    PyObject*    input;
    PyObject*    owner;
} source_state;

static void destroy_source(PyObject* capsule) {
    source_state* self = PyCapsule_GetPointer(capsule, SOURCE_NAME);
    if (!self) return;
    Py_DECREF(self->input);
    Py_DECREF(self->owner);
    free(self);
}

PyObject* opentlv_python_source_preserve(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  capsule;
    Py_buffer  output, tag, value;
    Py_ssize_t offset;
    if (!PyArg_ParseTuple(args, "Ow*ny*y*", &capsule, &output, &offset, &tag, &value)) return NULL;
    source_state* self = PyCapsule_GetPointer(capsule, SOURCE_NAME);
    if (!self || offset < 0 || offset > output.len) {
        if (self) PyErr_SetString(PyExc_ValueError, "output offset out of range");
        PyBuffer_Release(&output);
        PyBuffer_Release(&tag);
        PyBuffer_Release(&value);
        return NULL;
    }
    tlv_writer_t  writer = {NULL, output.buf, (size_t)output.len, (size_t)offset};
    tlv_element_t element = {tlv_tag(tag.buf, (size_t)tag.len), {value.buf, (tlv_size_t)value.len}};
    tlv_writer_diagnostic_t diagnostic;
    tlv_writer_diagnostic_init(&diagnostic);
    tlv_result_t code = tlv_writer_preserve_diag(&writer, &self->source, &element, &diagnostic);
    /* Convert while buffer-protocol exporters and all borrowed diagnostics are pinned. */
    if (code != TLV_OK) opentlv_python_raise_writer(code, &diagnostic);
    PyBuffer_Release(&output);
    PyBuffer_Release(&tag);
    PyBuffer_Release(&value);
    if (code != TLV_OK) return NULL;
    return PyLong_FromSize_t(writer.pos - (size_t)offset);
}
typedef struct cursor {
    PyObject*          input;
    tlv_fixed_format_t fixed;
    tlv_format_t       format;
    tlv_reader_t       reader;
    tlv_tree_reader_t  tree;
    tlv_tree_item_t    current;
    int                has_current;
    tlv_tree_frame_t*  frames;
    int                nested;
    int                busy;
    int                building;
} cursor;

static int idle(cursor* self) {
    if (!self) return 0;
    if (self->busy) {
        PyErr_SetString(PyExc_RuntimeError, "cannot access a cursor inside its Visitor callback");
        return 0;
    }
    return 1;
}

static int available(cursor* self) {
    if (!idle(self)) return 0;
    if (self->building) {
        PyErr_SetString(PyExc_RuntimeError, "cursor is owned by an active DocumentBuilder");
        return 0;
    }
    return 1;
}

typedef struct builder_state {
    tlv_document_builder_t* builder;
    PyObject*               owner;
    cursor*                 reader;
} builder_state;

static void release_builder(builder_state* self) {
    if (self->builder) {
        tlv_document_builder_free(self->builder);
        self->builder = NULL;
        self->reader->building = 0;
    }
}

static void destroy_builder(PyObject* capsule) {
    builder_state* self = PyCapsule_GetPointer(capsule, BUILDER_NAME);
    if (!self) return;
    release_builder(self);
    Py_DECREF(self->owner);
    free(self);
}

PyObject* opentlv_python_builder_create(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  owner;
    int        subtree;
    Py_ssize_t depth, count;
    if (!PyArg_ParseTuple(args, "Oinn", &owner, &subtree, &depth, &count)) return NULL;
    cursor* reader = PyCapsule_GetPointer(owner, CURSOR_NAME);
    if (!available(reader)) return NULL;
    if (!reader->nested || depth < 0 || count < 0) {
        PyErr_SetString(PyExc_ValueError, "TreeReader and nonnegative limits required");
        return NULL;
    }
    tlv_document_options_t options;
    tlv_result_t           code = tlv_document_options_init(&options, &reader->format);
    if (code != TLV_OK) {
        opentlv_python_raise_reader(code, NULL);
        return NULL;
    }
    options.max_depth = (size_t)depth;
    options.max_elements = (size_t)count;
    builder_state* self = calloc(1, sizeof(*self));
    if (!self) return PyErr_NoMemory();
    tlv_tree_item_t root = reader->current;
    int             has_current = reader->has_current;
    reader->has_current = 0;
    tlv_reader_diagnostic_t diagnostic;
    tlv_reader_diagnostic_init(&diagnostic);
    if (subtree == 2) {
        if (!has_current) code = TLV_ERR_INVALID_ARG;
    } else if (subtree == 1) {
        code = tlv_tree_reader_next_diag(&reader->tree, &root, &diagnostic);
    } else if (subtree != 0) {
        code = TLV_ERR_INVALID_ARG;
    }
    if (code == TLV_OK)
        code = tlv_document_builder_create(&options, &reader->tree, subtree ? &root : NULL,
                                           &self->builder);
    if (code != TLV_OK) {
        free(self);
        opentlv_python_raise_reader(code, &diagnostic);
        return NULL;
    }
    self->owner = Py_NewRef(owner);
    self->reader = reader;
    reader->building = 1;
    PyObject* capsule = PyCapsule_New(self, BUILDER_NAME, destroy_builder);
    if (!capsule) {
        release_builder(self);
        Py_DECREF(self->owner);
        free(self);
    }
    return capsule;
}

PyObject* opentlv_python_builder_consume(PyObject* module, PyObject* capsule) {
    (void)module;
    builder_state* self = PyCapsule_GetPointer(capsule, BUILDER_NAME);
    if (!self) return NULL;
    if (!self->builder) {
        PyErr_SetString(PyExc_ValueError, "builder already completed or failed");
        return NULL;
    }
    tlv_document_t*         document = NULL;
    size_t                  offset = SIZE_MAX;
    tlv_reader_diagnostic_t diagnostic;
    tlv_reader_diagnostic_init(&diagnostic);
    tlv_result_t code =
        tlv_document_builder_consume(self->builder, &document, &offset, &diagnostic);
    if (code != TLV_NEED_MORE_DATA) release_builder(self);
    if (code != TLV_OK) {
        if (offset != SIZE_MAX && !diagnostic.diagnostic.has_offset) {
            diagnostic.diagnostic.has_offset = 1;
            diagnostic.diagnostic.offset = offset;
        }
        opentlv_python_raise_reader(code, &diagnostic);
        return NULL;
    }
    return opentlv_python_document_wrap(document, self->owner);
}

static void destroy(PyObject* capsule) {
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!self) return;
    Py_XDECREF(self->input);
    free(self->frames);
    free(self);
}

PyObject* opentlv_python_cursor_create(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  input;
    int        format_id, final_input, nested, big_endian;
    Py_ssize_t capacity, depth, count, tag_size, length_size;
    if (!PyArg_ParseTuple(args, "Oippnnnnnp", &input, &format_id, &final_input, &nested, &capacity,
                          &depth, &count, &tag_size, &length_size, &big_endian))
        return NULL;
    if (!PyBytes_Check(input) || capacity < 0 || depth < 0 || count < 0 ||
        (size_t)capacity > SIZE_MAX / sizeof(tlv_tree_frame_t)) {
        PyErr_SetString(PyExc_ValueError, "immutable bytes and nonnegative limits required");
        return NULL;
    }
    cursor* self = calloc(1, sizeof(*self));
    if (!self) return PyErr_NoMemory();
    tlv_result_t code = TLV_OK;
    if (format_id == -1) {
        if (tag_size < 1 || length_size < 1 || length_size > 8)
            code = TLV_ERR_INVALID_ARG;
        else {
            self->fixed.tag_size = (size_t)tag_size;
            self->fixed.length_size = (size_t)length_size;
            self->fixed.length_order =
                big_endian ? TLV_BYTE_ORDER_BIG_ENDIAN : TLV_BYTE_ORDER_LITTLE_ENDIAN;
            self->fixed.element_order = TLV_ELEMENT_ORDER_TLV;
            self->fixed.length_scope = TLV_LENGTH_SCOPE_VALUE;
            code = tlv_fixed_format_init(&self->format, &self->fixed);
        }
    } else {
        const tlv_format_t* format = opentlv_python_format_for(format_id);
        if (!format)
            code = TLV_ERR_INVALID_ARG;
        else
            self->format = *format;
    }
    if (code != TLV_OK) {
        free(self);
        opentlv_python_raise_reader(code, NULL);
        return NULL;
    }
    if (nested && capacity) {
        self->frames = calloc((size_t)capacity, sizeof(*self->frames));
        if (!self->frames) {
            free(self);
            return PyErr_NoMemory();
        }
    }
    self->nested = nested;
    self->input = Py_NewRef(input);
    const uint8_t* data = (const uint8_t*)PyBytes_AsString(input);
    size_t         size = (size_t)PyBytes_Size(input);
    if (nested) {
        code = final_input
                   ? tlv_tree_reader_init(&self->tree, data, size, &self->format, self->frames,
                                          (size_t)capacity, (size_t)depth, (size_t)count)
                   : tlv_tree_reader_init_incremental(&self->tree, data, size, &self->format,
                                                      self->frames, (size_t)capacity, (size_t)depth,
                                                      (size_t)count);
    } else {
        code = final_input ? tlv_reader_init(&self->reader, data, size, &self->format)
                           : tlv_reader_init_incremental(&self->reader, data, size, &self->format);
    }
    PyObject* capsule = PyCapsule_New(self, CURSOR_NAME, destroy);
    if (!capsule) {
        Py_DECREF(self->input);
        free(self->frames);
        free(self);
        return NULL;
    }
    if (code != TLV_OK) {
        Py_DECREF(capsule);
        opentlv_python_raise_reader(code, NULL);
        return NULL;
    }
    return capsule;
}

static PyObject* range_object(tlv_range_t range) {
    if (!range.present) return Py_NewRef(Py_None);
    return Py_BuildValue("(nn)", (Py_ssize_t)range.offset, (Py_ssize_t)range.size);
}

PyObject* opentlv_python_cursor_next(PyObject* module, PyObject* capsule) {
    (void)module;
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!available(self)) return NULL;
    self->has_current = 0;
    tlv_tree_item_t         item = {0};
    tlv_reader_diagnostic_t diagnostic;
    tlv_reader_diagnostic_init(&diagnostic);
    item.offset = tlv_reader_offset(&self->reader);
    tlv_result_t code = self->nested ? tlv_tree_reader_next_diag(&self->tree, &item, &diagnostic)
                                     : tlv_reader_next_source_diag(&self->reader, &item.element,
                                                                   &item.source, &diagnostic);
    if (code == TLV_ERR_END_OF_BUFFER) return Py_NewRef(Py_None);
    if (code != TLV_OK) {
        opentlv_python_raise_reader(code, &diagnostic);
        return NULL;
    }
    PyObject* tag = PyBytes_FromStringAndSize((const char*)item.element.tag.data,
                                              (Py_ssize_t)item.element.tag.size);
    if (!tag) return NULL;
    PyObject* layout =
        Py_BuildValue("(NNNNN)", range_object(item.source.header), range_object(item.source.tag),
                      range_object(item.source.length), range_object(item.source.value),
                      range_object(item.source.trailer));
    if (!layout) {
        Py_DECREF(tag);
        return NULL;
    }
    source_state* source = malloc(sizeof(*source));
    if (!source) {
        Py_DECREF(tag);
        Py_DECREF(layout);
        return PyErr_NoMemory();
    }
    source->source = item.source;
    source->input = Py_NewRef(self->input);
    source->owner = Py_NewRef(capsule);
    PyObject* source_capsule = PyCapsule_New(source, SOURCE_NAME, destroy_source);
    if (!source_capsule) {
        Py_DECREF(tag);
        Py_DECREF(layout);
        Py_DECREF(source->input);
        Py_DECREF(source->owner);
        free(source);
        return NULL;
    }
    self->current = item;
    self->has_current = self->nested;
    return Py_BuildValue(
        "(NnnNnniN)", tag,
        (Py_ssize_t)(item.source.data - (const uint8_t*)PyBytes_AsString(self->input)),
        (Py_ssize_t)item.source.size, layout, (Py_ssize_t)item.depth, (Py_ssize_t)item.offset,
        item.constructed, source_capsule);
}

PyObject* opentlv_python_cursor_input(PyObject* module, PyObject* args) {
    (void)module;
    PyObject * capsule, *input;
    Py_ssize_t discard;
    int        final_input;
    if (!PyArg_ParseTuple(args, "OOnp", &capsule, &input, &discard, &final_input)) return NULL;
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!idle(self)) return NULL;
    self->has_current = 0;
    if (!PyBytes_Check(input) || discard < 0) {
        PyErr_SetString(PyExc_ValueError, "immutable bytes and nonnegative discard required");
        return NULL;
    }
    Py_ssize_t old_size = PyBytes_Size(self->input), size = PyBytes_Size(input);
    if (discard > old_size || size < old_size - discard ||
        memcmp(PyBytes_AsString(self->input) + discard, PyBytes_AsString(input),
               (size_t)(old_size - discard)) != 0) {
        opentlv_python_raise_reader(TLV_ERR_INVALID_ARG, NULL);
        return NULL;
    }
    const uint8_t* data = (const uint8_t*)PyBytes_AsString(input);
    tlv_result_t   code = self->nested ? tlv_tree_reader_set_input(&self->tree, data, (size_t)size,
                                                                   (size_t)discard, final_input)
                                       : tlv_reader_set_input(&self->reader, data, (size_t)size,
                                                              (size_t)discard, final_input);
    if (code != TLV_OK) {
        opentlv_python_raise_reader(code, NULL);
        return NULL;
    }
    PyObject* previous = self->input;
    self->input = Py_NewRef(input);
    Py_DECREF(previous);
    return Py_NewRef(Py_None);
}

PyObject* opentlv_python_cursor_status(PyObject* module, PyObject* capsule) {
    (void)module;
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!idle(self)) return NULL;
    size_t consumed =
        self->nested ? tlv_tree_reader_consumed(&self->tree) : tlv_reader_consumed(&self->reader);
    size_t offset =
        self->nested ? tlv_tree_reader_offset(&self->tree) : tlv_reader_offset(&self->reader);
    int end = self->nested ? tlv_tree_reader_at_end(&self->tree) : tlv_reader_at_end(&self->reader);
    return Py_BuildValue("(nni)", (Py_ssize_t)consumed, (Py_ssize_t)offset, end);
}

PyObject* opentlv_python_cursor_skip(PyObject* module, PyObject* capsule) {
    (void)module;
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!available(self)) return NULL;
    self->has_current = 0;
    tlv_result_t code =
        self->nested ? tlv_tree_reader_skip_subtree(&self->tree) : TLV_ERR_INVALID_ARG;
    if (code != TLV_OK) {
        opentlv_python_raise_reader(code, NULL);
        return NULL;
    }
    return Py_NewRef(Py_None);
}

static tlv_visit_result_t visit_item(const tlv_element_t* element, size_t depth, size_t offset,
                                     void* context) {
    PyObject* callback = context;
    if (element->value.size > PY_SSIZE_T_MAX || element->tag.size > PY_SSIZE_T_MAX) {
        opentlv_python_raise_reader(TLV_ERR_NATIVE_SIZE, NULL);
        return TLV_VISIT_ERROR;
    }
    PyObject* result = PyObject_CallFunction(
        callback, "y#y#nn", element->tag.size ? element->tag.data : (const uint8_t*)"",
        (Py_ssize_t)element->tag.size,
        element->value.size ? element->value.data : (const uint8_t*)"",
        (Py_ssize_t)element->value.size, (Py_ssize_t)depth, (Py_ssize_t)offset);
    if (!result) return TLV_VISIT_ERROR;
    long action = result == Py_None ? TLV_VISIT_CONTINUE : PyLong_AsLong(result);
    Py_DECREF(result);
    if (PyErr_Occurred()) return TLV_VISIT_ERROR;
    return action == 0 ? TLV_VISIT_CONTINUE : action == 1 ? TLV_VISIT_STOP : TLV_VISIT_ERROR;
}

static tlv_visit_result_t visit_element(const tlv_element_t* element, void* context) {
    return visit_item(element, 0, 0, context);
}

PyObject* opentlv_python_cursor_visit(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *capsule, *callback;
    if (!PyArg_ParseTuple(args, "OO", &capsule, &callback)) return NULL;
    cursor* self = PyCapsule_GetPointer(capsule, CURSOR_NAME);
    if (!available(self)) return NULL;
    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "visitor must be callable");
        return NULL;
    }
    self->has_current = 0;
    self->busy = 1;
    tlv_reader_diagnostic_t diagnostic;
    tlv_reader_diagnostic_init(&diagnostic);
    tlv_result_t code =
        self->nested
            ? tlv_tree_reader_visit_diag(&self->tree, visit_item, callback, NULL, &diagnostic)
            : tlv_reader_visit_diag(&self->reader, visit_element, callback, &diagnostic);
    self->busy = 0;
    if (PyErr_Occurred()) return NULL;
    if (code != TLV_OK) {
        opentlv_python_raise_reader(code, &diagnostic);
        return NULL;
    }
    return Py_NewRef(Py_None);
}

#define QUERY_NAME "opentlv.query"
typedef struct query_state {
    tlv_query_t         query;
    tlv_query_matcher_t matcher;
    int                 busy;
} query_state;

static void destroy_query(PyObject* capsule) {
    free(PyCapsule_GetPointer(capsule, QUERY_NAME));
}

PyObject* opentlv_python_query_create(PyObject* module, PyObject* input) {
    (void)module;
    query_state* self = calloc(1, sizeof(*self));
    if (!self) return PyErr_NoMemory();
    tlv_result_t code = TLV_OK;
    size_t       offset = 0;
    if (PyUnicode_Check(input)) {
        Py_ssize_t  length;
        const char* text = PyUnicode_AsUTF8AndSize(input, &length);
        if (!text) {
            free(self);
            return NULL;
        }
        if (memchr(text, 0, (size_t)length)) {
            free(self);
            PyErr_SetString(PyExc_ValueError, "query text contains NUL");
            return NULL;
        }
        code = tlv_query_parse(text, &self->query, &offset);
    } else {
        query_state* original = PyCapsule_GetPointer(input, QUERY_NAME);
        if (!original) {
            free(self);
            return NULL;
        }
        self->query = original->query;
    }
    if (code == TLV_OK) code = tlv_query_matcher_init(&self->matcher, &self->query);
    if (code != TLV_OK) {
        tlv_reader_diagnostic_t diag;
        tlv_reader_diagnostic_init(&diag);
        diag.diagnostic.has_offset = 1;
        diag.diagnostic.offset = offset;
        free(self);
        opentlv_python_raise_reader(code, &diag);
        return NULL;
    }
    PyObject* capsule = PyCapsule_New(self, QUERY_NAME, destroy_query);
    if (!capsule) free(self);
    return capsule;
}

PyObject* opentlv_python_query_steps(PyObject* module, PyObject* capsule) {
    (void)module;
    query_state* self = PyCapsule_GetPointer(capsule, QUERY_NAME);
    if (!self) return NULL;
    PyObject* steps = PyTuple_New((Py_ssize_t)self->query.count);
    if (!steps) return NULL;
    for (size_t i = 0; i < self->query.count; ++i) {
        tlv_tag_t tag = tlv_query_step(&self->query, i);
        PyObject* value = PyBytes_FromStringAndSize((const char*)tag.data, (Py_ssize_t)tag.size);
        if (!value) {
            Py_DECREF(steps);
            return NULL;
        }
        PyTuple_SetItem(steps, (Py_ssize_t)i, value);
    }
    return steps;
}

PyObject* opentlv_python_query_matches(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  capsule;
    Py_buffer  tag;
    Py_ssize_t depth;
    if (!PyArg_ParseTuple(args, "Oy*n", &capsule, &tag, &depth)) return NULL;
    query_state* self = PyCapsule_GetPointer(capsule, QUERY_NAME);
    if (!self) {
        PyBuffer_Release(&tag);
        return NULL;
    }
    if (self->busy || depth < 0) {
        PyBuffer_Release(&tag);
        PyErr_SetString(PyExc_ValueError, "matcher is busy or depth is negative");
        return NULL;
    }
    tlv_tag_t value = tlv_tag(tag.buf, (size_t)tag.len);
    int       matches = tlv_query_matcher_visit(&self->matcher, &value, (size_t)depth);
    PyBuffer_Release(&tag);
    return PyBool_FromLong(matches);
}

PyObject* opentlv_python_query_visit(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *capsule, *reader_capsule, *callback;
    if (!PyArg_ParseTuple(args, "OOO", &capsule, &reader_capsule, &callback)) return NULL;
    query_state* self = PyCapsule_GetPointer(capsule, QUERY_NAME);
    if (!self) return NULL;
    cursor* reader = PyCapsule_GetPointer(reader_capsule, CURSOR_NAME);
    if (!available(reader)) return NULL;
    if (self->busy || !reader->nested || !PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_ValueError, "idle matcher, Tree Reader and callable required");
        return NULL;
    }
    reader->has_current = 0;
    self->busy = reader->busy = 1;
    size_t       offset = 0;
    tlv_result_t code =
        tlv_query_visit(&reader->tree, &self->matcher, visit_item, callback, &offset);
    self->busy = reader->busy = 0;
    if (PyErr_Occurred()) return NULL;
    if (code != TLV_OK) {
        tlv_reader_diagnostic_t diag;
        tlv_reader_diagnostic_init(&diag);
        diag.diagnostic.has_offset = 1;
        diag.diagnostic.offset = offset;
        opentlv_python_raise_reader(code, &diag);
        return NULL;
    }
    return Py_NewRef(Py_None);
}
