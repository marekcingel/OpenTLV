// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#define PY_SSIZE_T_CLEAN
#include "query.h"
#include "reader.h"
#include "format.h"
#include <tlv/query/adapters.h>
#include <tlv/writer/tree.h>
#if OPENTLV_FORMAT_BER
#include <tlv/builtins/asn1/query.h>
#endif
#include <stdlib.h>
#include <string.h>

#define PROGRAM_NAME "opentlv.query_program"
#define EXECUTION_NAME "opentlv.query_execution"
typedef struct memory {
    void*  allocation;
    void*  data;
    size_t size;
} memory;
typedef struct program {
    memory                     image;
    const tlv_query_program_t* native;
    tlv_query_program_info_t   info;
    tlv_query_environment_t    environment;
    tlv_query_hook_t           hooks[4];
} program;
typedef struct execution {
    PyObject *        owner, *reader, *inputs, *bindings, *document;
    memory            workspace, values, staging_data, staging_scratch, frames;
    Py_buffer         external;
    tlv_query_exec_t* native;
    size_t            depth, nodes, work;
    int               retained, busy;
} execution;

static int allocate(memory* out, size_t bytes) {
    if (bytes > SIZE_MAX - 15) {
        PyErr_NoMemory();
        return 0;
    }
    out->allocation = malloc(bytes + 15);
    if (!out->allocation) {
        PyErr_NoMemory();
        return 0;
    }
    out->data = (void*)(((uintptr_t)out->allocation + 15) & ~(uintptr_t)15);
    out->size = bytes;
    return 1;
}
static void release(memory* out) {
    free(out->allocation);
    memset(out, 0, sizeof *out);
}
static PyObject* failure(tlv_result_t code, const tlv_query_diagnostic_t* diagnostic) {
    if (!PyErr_Occurred()) opentlv_python_raise_query(code, diagnostic);
    return NULL;
}
static int set_size(PyObject* dict, const char* key, size_t value) {
    PyObject* number = PyLong_FromSize_t(value);
    if (!number) return -1;
    int rc = PyDict_SetItemString(dict, key, number);
    Py_DECREF(number);
    return rc;
}
static int size_option(PyObject* options, const char* name, size_t* value) {
    PyObject* item = PyDict_GetItemString(options, name);
    if (!item) return 1;
    *value = PyLong_AsSize_t(item);
    return !PyErr_Occurred();
}
static tlv_result_t resolve(const void* context, const char* space, size_t space_size,
                            const char* name, size_t name_size, tlv_tag_t* tag) {
    PyObject* key = NULL;
    if (space_size) {
        PyObject* left = PyUnicode_DecodeUTF8(space, (Py_ssize_t)space_size, "strict");
        PyObject* right = PyUnicode_DecodeUTF8(name, (Py_ssize_t)name_size, "strict");
        key = left && right ? PyUnicode_FromFormat("%U:%U", left, right) : NULL;
        Py_XDECREF(left);
        Py_XDECREF(right);
    } else
        key = PyUnicode_DecodeUTF8(name, (Py_ssize_t)name_size, "strict");
    if (!key) return TLV_ERR_INVALID_ARG;
    PyObject* value = PyDict_GetItemWithError((PyObject*)context, key);
    Py_DECREF(key);
    if (!value) return PyErr_Occurred() ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_TAG;
    char*      data;
    Py_ssize_t size;
    if (PyBytes_AsStringAndSize(value, &data, &size) < 0) return TLV_ERR_INVALID_ARG;
    *tag = tlv_tag((const uint8_t*)data, (size_t)size);
    return TLV_OK;
}
static void destroy_program(PyObject* capsule) {
    program* self = PyCapsule_GetPointer(capsule, PROGRAM_NAME);
    if (!self) return;
    release(&self->image);
    free(self);
}
static void dispose_execution(execution* self) {
    Py_XDECREF(self->owner);
    Py_XDECREF(self->reader);
    Py_XDECREF(self->inputs);
    Py_XDECREF(self->bindings);
    Py_XDECREF(self->document);
    if (self->external.obj) PyBuffer_Release(&self->external);
    release(&self->workspace);
    release(&self->values);
    release(&self->staging_data);
    release(&self->staging_scratch);
    release(&self->frames);
    free(self);
}
static void destroy_execution(PyObject* capsule) {
    execution* self = PyCapsule_GetPointer(capsule, EXECUTION_NAME);
    if (self) dispose_execution(self);
}
static execution* get_execution(PyObject* capsule) {
    execution* self = PyCapsule_GetPointer(capsule, EXECUTION_NAME);
    if (self && self->busy) {
        PyErr_SetString(PyExc_RuntimeError, "Query execution is active in a callback");
        return NULL;
    }
    return self;
}

PyObject* opentlv_python_program_create(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *text, *variables, *names, *options;
    int       format_id, image;
    if (!PyArg_ParseTuple(args, "OiOOOp", &text, &format_id, &variables, &names, &options, &image))
        return NULL;
    if (!PyDict_Check(variables) || !PyDict_Check(names) || !PyDict_Check(options)) {
        PyErr_SetString(PyExc_TypeError, "Query variables, names and options must be dictionaries");
        return NULL;
    }
    char*      data;
    Py_ssize_t length;
    if (PyBytes_AsStringAndSize(text, &data, &length) < 0) return NULL;
    program* self = calloc(1, sizeof *self);
    if (!self) return PyErr_NoMemory();
    self->environment.format = format_id ? opentlv_python_format_for(format_id) : NULL;
    if (format_id && !self->environment.format) {
        free(self);
        return failure(TLV_ERR_UNSUPPORTED_TYPE, NULL);
    }
    size_t                  hook_count;
    const tlv_query_hook_t* hooks = tlv_query_builtin_hooks(&hook_count);
    memcpy(self->hooks, hooks, hook_count * sizeof *hooks);
#if OPENTLV_FORMAT_BER
    if (format_id == 1 || format_id == 2 || format_id == 3) {
        self->environment.tags = &tlv_asn1_query_tags;
        self->hooks[hook_count++] = tlv_asn1_query_date;
    }
#endif
    self->environment.hooks = self->hooks;
    self->environment.hook_count = hook_count;
    tlv_query_compile_options_t config;
    tlv_query_compile_options_init(&config);
    config.environment = &self->environment;
    config.resolve = resolve;
    config.resolve_context = names;
    Py_ssize_t            count = PyDict_Size(variables);
    tlv_query_variable_t* declarations = NULL;
    PyObject*             keep_names = PyList_New(0);
    if (!keep_names || (size_t)count > SIZE_MAX / sizeof *declarations) goto python_error;
    if (count) {
        declarations = calloc((size_t)count, sizeof *declarations);
        if (!declarations) {
            PyErr_NoMemory();
            goto python_error;
        }
    }
    Py_ssize_t position = 0;
    PyObject * key, *value;
    size_t     index = 0;
    while (PyDict_Next(variables, &position, &key, &value)) {
        PyObject* name = PyUnicode_AsUTF8String(key);
        if (!name) goto python_error;
        if (PyList_Append(keep_names, name) < 0) {
            Py_DECREF(name);
            goto python_error;
        }
        declarations[index].name = PyBytes_AsString(name);
        declarations[index++].type = (tlv_query_result_kind_t)PyLong_AsLong(value);
        Py_DECREF(name);
        if (PyErr_Occurred()) goto python_error;
    }
    config.variables = declarations;
    config.variable_count = (size_t)count;
    if (!size_option(options, "max_text", &config.max_text) ||
        !size_option(options, "max_tokens", &config.max_tokens) ||
        !size_option(options, "max_nesting", &config.max_nesting) ||
        !size_option(options, "max_states", &config.max_states) ||
        !size_option(options, "max_pattern", &config.max_pattern) ||
        !size_option(options, "max_resolved_tag", &config.max_resolved_tag))
        goto python_error;
    value = PyDict_GetItemString(options, "optimize");
    if (value) {
        config.optimize = PyObject_IsTrue(value);
        if (config.optimize < 0) goto python_error;
    }
    tlv_query_diagnostic_t diagnostic;
    size_t                 bytes, alignment;
    tlv_result_t rc = image ? tlv_query_program_load_scratch(data, (size_t)length, &config, &bytes,
                                                             &alignment, &diagnostic)
                            : tlv_query_compile_scratch(data, (size_t)length, &config, &bytes,
                                                        &alignment, &diagnostic);
    memory       scratch = {0};
    self->info.struct_size = sizeof self->info;
    if (rc == TLV_OK && !allocate(&scratch, bytes)) goto python_error;
    if (rc == TLV_OK && !image)
        rc = tlv_query_compile(data, (size_t)length, &config, scratch.data, scratch.size, NULL, 0,
                               &self->info, &diagnostic);
    if (rc == TLV_OK && !allocate(&self->image, image ? (size_t)length : self->info.program_size)) {
        release(&scratch);
        goto python_error;
    }
    if (rc == TLV_OK && image) {
        memcpy(self->image.data, data, (size_t)length);
        rc = tlv_query_program_load(self->image.data, self->image.size, &config, scratch.data,
                                    scratch.size, &self->native, &self->info, &diagnostic);
    } else if (rc == TLV_OK) {
        rc = tlv_query_compile(data, (size_t)length, &config, scratch.data, scratch.size,
                               self->image.data, self->image.size, &self->info, &diagnostic);
        self->native = self->image.data;
    }
    release(&scratch);
    free(declarations);
    Py_DECREF(keep_names);
    if (rc != TLV_OK || PyErr_Occurred()) {
        release(&self->image);
        free(self);
        return failure(rc, &diagnostic);
    }
    PyObject* capsule = PyCapsule_New(self, PROGRAM_NAME, destroy_program);
    if (!capsule) {
        release(&self->image);
        free(self);
    }
    return capsule;
python_error:
    free(declarations);
    Py_XDECREF(keep_names);
    release(&self->image);
    free(self);
    if (!PyErr_Occurred()) PyErr_NoMemory();
    return NULL;
}

PyObject* opentlv_python_program_info(PyObject* module, PyObject* capsule) {
    (void)module;
    program* self = PyCapsule_GetPointer(capsule, PROGRAM_NAME);
    if (!self) return NULL;
    PyObject* info = PyDict_New();
    if (!info) return NULL;
#define FIELD(name)                                                                                \
    do {                                                                                           \
        if (set_size(info, #name, self->info.name) < 0) {                                          \
            Py_DECREF(info);                                                                       \
            return NULL;                                                                           \
        }                                                                                          \
    } while (0)
    FIELD(program_size);
    FIELD(program_alignment);
    FIELD(scratch_size);
    FIELD(scratch_alignment);
    FIELD(states);
    FIELD(language_version);
    FIELD(level);
    FIELD(result_kind);
    FIELD(expression_values);
    FIELD(instructions);
    FIELD(variable_slots);
    FIELD(codec_scratch);
    FIELD(pattern_bytes);
    FIELD(optimized_states);
    FIELD(expression_stack);
    FIELD(candidate_size);
    FIELD(candidate_alignment);
    FIELD(frame_states);
    FIELD(decision_timing);
    FIELD(stable_input_required);
    FIELD(constructed_values_required);
#undef FIELD
    PyObject* variables = PyList_New(0);
    if (!variables) {
        Py_DECREF(info);
        return NULL;
    }
    for (size_t i = 0; i < tlv_query_program_variable_count(self->native); ++i) {
        tlv_query_variable_info_t variable;
        tlv_result_t              rc = tlv_query_program_variable(self->native, i, &variable);
        if (rc != TLV_OK) {
            Py_DECREF(variables);
            Py_DECREF(info);
            return failure(rc, NULL);
        }
        PyObject* item =
            Py_BuildValue("(s#i)", variable.name, (Py_ssize_t)variable.name_size, variable.type);
        int failed = !item || PyList_Append(variables, item) < 0;
        Py_XDECREF(item);
        if (failed) {
            Py_DECREF(variables);
            Py_DECREF(info);
            return NULL;
        }
    }
    int failed = PyDict_SetItemString(info, "variables", variables) < 0;
    Py_DECREF(variables);
    if (failed) {
        Py_DECREF(info);
        return NULL;
    }
    return info;
}
PyObject* opentlv_python_program_render(PyObject* module, PyObject* args) {
    (void)module;
    PyObject* capsule;
    int       kind;
    if (!PyArg_ParseTuple(args, "Oi", &capsule, &kind)) return NULL;
    program* self = PyCapsule_GetPointer(capsule, PROGRAM_NAME);
    if (!self) return NULL;
    if (kind == 2) return PyBytes_FromStringAndSize(self->image.data, (Py_ssize_t)self->image.size);
    size_t       bytes;
    tlv_result_t rc = kind ? tlv_query_program_explain(self->native, NULL, 0, &bytes)
                           : tlv_query_program_format(self->native, NULL, 0, &bytes);
    if (rc != TLV_OK) return failure(rc, NULL);
    memory output = {0};
    if (!allocate(&output, bytes)) return NULL;
    rc = kind ? tlv_query_program_explain(self->native, output.data, bytes, &bytes)
              : tlv_query_program_format(self->native, output.data, bytes, &bytes);
    PyObject* result = rc == TLV_OK
                           ? PyUnicode_DecodeUTF8(output.data, (Py_ssize_t)bytes - 1, "strict")
                           : failure(rc, NULL);
    release(&output);
    return result;
}

PyObject* opentlv_python_execution_create(PyObject* module, PyObject* args) {
    (void)module;
    PyObject * owner, *external;
    Py_ssize_t depth, nodes, work;
    int        retained;
    if (!PyArg_ParseTuple(args, "OnnnpO", &owner, &depth, &nodes, &work, &retained, &external))
        return NULL;
    program* query = PyCapsule_GetPointer(owner, PROGRAM_NAME);
    if (!query) return NULL;
    if (depth < 0 || nodes <= 0 || work <= 0) return failure(TLV_ERR_INVALID_ARG, NULL);
    execution* self = calloc(1, sizeof *self);
    if (!self) return PyErr_NoMemory();
    self->owner = Py_NewRef(owner);
    self->depth = (size_t)depth;
    self->nodes = (size_t)nodes;
    self->work = (size_t)work;
    self->retained = retained;
    self->inputs = PyList_New(0);
    self->bindings = PyList_New(0);
    if (!self->inputs || !self->bindings) {
        dispose_execution(self);
        return NULL;
    }
    size_t       bytes, alignment;
    tlv_result_t rc =
        retained ? tlv_query_eval_size(query->native, self->depth, self->nodes, &bytes, &alignment)
                 : tlv_query_exec_size(query->native, self->depth, &bytes, &alignment);
    void*  storage = NULL;
    size_t capacity = 0;
    if (rc == TLV_OK && external != Py_None) {
        if (PyObject_GetBuffer(external, &self->external, PyBUF_WRITABLE | PyBUF_C_CONTIGUOUS) <
            0) {
            dispose_execution(self);
            return NULL;
        }
        storage = self->external.buf;
        capacity = (size_t)self->external.len;
    } else if (rc == TLV_OK) {
        if (!allocate(&self->workspace, bytes)) {
            dispose_execution(self);
            return NULL;
        }
        storage = self->workspace.data;
        capacity = bytes;
    }
    if (rc == TLV_OK)
        rc = retained ? tlv_query_eval_init(query->native, &query->environment, storage, capacity,
                                            self->depth, self->nodes, self->work, &self->native)
                      : tlv_query_exec_init(query->native, storage, capacity, self->depth,
                                            self->nodes, self->work, &self->native);
    if (rc != TLV_OK) {
        dispose_execution(self);
        return failure(rc, NULL);
    }
    PyObject* capsule = PyCapsule_New(self, EXECUTION_NAME, destroy_execution);
    if (!capsule) dispose_execution(self);
    return capsule;
}
PyObject* opentlv_python_execution_size(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  capsule;
    Py_ssize_t depth, nodes;
    int        retained;
    if (!PyArg_ParseTuple(args, "Onnp", &capsule, &depth, &nodes, &retained)) return NULL;
    program* self = PyCapsule_GetPointer(capsule, PROGRAM_NAME);
    if (!self) return NULL;
    if (depth < 0 || nodes < 0) return failure(TLV_ERR_INVALID_ARG, NULL);
    size_t       bytes, alignment;
    tlv_result_t rc =
        retained
            ? tlv_query_eval_size(self->native, (size_t)depth, (size_t)nodes, &bytes, &alignment)
            : tlv_query_exec_size(self->native, (size_t)depth, &bytes, &alignment);
    if (rc != TLV_OK) return failure(rc, NULL);
    if (bytes > PY_SSIZE_T_MAX) return failure(TLV_ERR_NATIVE_SIZE, NULL);
    return Py_BuildValue("(nn)", (Py_ssize_t)bytes, (Py_ssize_t)alignment);
}
PyObject* opentlv_python_execution_bind(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *  capsule, *value;
    const char* name;
    int         type;
    if (!PyArg_ParseTuple(args, "OsiO", &capsule, &name, &type, &value)) return NULL;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    int64_t    number = 0;
    char*      data = NULL;
    Py_ssize_t size = 0;
    if (type == TLV_QUERY_RESULT_INTEGER)
        number = PyLong_AsLongLong(value);
    else if (PyBytes_AsStringAndSize(value, &data, &size) < 0)
        return NULL;
    if (PyErr_Occurred()) return NULL;
    /* Append before publishing borrowed storage to C; failure leaves C untouched. */
    if (PyList_Append(self->bindings, value) < 0) return NULL;
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t rc = tlv_query_exec_bind(self->native, name, (tlv_query_result_kind_t)type, number,
                                          (const uint8_t*)data, (size_t)size, &diagnostic);
    if (rc != TLV_OK) return failure(rc, &diagnostic);
    return Py_NewRef(Py_None);
}
static PyObject* project(const tlv_tree_event_t* event) {
    if (event->element.tag.size > PY_SSIZE_T_MAX || event->element.value.size > PY_SSIZE_T_MAX)
        return failure(TLV_ERR_NATIVE_SIZE, NULL);
    return Py_BuildValue("(iy#y#nn)", event->kind,
                         event->element.tag.size ? event->element.tag.data : (const uint8_t*)"",
                         (Py_ssize_t)event->element.tag.size,
                         event->element.value.size ? event->element.value.data : (const uint8_t*)"",
                         (Py_ssize_t)event->element.value.size, (Py_ssize_t)event->depth,
                         (Py_ssize_t)event->offset);
}
static tlv_visit_result_t visit(const tlv_tree_event_t* event, void* context) {
    PyObject* item = project(event);
    if (!item) return TLV_VISIT_ERROR;
    PyObject* result = PyObject_CallFunctionObjArgs(context, item, NULL);
    Py_DECREF(item);
    if (!result) return TLV_VISIT_ERROR;
    long action = result == Py_None ? 0 : PyLong_AsLong(result);
    Py_DECREF(result);
    if (PyErr_Occurred()) return TLV_VISIT_ERROR;
    return action == 0 ? TLV_VISIT_CONTINUE : action == 1 ? TLV_VISIT_STOP : TLV_VISIT_ERROR;
}
PyObject* opentlv_python_execution_feed(PyObject* module, PyObject* args) {
    (void)module;
    PyObject * capsule, *tag, *value, *source;
    Py_ssize_t depth, offset;
    int        kind, skipped;
    if (!PyArg_ParseTuple(args, "OiOOnnOp", &capsule, &kind, &tag, &value, &depth, &offset, &source,
                          &skipped))
        return NULL;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (self->reader || self->document || depth < 0 || offset < 0)
        return failure(TLV_ERR_INVALID_ARG, NULL);
    char *     tag_data, *value_data;
    Py_ssize_t tag_size, value_size;
    if (PyBytes_AsStringAndSize(tag, &tag_data, &tag_size) < 0 ||
        PyBytes_AsStringAndSize(value, &value_data, &value_size) < 0)
        return NULL;
    tlv_tree_event_t event = {0};
    event.kind = (tlv_tree_event_kind_t)kind;
    event.element.tag = tlv_tag((const uint8_t*)tag_data, (size_t)tag_size);
    event.element.value.data = (const uint8_t*)value_data;
    event.element.value.size = (tlv_size_t)value_size;
    event.depth = (size_t)depth;
    event.offset = (size_t)offset;
    event.skipped = skipped;
    if (source != Py_None) {
        const tlv_source_t* original = opentlv_python_source_pointer(source);
        if (!original) return NULL;
        event.source = *original;
    }
    if (PyList_Append(self->inputs, tag) < 0 || PyList_Append(self->inputs, value) < 0 ||
        PyList_Append(self->inputs, source) < 0)
        return NULL;
    int                    matched;
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t           rc = tlv_query_exec_feed(self->native, &event, &matched, &diagnostic);
    if (rc != TLV_OK) return failure(rc, &diagnostic);
    if (!matched) return Py_NewRef(Py_None);
    program* query = PyCapsule_GetPointer(self->owner, PROGRAM_NAME);
    if (!query) return NULL;
    if (!self->retained && query->info.level == TLV_QUERY_S1) {
        rc = tlv_query_exec_selected(self->native, &event);
        if (rc != TLV_OK) return failure(rc, NULL);
    }
    return project(&event);
}
PyObject* opentlv_python_execution_finish(PyObject* module, PyObject* capsule) {
    (void)module;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (self->reader || self->document) return failure(TLV_ERR_INVALID_ARG, NULL);
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t           rc = tlv_query_exec_finish(self->native, &diagnostic);
    if (rc != TLV_OK) return failure(rc, &diagnostic);
    return Py_NewRef(Py_None);
}
PyObject* opentlv_python_execution_visit(PyObject* module, PyObject* args) {
    (void)module;
    PyObject *capsule, *reader_capsule, *callback;
    int       existence;
    if (!PyArg_ParseTuple(args, "OOOi", &capsule, &reader_capsule, &callback, &existence))
        return NULL;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (self->document || (self->reader && self->reader != reader_capsule))
        return failure(TLV_ERR_INVALID_ARG, NULL);
    if (!existence && !PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "Query visitor must be callable");
        return NULL;
    }
    PyObject*          input;
    tlv_tree_reader_t* reader = opentlv_python_query_reader_begin(reader_capsule, &input);
    if (!reader) return NULL;
    if (PyList_Append(self->inputs, input) < 0) {
        opentlv_python_query_reader_end(reader_capsule);
        return NULL;
    }
    if (!self->reader) self->reader = Py_NewRef(reader_capsule);
    self->busy = 1;
    tlv_query_diagnostic_t diagnostic;
    int                    found = 0;
    tlv_result_t           rc =
        existence
            ? tlv_query_program_exists(reader, self->native, existence == 2, &found, &diagnostic)
            : tlv_query_program_visit(reader, self->native, visit, callback, &diagnostic);
    self->busy = 0;
    opentlv_python_query_reader_end(reader_capsule);
    if (PyErr_Occurred()) return NULL;
    if (rc != TLV_OK) return failure(rc, &diagnostic);
    return existence ? PyBool_FromLong(found) : Py_NewRef(Py_None);
}
PyObject* opentlv_python_execution_info(PyObject* module, PyObject* capsule) {
    (void)module;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    tlv_query_exec_info_t info = {0};
    info.struct_size = sizeof info;
    tlv_result_t rc = tlv_query_exec_info(self->native, &info);
    if (rc != TLV_OK) return failure(rc, NULL);
    return Py_BuildValue("{s:n,s:n,s:n,s:i,s:i,s:i}", "elements", (Py_ssize_t)info.elements, "work",
                         (Py_ssize_t)info.work, "skipped_subtrees",
                         (Py_ssize_t)info.skipped_subtrees, "finished", info.finished,
                         "full_validation", info.full_validation, "invalid", info.invalid);
}
PyObject* opentlv_python_execution_result(PyObject* module, PyObject* capsule) {
    (void)module;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    tlv_query_result_t result;
    tlv_result_t       rc = tlv_query_exec_result(self->native, &result);
    if (rc != TLV_OK) return failure(rc, NULL);
    switch (result.kind) {
        case TLV_QUERY_RESULT_BOOL: return PyBool_FromLong(result.boolean);
        case TLV_QUERY_RESULT_INTEGER: return PyLong_FromLongLong(result.integer);
        case TLV_QUERY_RESULT_BYTES:
            return PyBytes_FromStringAndSize((const char*)result.data, (Py_ssize_t)result.size);
        case TLV_QUERY_RESULT_STRING:
            return PyUnicode_DecodeUTF8((const char*)result.data, (Py_ssize_t)result.size,
                                        "strict");
        default: PyErr_SetString(PyExc_TypeError, "node results use next()"); return NULL;
    }
}
PyObject* opentlv_python_execution_control(PyObject* module, PyObject* args) {
    (void)module;
    PyObject*  capsule;
    int        kind;
    Py_ssize_t value;
    if (!PyArg_ParseTuple(args, "Oin", &capsule, &kind, &value)) return NULL;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (value < 0) return failure(TLV_ERR_INVALID_ARG, NULL);
    tlv_result_t rc = kind == 0 ? tlv_query_exec_context(self->native, (size_t)value)
                                : tlv_query_exec_pruning(self->native, value != 0);
    if (rc != TLV_OK) return failure(rc, NULL);
    return Py_NewRef(Py_None);
}
PyObject* opentlv_python_execution_document(PyObject* module, PyObject* args) {
    (void)module;
    PyObject * capsule, *document_capsule, *context;
    Py_ssize_t value_capacity;
    if (!PyArg_ParseTuple(args, "OOOn", &capsule, &document_capsule, &context, &value_capacity))
        return NULL;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (!self->retained || self->reader || self->document || value_capacity < 0)
        return failure(TLV_ERR_INVALID_ARG, NULL);
    tlv_document_t* document = opentlv_python_document_pointer(document_capsule);
    if (!document) return NULL;
    tlv_node_t* node = context == Py_None ? NULL : PyLong_AsVoidPtr(context);
    if (PyErr_Occurred()) return NULL;
    program* query = PyCapsule_GetPointer(self->owner, PROGRAM_NAME);
    if (!query) return NULL;
    tlv_tree_writer_workspace_t staging = {0};
    if (query->info.constructed_values_required) {
        release(&self->frames);
        release(&self->values);
        release(&self->staging_data);
        release(&self->staging_scratch);
        if (self->depth > SIZE_MAX / sizeof(tlv_tree_writer_frame_t))
            return failure(TLV_ERR_OVERFLOW, NULL);
        if (!allocate(&self->frames, self->depth * sizeof(tlv_tree_writer_frame_t)) ||
            !allocate(&self->values, (size_t)value_capacity) ||
            !allocate(&self->staging_data, (size_t)value_capacity) ||
            !allocate(&self->staging_scratch, (size_t)value_capacity))
            return NULL;
        staging.frames = self->frames.data;
        staging.frame_capacity = self->depth;
        staging.data = self->staging_data.data;
        staging.data_capacity = (size_t)value_capacity;
        staging.scratch = self->staging_scratch.data;
        staging.scratch_capacity = (size_t)value_capacity;
    }
    self->document = Py_NewRef(document_capsule);
    tlv_query_diagnostic_t diagnostic;
    tlv_result_t           rc = tlv_document_query_evaluate(
        document, self->native, node, self->values.data, self->values.size,
        query->info.constructed_values_required ? &staging : NULL, &diagnostic);
    if (rc != TLV_OK) return failure(rc, &diagnostic);
    return Py_NewRef(Py_None);
}
PyObject* opentlv_python_execution_next(PyObject* module, PyObject* capsule) {
    (void)module;
    execution* self = get_execution(capsule);
    if (!self) return NULL;
    if (self->document) {
        tlv_node_t*  node;
        tlv_result_t rc = tlv_document_query_next(self->native, &node);
        if (rc != TLV_OK) return failure(rc, NULL);
        return PyLong_FromVoidPtr(node);
    }
    tlv_tree_event_t event;
    tlv_result_t     rc = tlv_query_result_next(self->native, &event);
    if (rc != TLV_OK) return failure(rc, NULL);
    return project(&event);
}
