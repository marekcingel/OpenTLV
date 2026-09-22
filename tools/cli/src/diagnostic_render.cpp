#include "diagnostic_render.hpp"
#include <cstring>
#include <sstream>
#include <nlohmann/json.hpp>

namespace cli {

namespace {

std::string hex_offset(size_t offset) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << offset;
    return out.str();
}

// tlv_diagnostic_path_t never holds more than TLV_DIAGNOSTIC_PATH_MAX (32)
// tags; this comfortably bounds their hex-plus-separator text.
std::string path_string(const tlv_diagnostic_path_t& path) {
    char         buf[512];
    size_t       length = 0;
    tlv_result_t rc = tlv_diagnostic_path_string(&path, buf, sizeof buf, &length);
    return rc == TLV_OK ? std::string(buf, length) : std::string();
}

const char* form_name(tlv_schema_kind_t kind) {
    switch (kind) {
        case TLV_SCHEMA_PRIMITIVE: return "primitive";
        case TLV_SCHEMA_CONSTRUCTED: return "constructed";
        case TLV_SCHEMA_ANY: return "either";
    }
    return "unknown";
}

std::string hex_tag(const tlv_tag_t& tag) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       result(tag.size * 2, '0');
    for (size_t i = 0; i < tag.size; ++i) {
        result[i * 2] = digits[tag.data[i] >> 4];
        result[i * 2 + 1] = digits[tag.data[i] & 0xF];
    }
    return result;
}

const char* operation_name(tlv_reader_operation_t operation) {
    switch (operation) {
        case TLV_READER_OP_TAG: return "tag";
        case TLV_READER_OP_LENGTH: return "length";
        case TLV_READER_OP_VALUE: return "value";
        case TLV_READER_OP_TRAILER: return "trailer";
    }
    return "unknown";
}

// Every diagnostic type shares a base tlv_diagnostic_t (code, severity,
// offset, expected/actual, contexts, path): rendering it once here, rather
// than in each of diagnostic_/schema_/reader_ human/compact/json, is what
// keeps the three formats showing the same fields for every type.

void append_header_human(std::ostringstream& out, const tlv::diagnostic& d) {
    out << tlv_diagnostic_severity_string(d.severity) << ": " << tlv_strerror(d.code) << "\n";
    out << "\ncode: " << error_name(d.code);
    if (d.has_offset) out << "\noffset: " << hex_offset(d.offset) << " (" << d.offset << ")";
}

void append_trailer_human(std::ostringstream& out, const tlv::diagnostic& d) {
    if (d.expected) out << "\nexpected: " << d.expected;
    if (d.actual) out << "\nactual: " << d.actual;
    for (const tlv_diagnostic_context_t* ctx = d.contexts; ctx; ctx = ctx->next)
        out << "\n" << ctx->layer << " " << ctx->key << ": " << ctx->value;
}

std::string trailer_compact(const tlv::diagnostic& d) {
    std::ostringstream out;
    if (d.expected) out << "; expected=" << d.expected;
    if (d.actual) out << "; actual=" << d.actual;
    for (const tlv_diagnostic_context_t* ctx = d.contexts; ctx; ctx = ctx->next)
        out << "; " << ctx->layer << " " << ctx->key << "=" << ctx->value;
    return out.str();
}

void set_header_json(nlohmann::json& object, const tlv::diagnostic& d) {
    object["severity"] = tlv_diagnostic_severity_string(d.severity);
    object["code"] = error_name(d.code);
    object["message"] = tlv_strerror(d.code);
    if (d.has_offset) object["offset"] = d.offset;
}

void append_trailer_json(nlohmann::json& object, const tlv::diagnostic& d) {
    if (d.expected) object["expected"] = d.expected;
    if (d.actual) object["actual"] = d.actual;
    if (d.contexts) {
        nlohmann::json contexts = nlohmann::json::array();
        for (const tlv_diagnostic_context_t* ctx = d.contexts; ctx; ctx = ctx->next)
            contexts.push_back({{"layer", ctx->layer}, {"key", ctx->key}, {"value", ctx->value}});
        object["contexts"] = std::move(contexts);
    }
}

// -- Base diagnostic --------------------------------------------------------

std::string diagnostic_human(const tlv::diagnostic& d, const char* stage, const char* tag_hex) {
    std::ostringstream out;
    append_header_human(out, d);
    if (tag_hex) out << "\ntag: " << tag_hex;
    if (d.path) out << "\npath: " << path_string(*d.path);
    if (stage && *stage) out << "\nstage: " << stage;
    append_trailer_human(out, d);
    return out.str();
}

std::string diagnostic_compact(const tlv::diagnostic& d, const char* stage, const char* tag_hex) {
    std::ostringstream out;
    if (stage && *stage) out << stage << " ";
    out << error_name(d.code) << " at byte " << (d.has_offset ? d.offset : 0);
    if (tag_hex) out << " tag=" << tag_hex;
    out << ": " << tlv_strerror(d.code) << trailer_compact(d);
    return out.str();
}

std::string diagnostic_json(const tlv::diagnostic& d, const char* stage, const char* tag_hex) {
    nlohmann::json object;
    set_header_json(object, d);
    if (tag_hex) object["tag"] = tag_hex;
    if (d.path) object["path"] = path_string(*d.path);
    if (stage && *stage) object["stage"] = stage;
    append_trailer_json(object, d);
    return object.dump();
}

// -- Schema diagnostic --------------------------------------------------------

std::string schema_human(const tlv::schema_diagnostic& d) {
    std::ostringstream out;
    append_header_human(out, d.diagnostic);
    if (d.path.length) out << "\npath: " << path_string(d.path);
    out << "\ntag: " << hex_tag(d.tag);
    if (d.field) out << "\nfield: " << d.field;
    if (d.has_length)
        out << "\nexpected length: " << d.min_length << ".." << d.max_length
            << "\nactual length: " << d.actual_length;
    if (d.has_occurs)
        out << "\nexpected occurrences: " << d.min_occurs << ".." << d.max_occurs
            << "\nactual occurrences: " << d.occurs;
    if (d.has_form)
        out << "\nexpected form: " << form_name(d.expected_form)
            << "\nactual form: " << (d.actual_constructed ? "constructed" : "primitive");
    append_trailer_human(out, d.diagnostic);
    return out.str();
}

std::string schema_compact(const tlv::schema_diagnostic& d) {
    std::ostringstream out;
    out << "schema " << error_name(d.diagnostic.code) << " at byte "
        << (d.diagnostic.has_offset ? d.diagnostic.offset : 0) << " tag=" << hex_tag(d.tag);
    out << ": " << tlv_strerror(d.diagnostic.code) << trailer_compact(d.diagnostic);
    return out.str();
}

std::string schema_json(const tlv::schema_diagnostic& d) {
    nlohmann::json object;
    set_header_json(object, d.diagnostic);
    object["kind"] = tlv_schema_issue_kind_string(d.kind);
    if (d.path.length) object["path"] = path_string(d.path);
    object["tag"] = hex_tag(d.tag);
    if (d.field) object["field"] = d.field;
    if (d.has_length) {
        object["min_length"] = d.min_length;
        object["max_length"] = d.max_length;
        object["actual_length"] = d.actual_length;
    }
    if (d.has_occurs) {
        object["min_occurs"] = d.min_occurs;
        object["max_occurs"] = d.max_occurs;
        object["occurs"] = d.occurs;
    }
    if (d.has_form) {
        object["expected_form"] = form_name(d.expected_form);
        object["actual_form"] = d.actual_constructed ? "constructed" : "primitive";
    }
    append_trailer_json(object, d.diagnostic);
    return object.dump();
}

// -- Reader diagnostic --------------------------------------------------------

std::string reader_human(const tlv::reader_diagnostic& d) {
    std::ostringstream out;
    append_header_human(out, d.diagnostic);
    if (d.diagnostic.path) out << "\npath: " << path_string(*d.diagnostic.path);
    if (d.has_tag) out << "\ntag: " << hex_tag(d.tag);
    out << "\nwhile reading: " << operation_name(d.operation);
    if (d.has_declared_length) out << "\ndeclared length: " << d.declared_length;
    if (d.has_available) out << "\navailable: " << d.available;
    append_trailer_human(out, d.diagnostic);
    return out.str();
}

std::string reader_compact(const tlv::reader_diagnostic& d) {
    std::ostringstream out;
    out << error_name(d.diagnostic.code) << " at byte "
        << (d.diagnostic.has_offset ? d.diagnostic.offset : 0);
    if (d.has_tag) out << " tag=" << hex_tag(d.tag);
    out << " while reading " << operation_name(d.operation);
    if (d.has_declared_length) out << "; declared_length=" << d.declared_length;
    if (d.has_available) out << "; available=" << d.available;
    out << ": " << tlv_strerror(d.diagnostic.code) << trailer_compact(d.diagnostic);
    return out.str();
}

std::string reader_json(const tlv::reader_diagnostic& d) {
    nlohmann::json object;
    set_header_json(object, d.diagnostic);
    if (d.diagnostic.path) object["path"] = path_string(*d.diagnostic.path);
    if (d.has_tag) object["tag"] = hex_tag(d.tag);
    object["operation"] = operation_name(d.operation);
    if (d.has_declared_length) object["declared_length"] = d.declared_length;
    if (d.has_available) object["available"] = d.available;
    append_trailer_json(object, d.diagnostic);
    return object.dump();
}

} // namespace

bool parse_diagnostic_format(const char* name, diagnostic_format* out) {
    if (!strcmp(name, "human"))
        *out = diagnostic_format::human;
    else if (!strcmp(name, "compact"))
        *out = diagnostic_format::compact;
    else if (!strcmp(name, "json"))
        *out = diagnostic_format::json;
    else
        return false;
    return true;
}

const char* error_name(tlv_result_t rc) {
    switch (rc) {
#define ERROR_NAME(e)                                                                              \
    case e: return #e
        ERROR_NAME(TLV_OK);
        ERROR_NAME(TLV_ERR_BUFFER_TOO_SHORT);
        ERROR_NAME(TLV_ERR_INVALID_LENGTH);
        ERROR_NAME(TLV_ERR_NULL_ARG);
        ERROR_NAME(TLV_ERR_OUT_OF_MEMORY);
        ERROR_NAME(TLV_ERR_END_OF_BUFFER);
        ERROR_NAME(TLV_ERR_INVALID_TAG);
        ERROR_NAME(TLV_ERR_VISITOR);
        ERROR_NAME(TLV_ERR_LIMIT);
        ERROR_NAME(TLV_ERR_SCHEMA);
        ERROR_NAME(TLV_ERR_INVALID_ARG);
        ERROR_NAME(TLV_ERR_INVALID_TAG_SIZE);
        ERROR_NAME(TLV_ERR_INVALID_BYTE_ORDER);
        ERROR_NAME(TLV_ERR_OVERFLOW);
        ERROR_NAME(TLV_ERR_INVALID_VALUE);
        ERROR_NAME(TLV_ERR_UNSUPPORTED_TYPE);
        ERROR_NAME(TLV_ERR_SCHEMA_MISSING);
#undef ERROR_NAME
        default: return "TLV_ERR_UNKNOWN";
    }
}

std::string format_diagnostic(const tlv::diagnostic& diagnostic, diagnostic_format format,
                              const char* stage, const char* tag_hex) {
    switch (format) {
        case diagnostic_format::human: return diagnostic_human(diagnostic, stage, tag_hex);
        case diagnostic_format::compact: return diagnostic_compact(diagnostic, stage, tag_hex);
        case diagnostic_format::json: return diagnostic_json(diagnostic, stage, tag_hex);
    }
    return std::string();
}

std::string format_schema_diagnostic(const tlv::schema_diagnostic& diagnostic,
                                     diagnostic_format             format) {
    switch (format) {
        case diagnostic_format::human: return schema_human(diagnostic);
        case diagnostic_format::compact: return schema_compact(diagnostic);
        case diagnostic_format::json: return schema_json(diagnostic);
    }
    return std::string();
}

std::string format_reader_diagnostic(const tlv::reader_diagnostic& diagnostic,
                                     diagnostic_format             format) {
    switch (format) {
        case diagnostic_format::human: return reader_human(diagnostic);
        case diagnostic_format::compact: return reader_compact(diagnostic);
        case diagnostic_format::json: return reader_json(diagnostic);
    }
    return std::string();
}

} // namespace cli
