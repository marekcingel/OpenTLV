#include "encode.hpp"
#include <cstring>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <new>
#include <string>
#include "commands.hpp"
#include "diagnostics.hpp"
#include "input.hpp"
#include "json_model.hpp"
#include "tlv/config.h"
#include "tlv/writer/writer.h"
#if OPENTLV_FORMAT_DEFAULT
#include "tlv/formats/default/default.h"
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
#include "tlv/formats/fixed/fixed_1byte.h"
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
#include "tlv/formats/bluetooth/bluetooth_ltv.h"
#endif
#if OPENTLV_FORMAT_BER
#include "tlv/formats/asn1/ber.h"
#endif
#if OPENTLV_FORMAT_DER
#include "tlv/formats/asn1/der.h"
#endif
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

using cli::fail;

namespace {

const tlv_writer_format_t* select_writer(const char* name) {
#if OPENTLV_FORMAT_DEFAULT
    if (!strcmp(name, "default")) return &tlv_writer_format_default;
#endif
#if OPENTLV_FORMAT_FIXED_1BYTE
    if (!strcmp(name, "fixed-1byte")) return &tlv_writer_format_fixed_1byte;
#endif
#if OPENTLV_FORMAT_BER
    if (!strcmp(name, "ber")) return &tlv_writer_format_ber;
#endif
#if OPENTLV_FORMAT_DER
    if (!strcmp(name, "der")) return &tlv_writer_format_der;
#endif
#if OPENTLV_FORMAT_BLUETOOTH_LTV
    if (!strcmp(name, "bluetooth-ltv")) return &tlv_writer_format_bluetooth_ltv;
#endif
    (void)name;
    return NULL;
}

// Builds the element list from --tag/--value.
int specs_from_options(const cli::options& o, std::vector<cli::commands::element_spec>& specs) {
    cli::commands::element_spec spec;
    int                         rc = cli::decode_hex(o.tag, TLV_TAG_CAPACITY, spec.tag);
    if (rc == 3) return fail(2, "tag is longer than the supported tag capacity");
    if (rc) return rc;
    if (spec.tag.empty()) return fail(2, "tag must not be empty");
    if (o.value && (rc = cli::decode_hex(o.value, o.max_input, spec.value))) return rc;
    specs.push_back(std::move(spec));
    return 0;
}

// Builds a tlv_tag_t from validated-length tag bytes (size <= TLV_TAG_CAPACITY).
tlv_tag_t make_tag(const std::vector<uint8_t>& bytes) {
    tlv_tag_t tag;
    std::memset(&tag, 0, sizeof tag);
    std::memcpy(tag.data, bytes.data(), bytes.size());
    tag.size = (uint8_t)bytes.size();
    return tag;
}

std::string hex_text(const std::vector<uint8_t>& bytes) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       text;
    text.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        text += digits[byte >> 4];
        text += digits[byte & 0xF];
    }
    return text;
}

// Reports a writer rejection with the offending element's tag.
int write_failed(std::size_t index, tlv_result_t rc) {
    std::cerr << "otlv: cannot encode element " << index << ": " << tlv_strerror(rc) << "\n";
    return rc == TLV_ERR_OUT_OF_MEMORY ? 3 : 1;
}

// Encodes the elements of a JSON document with the format's writer. Children
// are encoded first and become their parent's value, so every length is
// derived from the bytes actually written.
class json_encoder {
public:
    json_encoder(const tlv_writer_format_t* format, const char* name)
        : format_(format), name_(name) {
#if OPENTLV_FORMAT_BER
        ber_ = !strcmp(name, "ber");
#endif
#if OPENTLV_FORMAT_DER
        der_ = !strcmp(name, "der");
#endif
    }

    int encode(const std::vector<cli::json_model::node>& elements, std::vector<uint8_t>& out) {
        for (const cli::json_model::node& element : elements) {
            const int rc = encode_element(element, out);
            if (rc) return rc;
        }
        return 0;
    }

private:
    bool is_constructed(const tlv_tag_t& tag) const {
#if OPENTLV_FORMAT_BER
        if (ber_) return tlv_ber_is_constructed(nullptr, &tag) != 0;
#endif
#if OPENTLV_FORMAT_DER
        if (der_) return tlv_der_is_constructed(nullptr, &tag) != 0;
#endif
        (void)tag;
        return false;
    }

    int reject(std::size_t index, const std::string& reason) {
        std::cerr << "otlv: cannot encode element " << index << ": " << reason << "\n";
        return 2;
    }

    // Elements are numbered in preorder, as they appear in the document.
    int encode_element(const cli::json_model::node& element, std::vector<uint8_t>& out) {
        const std::size_t           index = index_++;
        const tlv_tag_t             tag = make_tag(element.tag);
        std::vector<uint8_t>        children;
        const std::vector<uint8_t>* value = &element.value;
        std::size_t                 size;
        tlv_result_t                result;

        if (ber_ || der_) {
            const bool constructed = is_constructed(tag);
            if (element.has_children && !constructed)
                return reject(index, "tag " + hex_text(element.tag) +
                                         " is primitive; use \"value\" instead of \"children\"");
            if (element.has_value && constructed)
                return reject(index, "tag " + hex_text(element.tag) +
                                         " is constructed; use \"children\" instead of \"value\"");
        } else if (element.has_children) {
            return reject(index, std::string("format ") + name_ +
                                     " has no constructed elements; use \"value\"");
        }
        if (element.indefinite && !ber_)
            return reject(index,
                          std::string("indefinite length requires format ber, not ") + name_);
        if (element.has_children) {
            const int rc = encode(element.children, children);
            if (rc) return rc;
            value = &children;
        }
        const std::size_t before = out.size();
#if OPENTLV_FORMAT_BER
        if (element.indefinite)
            result = tlv_ber_indefinite_encoded_size(tag, value->size(), &size);
        else
#endif
            result = tlv_encoded_size(tag, value->size(), format_, &size);
        if (result != TLV_OK) return write_failed(index, result);
        if (size > SIZE_MAX - before) return fail(3, "encoded output too large");
        try {
            out.resize(before + size);
        } catch (const std::bad_alloc&) {
            return fail(3, "cannot allocate CLI memory");
        }
#if OPENTLV_FORMAT_BER
        if (element.indefinite)
            result = tlv_ber_write_indefinite(out.data() + before, size, tag, value->data(),
                                              value->size(), &size);
        else
#endif
            result = tlv_write(out.data() + before, size, format_, tag, value->data(),
                               value->size(), &size);
        return result == TLV_OK ? 0 : write_failed(index, result);
    }

    const tlv_writer_format_t* format_;
    const char*                name_;
    bool                       ber_ = false;
    bool                       der_ = false;
    std::size_t                index_ = 0;
};

// Emits encoded bytes as hex text or raw bytes, to stdout or --output-file.
int emit(const cli::options& o, const std::vector<uint8_t>& out) {
    if (o.output_file) {
        std::ofstream file(o.output_file, std::ios::binary | std::ios::trunc);
        if (!file) return fail(3, "cannot open output file");
        if (o.binary_output)
            file.write(reinterpret_cast<const char*>(out.data()), (std::streamsize)out.size());
        else
            file << hex_text(out) << "\n";
        file.flush();
        if (!file) return fail(3, "cannot write output file");
        file.close();
        return file ? 0 : fail(3, "cannot write output file");
    }
    if (o.binary_output) {
#ifdef _WIN32
        if (_setmode(_fileno(stdout), _O_BINARY) == -1)
            return fail(3, "cannot set binary stdout mode");
#endif
        std::cout.write(reinterpret_cast<const char*>(out.data()), (std::streamsize)out.size());
    } else {
        std::cout << hex_text(out) << "\n";
    }
    return cli::flush_stdout();
}

// Encodes the JSON document named by --input.
int encode_json(const cli::options& o, const tlv_writer_format_t* format) {
    std::string               text;
    cli::json_model::document document;
    std::vector<uint8_t>      out;
    int                       rc;

    if ((rc = cli::read_text(o.input, o.max_input, text))) return rc;
    if ((rc = cli::json_model::parse(text, o.format, o.max_depth, o.max_elements, document)))
        return rc;
    try {
        json_encoder encoder(format, o.format);
        if ((rc = encoder.encode(document.elements, out))) return rc;
    } catch (const std::bad_alloc&) {
        return fail(3, "cannot allocate CLI memory");
    }
    if (out.size() > o.max_input) return fail(3, "encoded output exceeds --max-input-size");

    // The output must be accepted by the reader and structural validator the
    // "validate" command uses for this format, under the same limits.
    cli::options check;
    check.command = "validate";
    check.format = o.format;
    check.max_input = o.max_input;
    check.max_depth = o.max_depth;
    check.max_elements = o.max_elements;
    if (cli::commands::execute(check, out.data(), out.size()) != 0)
        return fail(1, "encoded output failed validation");
    return emit(o, out);
}

} // namespace

namespace cli {
namespace commands {

int encode(const options& o) {
    const tlv_writer_format_t* format = select_writer(o.format);
    std::vector<element_spec>  specs;
    std::vector<uint8_t>       out;
    std::size_t                total = 0, i;
    int                        rc;

    if (!format) return fail(2, "unknown or disabled format; use otlv formats");
    if (o.input) return encode_json(o, format);
    if ((rc = specs_from_options(o, specs))) return rc;

    // Validate every element and size the whole output before writing, so a
    // rejected element never yields partial output.
    for (i = 0; i < specs.size(); ++i) {
        std::size_t  size;
        tlv_result_t result =
            tlv_encoded_size(make_tag(specs[i].tag), specs[i].value.size(), format, &size);
        if (result != TLV_OK) return write_failed(i, result);
        if (total > SIZE_MAX - size) return fail(3, "encoded output too large");
        total += size;
    }
    try {
        out.resize(total);
    } catch (const std::bad_alloc&) {
        return fail(3, "cannot allocate CLI memory");
    }
    tlv_writer_t writer;
    if (tlv_writer_init(&writer, out.data(), out.size(), format) != TLV_OK)
        return fail(3, "cannot initialize writer");
    for (i = 0; i < specs.size(); ++i) {
        tlv_result_t result = tlv_writer_write(&writer, make_tag(specs[i].tag),
                                               specs[i].value.data(), specs[i].value.size());
        if (result != TLV_OK) return write_failed(i, result);
    }
    return emit(o, out);
}

} // namespace commands
} // namespace cli
