// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "frontend_internal.h"
#include "match_internal.h"
#include "../utf8_internal.h"
#include <limits.h>

static int whitespace(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
static int identifier_start(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static int identifier_continue(unsigned char c) {
    return identifier_start(c) || (c >= '0' && c <= '9') || c == '_' || c == '-';
}
static int word_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           c == '-' || c == '?';
}

static int format_operator(unsigned kind) {
    return kind == T_UNION || kind == T_INTERSECT || kind == T_EXCEPT ||
           (kind >= T_EQ && kind <= T_OR);
}

static tlv_result_t lex(const char* text, size_t size, size_t limit, query_token_t* tokens,
                        size_t* count, tlv_query_diagnostic_t* d, char* formatted,
                        size_t* formatted_size) {
    size_t pos = 0, used = 0, emitted = 0;
    unsigned previous = T_END;
    while (pos < size) {
        unsigned char c = (unsigned char)text[pos];
        if (whitespace(c)) {
            ++pos;
            continue;
        }
        size_t begin = pos++;
        unsigned kind = T_END;
        switch (c) {
            case '/':
                kind = T_SLASH;
                if (pos < size && text[pos] == '/') {
                    ++pos;
                    kind = T_DESC;
                }
                break;
            case '(': kind = T_OPEN; break;
            case ')': kind = T_CLOSE; break;
            case '[': kind = T_POPEN; break;
            case ']': kind = T_PCLOSE; break;
            case ',': kind = T_COMMA; break;
            case '|': kind = T_UNION; break;
            case '=': kind = T_EQ; break;
            case '!':
                if (pos < size && text[pos] == '=') {
                    ++pos;
                    kind = T_NE;
                }
                break;
            case '<':
                kind = T_LT;
                if (pos < size && text[pos] == '=') {
                    ++pos;
                    kind = T_LE;
                }
                break;
            case '>':
                kind = T_GT;
                if (pos < size && text[pos] == '=') {
                    ++pos;
                    kind = T_GE;
                }
                break;
            case '.':
                kind = T_DOT;
                if (pos < size && text[pos] == '.') {
                    ++pos;
                    kind = T_DDOT;
                }
                break;
            case ':':
                if (pos < size && text[pos] == ':') {
                    ++pos;
                    kind = T_AXIS;
                }
                break;
            case '*': kind = T_WORD; break;
            case '@':
            case '$':
                if (c == '$' && (pos == size || !identifier_start((unsigned char)text[pos])))
                    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, begin, pos,
                                       "variable identifier starting with a letter");
                kind = c == '@' ? T_META : T_VARIABLE;
                while (pos < size && (c == '$' ? identifier_continue((unsigned char)text[pos])
                                               : word_char((unsigned char)text[pos])))
                    ++pos;
                if (pos == begin + 1) kind = T_END;
                break;
            case '\'':
            case '"':
                kind = T_STRING;
                while (pos < size && (unsigned char)text[pos] != c) {
                    if ((unsigned char)text[pos] < 32)
                        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, pos,
                                           pos + 1, "ASCII string or escaped UTF-8 bytes");
                    if (text[pos] == '\\') {
                        ++pos;
                        if (pos == size ||
                            (text[pos] != '\\' && text[pos] != '\'' && text[pos] != '"'))
                            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, pos,
                                               pos, "escaped quote or backslash");
                    }
                    ++pos;
                }
                if (pos == size)
                    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, begin, pos,
                                       "closing quote");
                if (tlv_utf8_validate((const uint8_t*)text + begin + 1, pos - begin - 1) != TLV_OK)
                    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, begin, pos,
                                       "valid UTF-8 string");
                ++pos;
                break;
            default:
                if (c == 'x' && pos < size && text[pos] == '\'') {
                    kind = T_BYTES;
                    ++pos;
                    size_t digits = pos;
                    while (pos < size && text[pos] != '\'') {
                        if (query_hex((unsigned char)text[pos]) < 0)
                            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, pos,
                                               pos + 1, "hexadecimal byte");
                        ++pos;
                    }
                    if (pos == size || (pos - digits) % 2)
                        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, begin,
                                           pos, "even hexadecimal bytes and closing quote");
                    ++pos;
                } else if (word_char(c)) {
                    kind = T_WORD;
                    while (pos < size && word_char((unsigned char)text[pos])) ++pos;
                    /* A single colon separates a namespace; :: is an axis token. */
                    if (pos < size && text[pos] == ':' &&
                        (pos + 1 == size || text[pos + 1] != ':')) {
                        ++pos;
                        while (pos < size && word_char((unsigned char)text[pos])) ++pos;
                    }
                    if (query_word(text, begin, pos, "and")) kind = T_AND;
                    if (query_word(text, begin, pos, "or")) kind = T_OR;
                    if (query_word(text, begin, pos, "intersect")) kind = T_INTERSECT;
                    if (query_word(text, begin, pos, "except")) kind = T_EXCEPT;
                }
        }
        if (kind == T_END)
            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, begin, pos,
                               "Query token");
        if (used == limit) return query_limit(d, "tokens", limit, begin, pos);
        if (tokens) {
            tokens[used].kind = kind;
            tokens[used].begin = (uint32_t)begin;
            tokens[used].end = (uint32_t)pos;
        }
        if (formatted_size) {
            if (used &&
                (format_operator(kind) || format_operator(previous) || previous == T_COMMA ||
                 ((previous == T_SLASH || previous == T_DESC) &&
                  (kind == T_SLASH || kind == T_DESC)) ||
                 ((previous == T_DOT || previous == T_DDOT) &&
                  (kind == T_DOT || kind == T_DDOT)))) {
                if (emitted == SIZE_MAX) return TLV_ERR_OVERFLOW;
                if (formatted) formatted[emitted] = ' ';
                ++emitted;
            }
            int hexadecimal = kind == T_BYTES;
            if (pos - begin > SIZE_MAX - emitted) return TLV_ERR_OVERFLOW;
            if (kind == T_WORD && (pos - begin) % 2 == 0) {
                hexadecimal = 1;
                for (size_t j = begin; j < pos; ++j)
                    if (query_hex((unsigned char)text[j]) < 0 && text[j] != '?') hexadecimal = 0;
            }
            for (size_t j = begin; j < pos; ++j) {
                unsigned char value = (unsigned char)text[j];
                if (hexadecimal && value >= 'a' && value <= 'f')
                    value = (unsigned char)(value - 'a' + 'A');
                if (formatted) formatted[emitted] = (char)value;
                ++emitted;
            }
            previous = kind;
        }
        ++used;
    }
    if (formatted_size) *formatted_size = emitted;
    *count = used;
    return TLV_OK;
}

void tlv_query_compile_options_init(tlv_query_compile_options_t* o) {
    if (!o) return;
    memset(o, 0, sizeof *o);
    o->struct_size = sizeof *o;
    o->language_version = 1;
    o->max_text = 65536;
    o->max_tokens = 8192;
    o->max_nesting = 128;
    o->max_states = 8192;
    o->max_resolved_tag = 512;
    o->max_pattern = 4096;
    o->optimize = 1;
}

static tlv_result_t options_check(const tlv_query_compile_options_t* supplied,
                                  tlv_query_compile_options_t* o, size_t size,
                                  tlv_query_diagnostic_t* d) {
    tlv_query_compile_options_init(o);
    if (supplied) {
        if (supplied->struct_size != sizeof *o || supplied->language_version != 1 ||
            !supplied->max_text || !supplied->max_tokens || !supplied->max_nesting ||
            !supplied->max_states)
            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                               "initialized language-version 1 options");
        *o = *supplied;
    }
    if (o->variable_count > o->max_states || (o->variable_count && !o->variables))
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                           "bounded variable declarations");
    for (size_t i = 0; i < o->variable_count; ++i) {
        const tlv_query_variable_t* v = &o->variables[i];
        if (!v->name || !identifier_start((unsigned char)v->name[0]) ||
            v->type < TLV_QUERY_RESULT_INTEGER || v->type > TLV_QUERY_RESULT_STRING)
            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                               "named integer, bytes or string variable");
        for (size_t j = 0; v->name[j]; ++j)
            if (!identifier_continue((unsigned char)v->name[j]))
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                                   "variable identifier");
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(v->name, o->variables[j].name))
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                                   "unique variable declaration");
    }
    if (!o->max_resolved_tag || o->max_resolved_tag > UINT32_MAX || o->max_pattern > UINT32_MAX)
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "bounded capabilities");
    if (o->environment) {
        const tlv_query_environment_t* e = o->environment;
        if (e->hook_count > o->max_states || (e->hook_count && !e->hooks))
            return TLV_ERR_INVALID_ARG;
        for (size_t i = 0; i < e->hook_count; ++i) {
            const tlv_query_hook_t* h = &e->hooks[i];
            if (!h->id || h->function > TLV_QUERY_DATE || !h->scratch_alignment ||
                h->scratch_alignment > 16 || (h->scratch_alignment & (h->scratch_alignment - 1)) ||
                h->scratch_size > UINT32_MAX - 15)
                return TLV_ERR_INVALID_ARG;
            for (size_t j = 0; j < i; ++j)
                if (e->hooks[j].id == h->id || e->hooks[j].function == h->function)
                    return TLV_ERR_INVALID_ARG;
        }
    }
    if (size > o->max_text) return query_limit(d, "text", o->max_text, 0, size);
    if (size >= UINT32_MAX)
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable Query text size");
    return TLV_OK;
}

static size_t scratch_unit(void) {
    return sizeof(query_token_t) + 2 * sizeof(query_node_t) + sizeof(query_operator_t) +
           sizeof(uint32_t);
}

tlv_result_t tlv_query_compile_scratch(const char* text, size_t size,
                                       const tlv_query_compile_options_t* options, size_t* bytes,
                                       size_t* alignment, tlv_query_diagnostic_t* d) {
    query_diag_init(d);
    if (!text || !bytes || !alignment) return TLV_ERR_NULL_ARG;
    tlv_query_compile_options_t o;
    tlv_result_t rc = options_check(options, &o, size, d);
    if (rc != TLV_OK) return rc;
    size_t count;
    rc = lex(text, size, o.max_tokens, NULL, &count, d, NULL, NULL);
    if (rc != TLV_OK) return rc;
    if (count >= UINT32_MAX / 2 || count > SIZE_MAX / scratch_unit() - 1)
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable compile scratch size");
    size_t base = (count + 1) * scratch_unit();
    if (size > SIZE_MAX - base || count > (SIZE_MAX - base - size) / o.max_resolved_tag)
        return TLV_ERR_OVERFLOW;
    *bytes = base + size + count * o.max_resolved_tag;
    *alignment = sizeof(uint32_t);
    return TLV_OK;
}

static unsigned precedence(unsigned kind) {
    switch (kind) {
        case T_COMMA: return 1;
        case T_UNION: return 2;
        case T_INTERSECT:
        case T_EXCEPT: return 6;
        case T_OR: return 3;
        case T_AND: return 4;
        case T_EQ:
        case T_NE:
        case T_LT:
        case T_LE:
        case T_GT:
        case T_GE: return 5;
        case T_SLASH:
        case T_DESC: return 7;
        default: return 0;
    }
}
static unsigned operation(unsigned kind) {
    switch (kind) {
        case T_COMMA: return Q_ARGS;
        case T_UNION: return Q_UNION;
        case T_INTERSECT: return Q_INTERSECT;
        case T_EXCEPT: return Q_EXCEPT;
        case T_OR: return Q_OR;
        case T_AND: return Q_AND;
        case T_EQ: return Q_EQ;
        case T_NE: return Q_NE;
        case T_LT: return Q_LT;
        case T_LE: return Q_LE;
        case T_GT: return Q_GT;
        case T_GE: return Q_GE;
        case T_DESC: return Q_DESC;
        default: return Q_CHILD;
    }
}
static uint32_t add_node(query_node_t* nodes, size_t* used, unsigned op, uint32_t left,
                         uint32_t right, query_token_t token) {
    query_node_t n = {0};
    n.op = op;
    n.left = left;
    n.right = right;
    n.begin = token.begin;
    n.end = token.end;
    n.low = (uint32_t)*used;
    if (left != QUERY_NONE && nodes[left].low < n.low) n.low = nodes[left].low;
    if (right != QUERY_NONE && nodes[right].low < n.low) n.low = nodes[right].low;
    n.predicate_guard = QUERY_NONE;
    n.path_guard = QUERY_NONE;
    n.reuse = QUERY_NONE;
    nodes[*used] = n;
    return (uint32_t)(*used)++;
}
static int reduce(query_node_t* nodes, size_t* used, uint32_t* values, size_t* vn,
                  query_operator_t op, const query_token_t* tokens) {
    if (*vn < 2) return 0;
    uint32_t right = values[--*vn], left = values[--*vn];
    values[(*vn)++] = add_node(nodes, used, operation(op.kind), left, right, tokens[op.token]);
    return 1;
}

static tlv_result_t parse(const char* text, const query_token_t* tokens, size_t count,
                          query_node_t* nodes, query_operator_t* ops, uint32_t* values,
                          const tlv_query_compile_options_t* o, size_t* used, uint32_t* root,
                          tlv_query_diagnostic_t* d) {
    size_t on = 0, vn = 0, nesting = 0, predicates = 0;
    int expected = 1, after_path = 0;
    *used = 0;
    for (size_t i = 0; i < count; ++i) {
        query_token_t t = tokens[i];
        unsigned k = t.kind;
        if (k == T_OPEN || k == T_POPEN) {
            if ((k == T_POPEN && expected) || (k == T_OPEN && !expected)) goto syntax;
            if (nesting == o->max_nesting)
                return query_limit(d, "nesting", o->max_nesting, t.begin, t.end);
            query_operator_t op = {k, (uint32_t)i, (uint32_t)vn, QUERY_NONE};
            ops[on++] = op;
            ++nesting;
            if (k == T_POPEN) ++predicates;
            expected = 1;
            after_path = 0;
            continue;
        }
        if (k == T_CLOSE || k == T_PCLOSE) {
            while (on && precedence(ops[on - 1].kind)) {
                if (!reduce(nodes, used, values, &vn, ops[--on], tokens)) goto syntax;
            }
            if (!on) goto syntax;
            query_operator_t op = ops[--on];
            if ((k == T_CLOSE && op.kind != T_OPEN) || (k == T_PCLOSE && op.kind != T_POPEN))
                goto syntax;
            --nesting;
            if (op.function != QUERY_NONE) {
                if (vn != op.base && (expected || vn != op.base + 1)) goto syntax;
                uint32_t args = vn == op.base ? QUERY_NONE : values[--vn];
                values[vn++] = add_node(nodes, used, Q_CALL, args, QUERY_NONE, tokens[op.function]);
                nodes[values[vn - 1]].anchor =
                    !predicates && !(op.function && (tokens[op.function - 1].kind == T_SLASH ||
                                                     tokens[op.function - 1].kind == T_DESC));
            } else if (op.kind == T_POPEN) {
                if (expected || vn != op.base + 1 || op.base == 0) goto syntax;
                uint32_t rhs = values[--vn], lhs = values[--vn];
                values[vn++] = add_node(nodes, used, Q_FILTER, lhs, rhs, tokens[op.token]);
                --predicates;
            } else {
                if (expected || vn != op.base + 1) goto syntax;
                nodes[values[vn - 1]].grouped = 1;
            }
            expected = 0;
            after_path = 0;
            continue;
        }
        if (precedence(k)) {
            if (expected) {
                if (k != T_SLASH && k != T_DESC) goto syntax;
                values[vn++] = add_node(nodes, used, Q_ROOT, QUERY_NONE, QUERY_NONE, t);
            }
            while (on && precedence(ops[on - 1].kind) >= precedence(k)) {
                if (!reduce(nodes, used, values, &vn, ops[--on], tokens)) goto syntax;
            }
            query_operator_t op = {k, (uint32_t)i, 0, QUERY_NONE};
            ops[on++] = op;
            expected = 1;
            after_path = k == T_SLASH || k == T_DESC;
            continue;
        }
        if (!expected) goto syntax;
        if (k == T_WORD && i + 1 < count && tokens[i + 1].kind == T_OPEN) {
            if (nesting == o->max_nesting)
                return query_limit(d, "nesting", o->max_nesting, t.begin, t.end);
            query_operator_t op = {T_OPEN, (uint32_t)(i + 1), (uint32_t)vn, (uint32_t)i};
            ops[on++] = op;
            ++nesting;
            ++i;
            after_path = 0;
            continue;
        }
        unsigned axis = A_CHILD;
        if (k == T_WORD && i + 1 < count && tokens[i + 1].kind == T_AXIS) {
            for (axis = A_CHILD; axis <= A_PRECEDE; ++axis)
                if (query_word(text, t.begin, t.end, query_axis_name(axis))) break;
            if (axis > A_PRECEDE)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, t.begin, t.end,
                                   "known axis");
            i += 2;
            if (i >= count || tokens[i].kind != T_WORD) goto syntax;
            t = tokens[i];
            k = t.kind;
        }
        unsigned op = Q_TEST;
        if (k == T_DOT)
            op = Q_SELF;
        else if (k == T_DDOT) {
            op = Q_TEST;
            axis = A_PARENT;
        } else if (k == T_META)
            op = Q_META;
        else if (k == T_VARIABLE)
            op = Q_VARIABLE;
        else if (k == T_BYTES)
            op = Q_BYTES;
        else if (k == T_STRING)
            op = Q_STRING;
        else if (k != T_WORD)
            goto syntax;
        if (op == Q_SELF && !predicates && !after_path) op = Q_ROOT;
        uint32_t n = add_node(nodes, used, op, QUERY_NONE, QUERY_NONE, t);
        nodes[n].axis = axis;
        nodes[n].anchor = !predicates && !after_path;
        nodes[n].scalar = predicates != 0;
        values[vn++] = n;
        expected = 0;
        after_path = 0;
        if (*used > o->max_states) return query_limit(d, "states", o->max_states, t.begin, t.end);
        continue;
    syntax:
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, t.begin, t.end,
                           expected ? "expression or step" : "operator or closing delimiter");
    }
    if (expected || nesting) {
        size_t eof = count ? tokens[count - 1].end : 0;
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, eof, eof,
                           nesting ? "closing delimiter" : "expression");
    }
    while (on)
        if (!reduce(nodes, used, values, &vn, ops[--on], tokens)) return TLV_ERR_INVALID_ARG;
    if (vn != 1) return TLV_ERR_INVALID_ARG;
    if (*used > o->max_states) return query_limit(d, "states", o->max_states, 0, 0);
    *root = values[0];
    return TLV_OK;
}

static int decimal(const char* text, const query_node_t* n) {
    size_t begin = n->begin;
    size_t prefix = begin;
    while (prefix && whitespace((unsigned char)text[prefix - 1])) --prefix;
    if (prefix >= 2 && text[prefix - 1] == ':' && text[prefix - 2] == ':') return 0;
    if (text[begin] == '-') ++begin;
    if (begin == n->end) return 0;
    for (size_t i = begin; i < n->end; ++i)
        if (text[i] < '0' || text[i] > '9') return 0;
    return 1;
}

static tlv_result_t resolve_name(const char* text, size_t begin, size_t end,
                                 const tlv_query_compile_options_t* o, tlv_tag_t* tag,
                                 tlv_query_diagnostic_t* d) {
    if (!o->resolve)
        return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY, begin, end,
                           "compile-time name resolver");
    size_t colon = begin;
    while (colon < end && text[colon] != ':') ++colon;
    tlv_result_t rc = o->resolve(
        o->resolve_context, colon < end ? text + begin : NULL, colon < end ? colon - begin : 0,
        text + (colon < end ? colon + 1 : begin), end - (colon < end ? colon + 1 : begin), tag);
    if (rc != TLV_OK)
        return query_error(d, rc, TLV_QUERY_ERROR_CAPABILITY, begin, end,
                           "one unambiguous symbolic name");
    if (!tag->size || !tag->data || tag->size > o->max_resolved_tag)
        return query_limit(d, "resolved-tag", o->max_resolved_tag, begin, end);
    return TLV_OK;
}
static size_t call_args(const query_node_t* nodes, const query_node_t* n, uint32_t args[3]) {
    size_t count = 0;
    uint32_t cursor = n->left;
    while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
        if (count == 2) return 4;
        args[count++] = nodes[cursor].right;
        cursor = nodes[cursor].left;
    }
    if (cursor != QUERY_NONE) args[count++] = cursor;
    for (size_t i = 0; i < count / 2; ++i) {
        uint32_t temp = args[i];
        args[i] = args[count - i - 1];
        args[count - i - 1] = temp;
    }
    return count;
}
static tlv_result_t analyze(const char* text, query_node_t* nodes, size_t count, uint32_t root,
                            const tlv_query_compile_options_t* o, uint8_t* payload,
                            size_t* payload_size, size_t* codec_stride, size_t* optimized,
                            tlv_query_level_t* level, tlv_query_diagnostic_t* d) {
    *level = TLV_QUERY_S0;
    *payload_size = 0;
    *codec_stride = 0;
    *optimized = 0;
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
#if !OPENTLV_QUERY_SET_OPERATIONS
        if (n->op >= Q_UNION && n->op <= Q_EXCEPT)
            return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY, n->begin,
                               n->end, "Query set operations enabled");
#endif
        if (n->op >= Q_EQ && n->op <= Q_GE) {
            uint32_t sides[2] = {n->left, n->right};
            for (unsigned j = 0; j < 2; ++j)
                if (nodes[sides[j]].op == Q_TEST && decimal(text, &nodes[sides[j]]))
                    nodes[sides[j]].op = Q_LITERAL;
        }
        if (n->op == Q_FILTER && nodes[n->right].op == Q_TEST && decimal(text, &nodes[n->right])) {
            nodes[n->right].op = Q_LITERAL;
            nodes[n->right].anchor = 2;
        }
        if (n->op == Q_CALL && query_function_kind(text, n) == F_SUBSTR) {
            uint32_t args[3];
            size_t arity = call_args(nodes, n, args);
            if (arity > 3) return TLV_ERR_INVALID_ARG;
            for (size_t j = 1; j < arity; ++j)
                if (nodes[args[j]].op == Q_TEST && decimal(text, &nodes[args[j]]))
                    nodes[args[j]].op = Q_LITERAL;
        }
        if (n->op == Q_TEST && (query_word(text, n->begin, n->end, "true") ||
                                query_word(text, n->begin, n->end, "false"))) {
            n->op = Q_BOOL;
            n->folded = text[n->begin] == 't';
        }
    }
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
        n->type = V_NODE;
        n->context =
            (n->op == Q_ROOT || n->op == Q_SELF || n->op == Q_TEST) && text[n->begin] == '.';
        if (n->op == Q_CALL) n->selector = query_function_kind(text, n);
        if (n->op == Q_META) {
            static const char* names[] = {"@len", "@depth", "@index", "@offset", "@hlen"};
            for (unsigned j = 0; j < 5; ++j)
                if (query_word(text, n->begin, n->end, names[j])) n->selector = j;
        }
        if (n->op == Q_TEST && n->axis == A_PARENT && n->end - n->begin == 2 &&
            text[n->begin] == '.' && text[n->begin + 1] == '.') {
            n->resolved = 0;
            n->data_offset = (uint32_t)*payload_size;
            n->data_size = 0;
        }
        if (n->op == Q_TEST && !n->resolved && !n->context) {
            int raw = 1;
            for (size_t j = n->begin; j < n->end; ++j)
                if (query_hex((unsigned char)text[j]) < 0 && text[j] != '?' && text[j] != '*')
                    raw = 0;
            if (!raw) {
                tlv_tag_t tag;
                tlv_result_t rc = resolve_name(text, n->begin, n->end, o, &tag, d);
                if (rc != TLV_OK) return rc;
                n->resolved = 1;
                n->data_offset = (uint32_t)*payload_size;
                n->data_size = (uint32_t)tag.size;
                memcpy(payload + *payload_size, tag.data, tag.size);
                *payload_size += tag.size;
            } else if (!(n->end - n->begin == 1 && text[n->begin] == '*')) {
                if ((n->end - n->begin) % 2) goto syntax;
                for (size_t j = n->begin; j < n->end; j += 2)
                    if (!((text[j] == '?' && text[j + 1] == '?') ||
                          (query_hex((unsigned char)text[j]) >= 0 &&
                           query_hex((unsigned char)text[j + 1]) >= 0)))
                        goto syntax;
                n->resolved = 2;
                n->data_offset = (uint32_t)*payload_size;
                n->data_size = (n->end - n->begin) / 2;
                for (size_t j = n->begin; j < n->end; j += 2)
                    payload[(*payload_size)++] =
                        text[j] == '?' ? 0
                                       : (uint8_t)(query_hex((unsigned char)text[j]) * 16 +
                                                   query_hex((unsigned char)text[j + 1]));
                n->mask_offset = (uint32_t)*payload_size;
                for (size_t j = n->begin; j < n->end; j += 2)
                    payload[(*payload_size)++] = text[j] == '?' ? 0 : 255;
            }
        }
        if (n->op == Q_TEST &&
            ((n->axis >= A_DESC_SELF && !(n->axis == A_PRECEDE_SIBLING && n->scalar)) ||
             (n->axis == A_DESC && n->scalar) || (n->axis == A_ANCESTOR && !n->scalar) ||
             (n->axis == A_CHILD && n->scalar)))
            *level = TLV_QUERY_D;

        if (n->op == Q_VARIABLE) {
            n->data_offset = (uint32_t)*payload_size;
            n->data_size = n->end - n->begin - 1;
            memcpy(payload + *payload_size, text + n->begin + 1, n->data_size);
            *payload_size += n->data_size;
            int found = 0;
            for (size_t j = 0; j < o->variable_count; ++j)
                if (query_word(text, n->begin + 1, n->end, o->variables[j].name)) {
                    n->type = query_private_type(o->variables[j].type);
                    found = 1;
                    break;
                }
            if (!found)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, n->begin,
                                   n->end, "declared typed variable");
        }
        if (n->op == Q_META || n->op == Q_LITERAL) n->type = V_NUMBER;
        if (n->op == Q_BOOL) n->type = V_BOOL;
        if (n->op == Q_META && !query_word(text, n->begin, n->end, "@len") &&
            !query_word(text, n->begin, n->end, "@depth") &&
            !query_word(text, n->begin, n->end, "@index") &&
            !query_word(text, n->begin, n->end, "@offset") &&
            !query_word(text, n->begin, n->end, "@hlen"))
            goto syntax;
        if (n->op == Q_LITERAL) {
            uint64_t value = 0;
            int negative = text[n->begin] == '-';
            uint64_t maximum = (uint64_t)INT64_MAX + (unsigned)negative;
            for (size_t j = n->begin + (unsigned)negative; j < n->end; ++j) {
                unsigned digit = (unsigned)(text[j] - '0');
                if (digit > 9 || value > (maximum - digit) / 10)
                    return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                       n->end, "signed int64");
                value = value * 10 + digit;
            }
            n->immediate_low = (uint32_t)value;
            n->immediate_high = (uint32_t)(value >> 32);
            n->negative = value ? (uint32_t)negative : 0;
            if (n->anchor == 2) *level = TLV_QUERY_D;
        }
        if (n->op == Q_BYTES || n->op == Q_STRING) {
            n->type = n->op == Q_BYTES ? V_BYTES : V_STRING;
            n->data_offset = (uint32_t)*payload_size;
            if (n->op == Q_BYTES) {
                for (size_t j = n->begin + 2; j + 1 < n->end - 1; j += 2)
                    payload[(*payload_size)++] = (uint8_t)(query_hex((unsigned char)text[j]) * 16 +
                                                           query_hex((unsigned char)text[j + 1]));
            } else {
                for (size_t j = n->begin + 1; j < n->end - 1; ++j) {
                    if (text[j] == '\\') ++j;
                    payload[(*payload_size)++] = (uint8_t)text[j];
                }
            }
            n->data_size = (uint32_t)(*payload_size - n->data_offset);
        }
        if (n->op >= Q_EQ && n->op <= Q_OR) n->type = V_BOOL;
        if (n->op == Q_CALL) {
            unsigned f = query_function_kind(text, n);
            uint32_t args[3];
            size_t arity = call_args(nodes, n, args);
            if (arity > 3) goto syntax;
            if (f == F_NAME) {
                if (arity != 2 || nodes[args[0]].op != Q_STRING || nodes[args[1]].op != Q_STRING)
                    goto types;
                const query_node_t *ns = &nodes[args[0]], *symbol = &nodes[args[1]];
                if (!o->resolve)
                    return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                       n->begin, n->end, "name resolver");
                tlv_tag_t tag;
                tlv_result_t rc = o->resolve(
                    o->resolve_context, (const char*)payload + ns->data_offset, ns->data_size,
                    (const char*)payload + symbol->data_offset, symbol->data_size, &tag);
                if (rc != TLV_OK)
                    return query_error(d, rc, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                                       "one symbolic name");
                if (!tag.data || !tag.size || tag.size > o->max_resolved_tag)
                    return query_limit(d, "resolved-tag", o->max_resolved_tag, n->begin, n->end);
                n->op = Q_TEST;
                n->left = n->right = QUERY_NONE;
                n->resolved = 1;
                n->data_offset = (uint32_t)*payload_size;
                n->data_size = (uint32_t)tag.size;
                memcpy(payload + *payload_size, tag.data, tag.size);
                *payload_size += tag.size;
                if (n->scalar || n->predicate_guard != QUERY_NONE || n->axis != A_CHILD)
                    *level = TLV_QUERY_D;
                continue;
            }
            if (f == F_UNKNOWN)
                return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                   n->begin, n->end, "closed supported Query function");
            if ((f == F_VALUE || f == F_LEN || f == F_TAG || f == F_CLASS || f == F_NUMBER ||
                 f == F_CONSTRUCTED) &&
                arity > 1)
                goto syntax;
            if ((f == F_NOT || f == F_COUNT || f == F_EXISTS || f == F_EMPTY ||
                 (f >= F_NUM && f <= F_DATE)) &&
                arity != 1)
                goto syntax;
            if ((f == F_POSITION || f == F_LAST) && arity) goto syntax;
            if ((f == F_STARTS || f == F_ENDS || f == F_CONTAINS || f == F_MASK || f == F_RANGE) &&
                arity != 2)
                goto syntax;
            if (f == F_SUBSTR && arity != 2 && arity != 3) goto syntax;
            /* Node-test functions inside predicates select children of the
               candidate context. The immediate VM cannot publish that evidence
               at BEGIN; use the retained backend rather than testing the parent. */
            if ((f == F_MASK || f == F_RANGE) && n->predicate_guard != QUERY_NONE)
                *level = TLV_QUERY_S2;
            n->type = f == F_VALUE || f == F_TAG || f == F_SUBSTR ? V_BYTES
                      : f == F_LEN || f == F_COUNT || f == F_POSITION || f == F_LAST ||
                              f == F_NUM || f == F_BCD || f == F_DATE || f == F_CLASS ||
                              f == F_NUMBER
                          ? V_NUMBER
                      : f == F_TEXT                 ? V_STRING
                      : f == F_MASK || f == F_RANGE ? V_NODE
                                                    : V_BOOL;
            if (f == F_VALUE || f == F_TAG || f == F_CLASS || f == F_NUMBER || f == F_CONSTRUCTED) {
                if (arity && nodes[args[0]].type != V_NODE) goto types;
                if (arity) *level = TLV_QUERY_D;
            } else if (f == F_LEN) {
                if (arity && nodes[args[0]].type != V_BYTES && nodes[args[0]].type != V_STRING)
                    goto types;
            } else if (f == F_NOT) {
                if (nodes[args[0]].type != V_BOOL && nodes[args[0]].type != V_NODE) goto types;
            } else if (f == F_COUNT || f == F_EXISTS || f == F_EMPTY) {
                if (nodes[args[0]].type != V_NODE) goto types;
                *level = TLV_QUERY_D;
            } else if (f == F_POSITION || f == F_LAST)
                *level = TLV_QUERY_D;
            else if (f >= F_NUM && f <= F_DATE) {
                if (nodes[args[0]].type != V_NODE && nodes[args[0]].type != V_BYTES) goto types;
                const tlv_query_hook_t* hook = NULL;
                if (o->environment)
                    for (size_t j = 0; j < o->environment->hook_count; ++j)
                        if ((unsigned)o->environment->hooks[j].function == f - F_NUM)
                            hook = &o->environment->hooks[j];
                if (!hook)
                    return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                       n->begin, n->end, "conversion provider");
                n->hook_id = hook->id;
                n->scratch_size = (uint32_t)((hook->scratch_size + 15) & ~(size_t)15);
                if (n->scratch_size > *codec_stride) *codec_stride = n->scratch_size;
                *level = TLV_QUERY_D;
            } else if (f == F_SUBSTR) {
                if (nodes[args[0]].type != V_BYTES || nodes[args[1]].type != V_NUMBER ||
                    (arity == 3 && nodes[args[2]].type != V_NUMBER))
                    goto types;
            } else if (f == F_STARTS || f == F_ENDS || f == F_CONTAINS || f == F_MASK ||
                       f == F_RANGE) {
                if (nodes[args[0]].type != V_BYTES || nodes[args[1]].type != V_BYTES) goto types;
                if ((f == F_MASK || f == F_RANGE) &&
                    (nodes[args[0]].op != Q_BYTES || nodes[args[1]].op != Q_BYTES))
                    goto types;
                if (f == F_CONTAINS && nodes[args[1]].op == Q_BYTES &&
                    nodes[args[1]].data_size > o->max_pattern)
                    return query_limit(d, "pattern", o->max_pattern, n->begin, n->end);
                if (f == F_MASK && nodes[args[0]].data_size != nodes[args[1]].data_size)
                    goto syntax;
                if (f == F_RANGE) {
                    query_node_t *a = &nodes[args[0]], *b = &nodes[args[1]];
                    size_t size = a->data_size < b->data_size ? a->data_size : b->data_size;
                    int order = memcmp(payload + a->data_offset, payload + b->data_offset, size);
                    if (order > 0 || (!order && a->data_size > b->data_size)) goto syntax;
                }
            }
            if (f == F_TAG) *level = TLV_QUERY_D;
            if (f == F_CLASS || f == F_NUMBER) {
                if (!o->environment || !o->environment->tags || !o->environment->tags->id ||
                    (f == F_CLASS ? !o->environment->tags->class_of
                                  : !o->environment->tags->number_of))
                    return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                       n->begin, n->end, "semantic tag provider");
                *level = TLV_QUERY_D;
            }
            if (f == F_CONSTRUCTED) {
                if (o->environment && !o->environment->format) return TLV_ERR_UNSUPPORTED_TYPE;
                *level = TLV_QUERY_D;
            }
        }
        if ((n->op == Q_CHILD || n->op == Q_DESC || n->op == Q_UNION || n->op == Q_INTERSECT ||
             n->op == Q_EXCEPT) &&
            (nodes[n->left].type != V_NODE || nodes[n->right].type != V_NODE))
            goto types;
        if (n->op == Q_FILTER && query_reverse_axis(nodes[n->left].axis)) *level = TLV_QUERY_D;
        if (n->op == Q_FILTER &&
            (nodes[n->left].type != V_NODE ||
             (nodes[n->right].type != V_BOOL && nodes[n->right].type != V_NODE &&
              nodes[n->right].type != V_NUMBER)))
            goto types;
        if (n->op >= Q_EQ && n->op <= Q_GE &&
            (nodes[n->left].type != nodes[n->right].type || nodes[n->left].type == V_NODE))
            goto types;
        if ((n->op == Q_AND || n->op == Q_OR) &&
            ((nodes[n->left].type != V_BOOL && nodes[n->left].type != V_NODE) ||
             (nodes[n->right].type != V_BOOL && nodes[n->right].type != V_NODE)))
            goto types;
        if (o->optimize && n->op >= Q_EQ && n->op <= Q_GE) {
            const query_node_t* a = &nodes[n->left];
            const query_node_t* b = &nodes[n->right];
            int constant = 0, order = 0;
            if (a->op == Q_LITERAL && b->op == Q_LITERAL) {
                uint64_t av = 0, bv = 0;
                int an = text[a->begin] == '-', bn = text[b->begin] == '-';
                for (size_t j = a->begin + (unsigned)an; j < a->end; ++j)
                    av = av * 10 + (unsigned)(text[j] - '0');
                for (size_t j = b->begin + (unsigned)bn; j < b->end; ++j)
                    bv = bv * 10 + (unsigned)(text[j] - '0');
                if (!av) an = 0;
                if (!bv) bn = 0;
                order = an != bn ? an ? -1 : 1 : av < bv ? -1 : av > bv;
                if (an && bn) order = -order;
                constant = 1;
            } else if ((a->op == Q_BYTES || a->op == Q_STRING) && a->op == b->op) {
                size_t length = a->data_size < b->data_size ? a->data_size : b->data_size;
                order = memcmp(payload + a->data_offset, payload + b->data_offset, length);
                if (!order) order = a->data_size < b->data_size ? -1 : a->data_size > b->data_size;
                constant = 1;
            }
            if (constant) {
                n->folded = n->op == Q_EQ   ? order == 0
                            : n->op == Q_NE ? order != 0
                            : n->op == Q_LT ? order < 0
                            : n->op == Q_LE ? order <= 0
                            : n->op == Q_GT ? order > 0
                                            : order >= 0;
                n->op = Q_BOOL;
                n->left = n->right = QUERY_NONE;
                ++*optimized;
            }
        }
        /* A terminal dot contributes no navigation or fallible operation. */
        if (o->optimize && n->op == Q_CHILD && nodes[n->right].op == Q_SELF) {
            query_node_t* dot = &nodes[n->right];
            dot->op = Q_BOOL;
            dot->type = V_BOOL;
            dot->folded = 1;
            n->op = Q_FILTER;
            ++*optimized;
        }
        if (o->optimize && (n->op == Q_AND || n->op == Q_OR) && nodes[n->left].op == Q_BOOL &&
            nodes[n->right].op == Q_BOOL) {
            n->folded = n->op == Q_AND ? nodes[n->left].folded && nodes[n->right].folded
                                       : nodes[n->left].folded || nodes[n->right].folded;
            n->op = Q_BOOL;
            n->left = n->right = QUERY_NONE;
            ++*optimized;
        }
        if (o->optimize && n->op == Q_TEST) {
            for (size_t j = 0; j < i; ++j) {
                query_node_t* a = &nodes[j];
                if (a->op == Q_TEST && a->axis == n->axis && a->anchor == n->anchor &&
                    a->scalar == n->scalar && a->predicate_guard == n->predicate_guard &&
                    a->path_guard == n->path_guard && a->path_kind == n->path_kind &&
                    a->end - a->begin == n->end - n->begin &&
                    !memcmp(text + a->begin, text + n->begin, n->end - n->begin)) {
                    n->reuse = (uint32_t)j;
                    ++*optimized;
                    break;
                }
            }
        }
        continue;
    syntax:
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                           "valid Query operand/arity");
    types:
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                           "compatible expression types");
    }
    if (nodes[root].type != V_NODE) *level = TLV_QUERY_D;
    for (size_t i = 0; i < count; ++i)
        if (nodes[i].op == Q_ROOT && nodes[i].nested) *level = TLV_QUERY_D;
    if (*level == TLV_QUERY_D) {
        *level = TLV_QUERY_S2;
        for (size_t i = 0; i < count; ++i)
            if (nodes[i].op == Q_TEST && (nodes[i].axis == A_FOLLOW || nodes[i].axis == A_PRECEDE))
                *level = TLV_QUERY_D;
    }
    if (*level == TLV_QUERY_S2 && query_s1_filter(nodes, count, root) != QUERY_NONE)
        *level = TLV_QUERY_S1;
    return TLV_OK;
}

tlv_result_t tlv_query_compile(const char* text, size_t size,
                               const tlv_query_compile_options_t* options, void* scratch,
                               size_t scratch_size, void* storage, size_t capacity,
                               tlv_query_program_info_t* info, tlv_query_diagnostic_t* d) {
    query_diag_init(d);
    if (!text || !scratch || !info || (!storage && capacity)) return TLV_ERR_NULL_ARG;
    if (info->struct_size < offsetof(tlv_query_program_info_t, expression_values))
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "initialized program info extent");
    tlv_query_compile_options_t o;
    tlv_result_t rc = options_check(options, &o, size, d);
    if (rc != TLV_OK) return rc;
    size_t needed, alignment;
    rc = tlv_query_compile_scratch(text, size, &o, &needed, &alignment, d);
    if (rc != TLV_OK) return rc;
    if ((uintptr_t)scratch % alignment || (storage && (uintptr_t)storage % sizeof(uint32_t)))
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "aligned storage");
    if (scratch_size < needed)
        return query_error(d, TLV_ERR_BUFFER_TOO_SHORT, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "sufficient compile scratch capacity");
    size_t count = 0;
    rc = lex(text, size, o.max_tokens, NULL, &count, d, NULL, NULL);
    if (rc != TLV_OK) return rc;
    ++count;
    query_token_t* tokens = scratch;
    query_node_t* nodes = (query_node_t*)(tokens + count);
    query_operator_t* ops = (query_operator_t*)(nodes + 2 * count);
    uint32_t* values = (uint32_t*)(ops + count);
    --count;
    rc = lex(text, size, o.max_tokens, tokens, &count, d, NULL, NULL);
    if (rc != TLV_OK) return rc;
    size_t used;
    uint32_t root;
    rc = parse(text, tokens, count, nodes, ops, values, &o, &used, &root, d);
    if (rc != TLV_OK) return rc;
    for (size_t i = 0; i < used; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op == Q_FILTER) {
            for (size_t j = nodes[n->right].low; j <= n->right; ++j)
                nodes[j].predicate_guard = n->left;
        }
        if (n->op == Q_CHILD || n->op == Q_DESC) {
            for (size_t j = nodes[n->right].low; j <= n->right; ++j) {
                query_node_t* step = &nodes[j];
                if (step->op == Q_ROOT && !step->anchor && text[step->begin] == '/')
                    step->nested = 1;

                if (step->predicate_guard != QUERY_NONE || step->path_guard != QUERY_NONE) continue;
                int node_test =
                    step->op == Q_TEST || step->op == Q_SELF ||
                    (step->op == Q_ROOT && step->anchor) ||
                    (step->op == Q_CALL && (query_word(text, step->begin, step->end, "name") ||
                                            query_word(text, step->begin, step->end, "tag-mask") ||
                                            query_word(text, step->begin, step->end, "tag-range")));
                if (!node_test) continue;
                if (step->op == Q_ROOT) step->op = Q_SELF;
                unsigned kind = n->op;
                if (n->op == Q_CHILD && step->axis == A_DESC) kind = Q_DESC;
                if (n->op == Q_CHILD && (step->op == Q_SELF || step->axis == A_SELF)) kind = Q_SELF;
                step->path_guard = n->left;
                step->path_kind = kind;
                step->anchor = 0;
            }
        }
    }
    tlv_query_level_t level;
    size_t payload_size, codec_stride, optimized;
    uint8_t* payload = (uint8_t*)(values + count + 1);
    rc = analyze(text, nodes, used, root, &o, payload, &payload_size, &codec_stride, &optimized,
                 &level, d);
    if (size > SIZE_MAX - sizeof(tlv_query_program_t) - 1 ||
        used > (SIZE_MAX - sizeof(tlv_query_program_t) - size - 1) / sizeof(query_node_t))
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable program size");
    size_t text_offset = sizeof(tlv_query_program_t) + used * sizeof(query_node_t);
    if (payload_size > SIZE_MAX - text_offset - size - 1) return TLV_ERR_OVERFLOW;
    size_t total = text_offset + size + 1 + payload_size;
    if (total > UINT32_MAX)
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable program size");
    tlv_query_program_info_t result = {info->struct_size,
                                       total,
                                       sizeof(uint32_t),
                                       needed,
                                       alignment,
                                       used,
                                       1,
                                       level,
                                       query_public_type(nodes[root].type),
                                       used,
                                       used,
                                       0,
                                       codec_stride,
                                       o.max_pattern,
                                       optimized,
                                       used + 1,
                                       level >= TLV_QUERY_S2 ? query_candidate_size() : 0,
                                       level >= TLV_QUERY_S2 ? query_candidate_alignment() : 0,
                                       used,
                                       level == TLV_QUERY_S0   ? TLV_QUERY_DECISION_NODE
                                       : level == TLV_QUERY_S1 ? TLV_QUERY_DECISION_SCOPE
                                                               : TLV_QUERY_DECISION_EOF,
                                       level != TLV_QUERY_S0,
                                       query_nodes_need_values(nodes, used)};
    for (size_t i = 0; i < used; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op != Q_VARIABLE) continue;
        n->variable_slot = (uint32_t)result.variable_slots;
        for (size_t j = 0; j < i; ++j)
            if (nodes[j].op == Q_VARIABLE && nodes[j].end - nodes[j].begin == n->end - n->begin &&
                !memcmp(text + nodes[j].begin, text + n->begin, n->end - n->begin)) {
                n->variable_slot = nodes[j].variable_slot;
                break;
            }
        if (n->variable_slot == result.variable_slots) ++result.variable_slots;
    }
    if (rc != TLV_OK) {
        memcpy(info, &result,
               info->struct_size < sizeof result ? info->struct_size : sizeof result);
        return rc;
    }
    memcpy(info, &result, info->struct_size < sizeof result ? info->struct_size : sizeof result);
    if (!storage) return TLV_OK;
    if (capacity < total)
        return query_error(d, TLV_ERR_BUFFER_TOO_SHORT, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "sufficient program capacity");
    tlv_query_program_t p = {QUERY_MAGIC,
                             QUERY_IMAGE_VERSION,
                             (uint32_t)used,
                             root,
                             (uint32_t)size,
                             (uint32_t)text_offset,
                             (uint32_t)level,
                             (uint32_t)total,
                             (uint32_t)result.variable_slots,
                             (uint32_t)payload_size,
                             (uint32_t)o.max_pattern,
                             (uint32_t)codec_stride,
                             o.environment && o.environment->tags ? o.environment->tags->id : 0};
    memcpy(storage, &p, sizeof p);
    memcpy((uint8_t*)storage + sizeof p, nodes, used * sizeof *nodes);
    memcpy((uint8_t*)storage + text_offset, text, size);
    ((char*)storage)[text_offset + size] = 0;
    memcpy((uint8_t*)storage + text_offset + size + 1, payload, payload_size);
    return TLV_OK;
}

/* Never dereference untrusted nodes: only the fixed header and bounded text
   are consumed until canonical reconstruction has authenticated every field. */
static int image_overlap(const void* a, size_t an, const void* b, size_t bn) {
    if (!a || !b || !an || !bn) return 0;
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x <= y ? y - x < an : x - y < bn;
}

/* Compiler scratch already bounds all instruction nodes and copied payload.
   A second such extent plus header/text therefore bounds a prepared image. */
static tlv_result_t prepare_layout(const char* text, size_t size,
                                   const tlv_query_compile_options_t* options, size_t* offset,
                                   size_t* bytes, size_t* alignment,
                                   tlv_query_diagnostic_t* diagnostic) {
    size_t scratch, align;
    tlv_result_t rc = tlv_query_compile_scratch(text, size, options, &scratch, &align, diagnostic);
    if (rc != TLV_OK) return rc;
    if (scratch > SIZE_MAX - (sizeof(uint32_t) - 1)) return TLV_ERR_OVERFLOW;
    size_t start = (scratch + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
    if (size > SIZE_MAX - sizeof(tlv_query_program_t) - 1) return TLV_ERR_OVERFLOW;
    size_t image = sizeof(tlv_query_program_t) + size + 1;
    if (scratch > SIZE_MAX - image || start > SIZE_MAX - image - scratch) return TLV_ERR_OVERFLOW;
    *offset = start;
    *bytes = start + image + scratch;
    *alignment = align;
    return TLV_OK;
}

tlv_result_t tlv_query_compile_prepare_size(const char* text, size_t size,
                                            const tlv_query_compile_options_t* options,
                                            size_t* bytes, size_t* alignment,
                                            tlv_query_diagnostic_t* diagnostic) {
    if (!bytes || !alignment) return TLV_ERR_NULL_ARG;
    size_t offset;
    return prepare_layout(text, size, options, &offset, bytes, alignment, diagnostic);
}

tlv_result_t tlv_query_compile_prepare(const char* text, size_t size,
                                       const tlv_query_compile_options_t* options, void* workspace,
                                       size_t capacity, const tlv_query_program_t** prepared,
                                       tlv_query_program_info_t* info,
                                       tlv_query_diagnostic_t* diagnostic) {
    if (!text || !workspace || !prepared || !info) return TLV_ERR_NULL_ARG;
    if (info->struct_size < offsetof(tlv_query_program_info_t, expression_values) ||
        image_overlap(workspace, capacity, text, size) ||
        image_overlap(workspace, capacity, options, options ? sizeof *options : 0) ||
        image_overlap(workspace, capacity, prepared, sizeof *prepared) ||
        image_overlap(workspace, capacity, info, sizeof *info) ||
        image_overlap(workspace, capacity, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(prepared, sizeof *prepared, info, sizeof *info) ||
        image_overlap(prepared, sizeof *prepared, diagnostic,
                      diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(info, sizeof *info, diagnostic, diagnostic ? sizeof *diagnostic : 0))
        return TLV_ERR_INVALID_ARG;
    size_t offset, needed, alignment;
    tlv_result_t rc = prepare_layout(text, size, options, &offset, &needed, &alignment, diagnostic);
    if (rc != TLV_OK) return rc;
    if ((uintptr_t)workspace % alignment) return TLV_ERR_INVALID_ARG;
    if (capacity < needed) return TLV_ERR_BUFFER_TOO_SHORT;
    tlv_query_program_info_t result = {0};
    result.struct_size = sizeof result;
    void* image = (uint8_t*)workspace + offset;
    rc = tlv_query_compile(text, size, options, workspace, offset, image, needed - offset, &result,
                           diagnostic);
    if (rc != TLV_OK) return rc;
    result.struct_size = info->struct_size;
    memcpy(info, &result, info->struct_size < sizeof result ? info->struct_size : sizeof result);
    *prepared = image;
    return TLV_OK;
}

tlv_result_t tlv_query_compile_commit(const void* prepared, size_t prepared_size,
                                      const tlv_query_compile_options_t* options, void* scratch,
                                      size_t scratch_capacity, void* storage,
                                      size_t storage_capacity, tlv_query_program_info_t* info,
                                      tlv_query_diagnostic_t* diagnostic) {
    if (!prepared || !scratch || !storage) return TLV_ERR_NULL_ARG;
    if ((uintptr_t)storage % sizeof(uint32_t) ||
        (info && info->struct_size < offsetof(tlv_query_program_info_t, expression_values)) ||
        image_overlap(storage, storage_capacity, prepared, prepared_size) ||
        image_overlap(storage, storage_capacity, scratch, scratch_capacity) ||
        image_overlap(storage, storage_capacity, options, options ? sizeof *options : 0) ||
        image_overlap(storage, storage_capacity, info, info ? sizeof *info : 0) ||
        image_overlap(storage, storage_capacity, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(prepared, prepared_size, info, info ? sizeof *info : 0) ||
        image_overlap(prepared, prepared_size, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(scratch, scratch_capacity, info, info ? sizeof *info : 0) ||
        image_overlap(scratch, scratch_capacity, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(info, info ? sizeof *info : 0, diagnostic,
                      diagnostic ? sizeof *diagnostic : 0))
        return TLV_ERR_INVALID_ARG;
    if (storage_capacity < prepared_size) {
        query_diag_init(diagnostic);
        return TLV_ERR_BUFFER_TOO_SHORT;
    }
    tlv_query_program_info_t result = {0};
    result.struct_size = sizeof result;
    const tlv_query_program_t* validated;
    tlv_result_t rc = tlv_query_program_load(prepared, prepared_size, options, scratch,
                                             scratch_capacity, &validated, &result, diagnostic);
    if (rc != TLV_OK) return rc;
    memcpy(storage, validated, prepared_size);
    if (info) {
        result.struct_size = info->struct_size;
        memcpy(info, &result,
               info->struct_size < sizeof result ? info->struct_size : sizeof result);
    }
    return TLV_OK;
}

static tlv_result_t image_header(const void* image, size_t size, tlv_query_program_t* header,
                                 tlv_query_diagnostic_t* diagnostic) {
    if (image_overlap(image, size, diagnostic, diagnostic ? sizeof *diagnostic : 0))
        return TLV_ERR_INVALID_ARG;
    query_diag_init(diagnostic);
    if (!image) return TLV_ERR_NULL_ARG;
    if (size < sizeof *header)
        return query_error(diagnostic, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "complete image header");
    memcpy(header, image, sizeof *header);
    if (header->magic != QUERY_MAGIC || header->version != QUERY_IMAGE_VERSION)
        return query_error(diagnostic, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_IMAGE_VERSION, 0,
                           0, "same-release native-endian Query image");
    if (!header->count || header->count > (UINT32_MAX - sizeof *header) / sizeof(query_node_t))
        return TLV_ERR_INVALID_ARG;
    size_t offset = sizeof *header + (size_t)header->count * sizeof(query_node_t);
    if (header->reserved != size || header->text_offset != offset || offset >= size ||
        !header->text_size || header->text_size >= size - offset ||
        header->payload_size != size - offset - header->text_size - 1 ||
        ((const char*)image)[offset + header->text_size] != 0)
        return query_error(diagnostic, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "bounded image text and payload");
    return TLV_OK;
}

tlv_result_t tlv_query_program_load_scratch(const void* image, size_t size,
                                            const tlv_query_compile_options_t* options,
                                            size_t* bytes, size_t* alignment,
                                            tlv_query_diagnostic_t* diagnostic) {
    if (!bytes || !alignment) return TLV_ERR_NULL_ARG;
    if (image_overlap(image, size, bytes, sizeof *bytes) ||
        image_overlap(image, size, alignment, sizeof *alignment))
        return TLV_ERR_INVALID_ARG;
    tlv_query_program_t header;
    tlv_result_t rc = image_header(image, size, &header, diagnostic);
    if (rc != TLV_OK) return rc;
    size_t compile_bytes, compile_alignment;
    rc = tlv_query_compile_scratch((const char*)image + header.text_offset, header.text_size,
                                   options, &compile_bytes, &compile_alignment, diagnostic);
    if (rc != TLV_OK) return rc;
    if (compile_bytes > SIZE_MAX - (sizeof(uint32_t) - 1)) return TLV_ERR_OVERFLOW;
    size_t offset = (compile_bytes + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
    if (size > SIZE_MAX - offset) return TLV_ERR_OVERFLOW;
    *bytes = offset + size;
    *alignment = compile_alignment;
    return TLV_OK;
}

tlv_result_t tlv_query_program_load(const void* image, size_t size,
                                    const tlv_query_compile_options_t* options, void* scratch,
                                    size_t capacity, const tlv_query_program_t** program,
                                    tlv_query_program_info_t* output_info,
                                    tlv_query_diagnostic_t* diagnostic) {
    if (!scratch || !program) return TLV_ERR_NULL_ARG;
    if (image_overlap(image, size, scratch, capacity) ||
        image_overlap(image, size, program, sizeof *program) ||
        image_overlap(image, size, output_info, output_info ? sizeof *output_info : 0) ||
        image_overlap(scratch, capacity, program, sizeof *program) ||
        image_overlap(scratch, capacity, output_info, output_info ? sizeof *output_info : 0) ||
        image_overlap(scratch, capacity, diagnostic, diagnostic ? sizeof *diagnostic : 0) ||
        image_overlap(scratch, capacity, options, options ? sizeof *options : 0))
        return TLV_ERR_INVALID_ARG;
    if (output_info &&
        output_info->struct_size < offsetof(tlv_query_program_info_t, expression_values))
        return TLV_ERR_INVALID_ARG;
    size_t needed, alignment;
    tlv_result_t rc =
        tlv_query_program_load_scratch(image, size, options, &needed, &alignment, diagnostic);
    if (rc != TLV_OK) return rc;
    if ((uintptr_t)image % sizeof(uint32_t) || (uintptr_t)scratch % alignment)
        return query_error(diagnostic, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "aligned image and validation scratch");
    if (capacity < needed) return TLV_ERR_BUFFER_TOO_SHORT;
    size_t offset = needed - size;
    tlv_query_program_t header;
    memcpy(&header, image, sizeof header);
    tlv_query_program_info_t info = {0};
    info.struct_size = sizeof info;
    void* reconstructed = (uint8_t*)scratch + offset;
    rc = tlv_query_compile((const char*)image + header.text_offset, header.text_size, options,
                           scratch, offset, reconstructed, size, &info, diagnostic);
    if (rc != TLV_OK) return rc;
    if (info.program_size != size || memcmp(image, reconstructed, size))
        return query_error(diagnostic, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "canonical validated Query image and matching capabilities");
    *program = (const tlv_query_program_t*)image;
    if (output_info) {
        info.struct_size = output_info->struct_size;
        memcpy(output_info, &info,
               output_info->struct_size < sizeof info ? output_info->struct_size : sizeof info);
    }
    return TLV_OK;
}

tlv_result_t tlv_query_program_format(const tlv_query_program_t* p, char* output, size_t capacity,
                                      size_t* required) {
    if (!p || !required || (!output && capacity)) return TLV_ERR_NULL_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_ARG;
    if (!p->text_size) return TLV_ERR_UNSUPPORTED_TYPE;
    size_t count, length;
    tlv_result_t rc =
        lex(query_text(p), p->text_size, UINT32_MAX, NULL, &count, NULL, NULL, &length);
    if (rc != TLV_OK) return rc;
    if (length == SIZE_MAX) return TLV_ERR_OVERFLOW;
    *required = length + 1;
    if (!output) return TLV_OK;
    if (capacity <= length) return TLV_ERR_BUFFER_TOO_SHORT;
    rc = lex(query_text(p), p->text_size, UINT32_MAX, NULL, &count, NULL, output, &length);
    if (rc == TLV_OK) output[length] = 0;
    return rc;
}
