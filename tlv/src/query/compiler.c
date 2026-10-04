// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "program_internal.h"
#include "../utf8_internal.h"
#include <limits.h>

static int whitespace(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
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
                kind = c == '@' ? T_META : T_VARIABLE;
                while (pos < size && word_char((unsigned char)text[pos])) ++pos;
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
                (format_operator(kind) || format_operator(previous) || previous == T_COMMA)) {
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
        if (!v->name || !v->name[0] || v->type < TLV_QUERY_RESULT_INTEGER ||
            v->type > TLV_QUERY_RESULT_STRING)
            return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                               "named integer, bytes or string variable");
        for (size_t j = 0; v->name[j]; ++j)
            if (!word_char((unsigned char)v->name[j]))
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                                   "variable identifier");
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(v->name, o->variables[j].name))
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, 0, 0,
                                   "unique variable declaration");
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
    *bytes = (count + 1) * scratch_unit();
    *alignment = sizeof(uint32_t);
    return TLV_OK;
}

static unsigned precedence(unsigned kind) {
    switch (kind) {
        case T_COMMA: return 1;
        case T_UNION:
        case T_INTERSECT:
        case T_EXCEPT: return 2;
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
            } else if (expected || vn != op.base + 1)
                goto syntax;
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
            if (query_word(text, t.begin, t.end, "self"))
                axis = A_SELF;
            else if (query_word(text, t.begin, t.end, "descendant"))
                axis = A_DESC;
            else if (query_word(text, t.begin, t.end, "ancestor"))
                axis = A_ANCESTOR;
            else if (query_word(text, t.begin, t.end, "descendant-or-self") ||
                     query_word(text, t.begin, t.end, "parent") ||
                     query_word(text, t.begin, t.end, "ancestor-or-self") ||
                     query_word(text, t.begin, t.end, "following-sibling") ||
                     query_word(text, t.begin, t.end, "preceding-sibling") ||
                     query_word(text, t.begin, t.end, "following") ||
                     query_word(text, t.begin, t.end, "preceding"))
                axis = A_OTHER;
            else if (!query_word(text, t.begin, t.end, "child"))
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
            axis = A_OTHER;
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
        if (axis == A_DESC && !predicates) {
            if (after_path && on && ops[on - 1].kind == T_SLASH)
                ops[on - 1].kind = T_DESC;
            else if (!after_path) {
                values[vn++] = add_node(nodes, used, Q_ROOT, QUERY_NONE, QUERY_NONE, t);
                nodes[values[vn - 1]].anchor = 1;
                query_operator_t prefix = {T_DESC, (uint32_t)i, 0, QUERY_NONE};
                ops[on++] = prefix;
                after_path = 1;
            }
            axis = A_CHILD;
        }
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

static tlv_result_t analyze(const char* text, query_node_t* nodes, size_t count,
                            const tlv_query_compile_options_t* options, tlv_query_level_t* level,
                            tlv_query_diagnostic_t* d) {
    *level = TLV_QUERY_S0;
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op >= Q_EQ && n->op <= Q_GE) {
            uint32_t sides[2] = {n->left, n->right};
            for (unsigned j = 0; j < 2; ++j) {
                query_node_t* operand = &nodes[sides[j]];
                if (operand->op == Q_TEST && decimal(text, operand)) operand->op = Q_LITERAL;
            }
        }
        if (n->op == Q_FILTER) {
            query_node_t* predicate = &nodes[n->right];
            if (predicate->op == Q_TEST && predicate->axis == A_CHILD && decimal(text, predicate)) {
                predicate->op = Q_LITERAL;
                predicate->anchor = 2; /* Positional predicate, reserved for deferred execution. */
            }
        }
    }
    /* Propagate scalar context through function argument lists before resolving
       numeric-looking tokens. Path tests retain their raw-byte interpretation. */
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op != Q_CALL) continue;
        uint32_t args[3], cursor = n->left;
        size_t arity = 0;
        while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
            if (arity == 2)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "at most three arguments");
            args[arity++] = nodes[cursor].right;
            cursor = nodes[cursor].left;
        }
        if (cursor != QUERY_NONE) args[arity++] = cursor;
        for (size_t j = 0; j < arity / 2; ++j) {
            uint32_t temp = args[j];
            args[j] = args[arity - 1 - j];
            args[arity - 1 - j] = temp;
        }
        if (query_word(text, n->begin, n->end, "substr")) {
            if (arity != 2 && arity != 3)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "substr(bytes, start[, length])");
            for (size_t j = 1; j < arity; ++j) {
                query_node_t* arg = &nodes[args[j]];
                if (arg->op == Q_TEST && decimal(text, arg)) arg->op = Q_LITERAL;
            }
        } else if (query_word(text, n->begin, n->end, "value")) {
            if (arity)
                return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                   n->begin, n->end, "F1 value() without node-sequence argument");
        } else if (query_word(text, n->begin, n->end, "len")) {
            if (arity > 1)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "len([bytes])");
        } else if (query_word(text, n->begin, n->end, "not")) {
            if (arity != 1)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "not(boolean)");
        } else if (query_word(text, n->begin, n->end, "starts-with") ||
                   query_word(text, n->begin, n->end, "ends-with") ||
                   query_word(text, n->begin, n->end, "contains") ||
                   query_word(text, n->begin, n->end, "tag-mask") ||
                   query_word(text, n->begin, n->end, "tag-range")) {
            if (arity != 2)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "two byte arguments");
            if (query_word(text, n->begin, n->end, "contains") && nodes[args[1]].op != Q_BYTES)
                return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                   n->begin, n->end, "constant byte pattern for F1 contains");
            if (query_word(text, n->begin, n->end, "tag-mask") ||
                query_word(text, n->begin, n->end, "tag-range")) {
                query_node_t* a = &nodes[args[0]];
                query_node_t* b = &nodes[args[1]];
                if (a->op != Q_BYTES || b->op != Q_BYTES)
                    return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                       n->begin, n->end, "constant tag-test byte arguments");
                size_t left = (a->end - a->begin - 3) / 2, right = (b->end - b->begin - 3) / 2;
                if (query_word(text, n->begin, n->end, "tag-mask") && left != right)
                    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                       n->end, "equal pattern and mask widths");
                if (query_word(text, n->begin, n->end, "tag-range")) {
                    int order = left < right ? -1 : left > right;
                    size_t limit = left < right ? left : right;
                    for (size_t j = 0; j < limit; ++j) {
                        size_t x = a->begin + 2 + j * 2, y = b->begin + 2 + j * 2;
                        int low = query_hex((unsigned char)text[x]) * 16 +
                                  query_hex((unsigned char)text[x + 1]);
                        int high = query_hex((unsigned char)text[y]) * 16 +
                                   query_hex((unsigned char)text[y + 1]);
                        if (low != high) {
                            order = low < high ? -1 : 1;
                            break;
                        }
                    }
                    if (order > 0)
                        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                           n->end, "ordered range bounds");
                }
            }
        }
    }
    int deferred = 0, ordered_union = 0, document = 0, candidates = 0;
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op == Q_UNION) ordered_union = 1;
        if (n->op == Q_LITERAL && n->anchor == 2) deferred = 1;
        if (n->op == Q_TEST && n->scalar && n->axis == A_CHILD) deferred = 1;
        if (n->op == Q_TEST && (n->axis == A_OTHER || (n->axis == A_ANCESTOR && !n->scalar)))
            document = 1;
        if (n->op == Q_CALL && query_word(text, n->begin, n->end, "last")) candidates = 1;
        if (n->op == Q_CALL && (query_word(text, n->begin, n->end, "count") ||
                                query_word(text, n->begin, n->end, "exists") ||
                                query_word(text, n->begin, n->end, "empty")))
            deferred = 1;
    }
    *level = document                                    ? TLV_QUERY_D
             : candidates || (deferred && ordered_union) ? TLV_QUERY_S2
             : deferred                                  ? TLV_QUERY_S1
                                                         : TLV_QUERY_S0;
    /* Every recognized later-phase operation gets an explicit capability error.
       Grammar parsing completes before this semantic pass. */
    for (size_t i = 0; i < count; ++i) {
        query_node_t* n = &nodes[i];
        if (n->op == Q_TEST) {
            int wildcard = n->end - n->begin == 1 && text[n->begin] == '*';
            if (!wildcard) {
                if (memchr(text + n->begin, ':', n->end - n->begin)) goto unsupported;
                if ((n->end - n->begin) % 2)
                    return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                       n->end, "whole-byte hexadecimal tag test");
                for (size_t j = n->begin; j < n->end; j += 2) {
                    if (text[j] == '?' && text[j + 1] == '?') continue;
                    if (query_hex((unsigned char)text[j]) < 0 ||
                        query_hex((unsigned char)text[j + 1]) < 0)
                        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                           n->end, "hexadecimal bytes or whole-byte ?? wildcard");
                }
            }
            if (n->axis == A_OTHER || n->axis == A_DESC || (n->axis == A_ANCESTOR && !n->scalar) ||
                (n->axis == A_CHILD && n->scalar))
                goto unsupported;
        }
        if (n->op == Q_STRING) goto unsupported;
        if (n->op == Q_META) {
            if (!query_word(text, n->begin, n->end, "@len") &&
                !query_word(text, n->begin, n->end, "@offset") &&
                !query_word(text, n->begin, n->end, "@hlen") &&
                !query_word(text, n->begin, n->end, "@depth") &&
                !query_word(text, n->begin, n->end, "@index"))
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_SYNTAX, n->begin, n->end,
                                   "known metadata property");
        }
        if (n->op == Q_LITERAL) {
            if (n->anchor == 2)
                return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                   n->begin, n->end, "positional predicate execution");
            int negative = text[n->begin] == '-';
            uint64_t maximum = (uint64_t)INT64_MAX + (unsigned)negative;
            uint64_t value = 0;
            for (size_t j = n->begin + (unsigned)negative; j < n->end; ++j) {
                unsigned digit = (unsigned)(text[j] - '0');
                if (digit > 9 || value > (maximum - digit) / 10)
                    return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_SYNTAX, n->begin,
                                       n->end, "signed 64-bit integer");
                value = value * 10 + digit;
            }
        }
        if (n->op == Q_FILTER) {
            /* A direct numeric predicate is position-based, not a raw tag. */
            query_node_t* rhs = &nodes[n->right];
            if (nodes[n->left].op == Q_TEST && nodes[n->left].axis == A_ANCESTOR) goto unsupported;
            if (rhs->op == Q_TEST && rhs->axis == A_CHILD && decimal(text, rhs)) goto unsupported;
        }
        if (n->op == Q_CALL) {
            static const char* supported[] = {"value",       "len",       "not",
                                              "starts-with", "ends-with", "contains",
                                              "substr",      "tag-range", "tag-mask"};
            int found = 0;
            for (size_t j = 0; j < sizeof supported / sizeof supported[0]; ++j)
                if (query_word(text, n->begin, n->end, supported[j])) found = 1;
            if (!found) goto unsupported;
        }
        n->type = V_NODE;
        if (n->op == Q_VARIABLE) {
            int found = 0;
            for (size_t j = 0; j < options->variable_count; ++j) {
                const tlv_query_variable_t* v = &options->variables[j];
                if (query_word(text, n->begin + 1, n->end, v->name)) {
                    n->type = (uint32_t)v->type;
                    found = 1;
                    break;
                }
            }
            if (!found)
                return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_BINDING, n->begin,
                                   n->end, "declared typed variable");
        }
        if (n->op == Q_META || n->op == Q_LITERAL) n->type = V_NUMBER;
        if (n->op == Q_BYTES) n->type = V_BYTES;
        if ((n->op >= Q_EQ && n->op <= Q_OR)) n->type = V_BOOL;
        if (n->op == Q_CALL) {
            if (query_word(text, n->begin, n->end, "value") ||
                query_word(text, n->begin, n->end, "substr"))
                n->type = V_BYTES;
            else if (query_word(text, n->begin, n->end, "len"))
                n->type = V_NUMBER;
            else if (!query_word(text, n->begin, n->end, "tag-range") &&
                     !query_word(text, n->begin, n->end, "tag-mask"))
                n->type = V_BOOL;
            uint32_t args[3], cursor = n->left;
            size_t arity = 0;
            while (cursor != QUERY_NONE && nodes[cursor].op == Q_ARGS) {
                args[arity++] = nodes[cursor].right;
                cursor = nodes[cursor].left;
            }
            if (cursor != QUERY_NONE) args[arity++] = cursor;
            for (size_t j = 0; j < arity / 2; ++j) {
                uint32_t temp = args[j];
                args[j] = args[arity - 1 - j];
                args[arity - 1 - j] = temp;
            }
            if (query_word(text, n->begin, n->end, "not")) {
                if (nodes[args[0]].type != V_BOOL && nodes[args[0]].type != V_NODE) goto types;
            } else if (query_word(text, n->begin, n->end, "substr")) {
                if (nodes[args[0]].type != V_BYTES || nodes[args[1]].type != V_NUMBER ||
                    (arity == 3 && nodes[args[2]].type != V_NUMBER))
                    goto types;
            } else if (query_word(text, n->begin, n->end, "len")) {
                if (arity && nodes[args[0]].type != V_BYTES) goto types;
            } else if (arity && (nodes[args[0]].type != V_BYTES || nodes[args[1]].type != V_BYTES))
                goto types;
        }
        if ((n->op == Q_CHILD || n->op == Q_DESC || n->op == Q_UNION || n->op == Q_INTERSECT ||
             n->op == Q_EXCEPT) &&
            (nodes[n->left].type != V_NODE || nodes[n->right].type != V_NODE))
            goto types;
        if (n->op == Q_FILTER &&
            (nodes[n->left].type != V_NODE ||
             (nodes[n->right].type != V_BOOL && nodes[n->right].type != V_NODE)))
            goto types;
        if (n->op >= Q_EQ && n->op <= Q_GE &&
            (nodes[n->left].type != nodes[n->right].type ||
             (nodes[n->left].type != V_BYTES && nodes[n->left].type != V_NUMBER &&
              nodes[n->left].type != V_STRING)))
            goto types;
        if ((n->op == Q_AND || n->op == Q_OR) &&
            ((nodes[n->left].type != V_BOOL && nodes[n->left].type != V_NODE) ||
             (nodes[n->right].type != V_BOOL && nodes[n->right].type != V_NODE)))
            goto types;
        continue;
    types:
        return query_error(d, TLV_ERR_INVALID_ARG, TLV_QUERY_ERROR_CAPABILITY, n->begin, n->end,
                           "compatible expression types");
    unsupported:
        return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY, n->begin,
                           n->end, "feature supported by F1 S0 execution");
    }
    return TLV_OK;
}

tlv_result_t tlv_query_compile(const char* text, size_t size,
                               const tlv_query_compile_options_t* options, void* scratch,
                               size_t scratch_size, void* storage, size_t capacity,
                               tlv_query_program_info_t* info, tlv_query_diagnostic_t* d) {
    query_diag_init(d);
    if (!text || !scratch || !info || (!storage && capacity)) return TLV_ERR_NULL_ARG;
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
    size_t count = needed / scratch_unit();
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
                    return query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY,
                                       step->begin, step->end, "nested absolute path");
                if (step->predicate_guard != QUERY_NONE || step->path_guard != QUERY_NONE) continue;
                int node_test =
                    step->op == Q_TEST || step->op == Q_SELF ||
                    (step->op == Q_ROOT && step->anchor) ||
                    (step->op == Q_CALL && (query_word(text, step->begin, step->end, "tag-mask") ||
                                            query_word(text, step->begin, step->end, "tag-range")));
                if (!node_test) continue;
                if (step->op == Q_ROOT) step->op = Q_SELF;
                unsigned kind = n->op;
                if (n->op == Q_CHILD && (step->op == Q_SELF || step->axis == A_SELF)) kind = Q_SELF;
                step->path_guard = n->left;
                step->path_kind = kind;
                step->anchor = 0;
            }
        }
    }
    tlv_query_level_t level;
    rc = analyze(text, nodes, used, &o, &level, d);
    if (rc == TLV_OK && nodes[root].type != V_NODE)
        rc = query_error(d, TLV_ERR_UNSUPPORTED_TYPE, TLV_QUERY_ERROR_CAPABILITY, nodes[root].begin,
                         nodes[root].end, "F1 node-sequence result");
    if (size > SIZE_MAX - sizeof(tlv_query_program_t) - 1 ||
        used > (SIZE_MAX - sizeof(tlv_query_program_t) - size - 1) / sizeof(query_node_t))
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable program size");
    size_t text_offset = sizeof(tlv_query_program_t) + used * sizeof(query_node_t);
    size_t total = text_offset + size + 1;
    if (total > UINT32_MAX)
        return query_error(d, TLV_ERR_OVERFLOW, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "representable program size");
    tlv_query_program_info_t result = {total,  sizeof(uint32_t),
                                       needed, alignment,
                                       used,   1,
                                       level,  (tlv_query_result_kind_t)nodes[root].type,
                                       used,   used,
                                       0};
    for (size_t i = 0; i < used; ++i)
        if (nodes[i].op == Q_VARIABLE) ++result.variable_slots;
    if (rc != TLV_OK) {
        *info = result;
        return rc;
    }
    *info = result;
    if (!storage) return TLV_OK;
    if (capacity < total)
        return query_error(d, TLV_ERR_BUFFER_TOO_SHORT, TLV_QUERY_ERROR_STORAGE, 0, 0,
                           "sufficient program capacity");
    tlv_query_program_t p = {QUERY_MAGIC,     1,
                             (uint32_t)used,  root,
                             (uint32_t)size,  (uint32_t)text_offset,
                             (uint32_t)level, (uint32_t)total};
    memcpy(storage, &p, sizeof p);
    memcpy((uint8_t*)storage + sizeof p, nodes, used * sizeof *nodes);
    memcpy((uint8_t*)storage + text_offset, text, size);
    ((char*)storage)[text_offset + size] = 0;
    return TLV_OK;
}

tlv_result_t tlv_query_program_format(const tlv_query_program_t* p, char* output, size_t capacity,
                                      size_t* required) {
    if (!p || !required || (!output && capacity)) return TLV_ERR_NULL_ARG;
    if (!query_program_valid(p)) return TLV_ERR_INVALID_ARG;
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
