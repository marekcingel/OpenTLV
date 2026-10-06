// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#ifndef OPENTLV_QUERY_FRONTEND_INTERNAL_H
#define OPENTLV_QUERY_FRONTEND_INTERNAL_H
#include "program_internal.h"

enum query_token_kind {
    T_WORD,
    T_BYTES,
    T_STRING,
    T_META,
    T_VARIABLE,
    T_SLASH,
    T_DESC,
    T_OPEN,
    T_CLOSE,
    T_POPEN,
    T_PCLOSE,
    T_COMMA,
    T_UNION,
    T_INTERSECT,
    T_EXCEPT,
    T_EQ,
    T_NE,
    T_LT,
    T_LE,
    T_GT,
    T_GE,
    T_AND,
    T_OR,
    T_DOT,
    T_DDOT,
    T_AXIS,
    T_END
};

static inline const char* query_axis_name(unsigned axis) {
    static const char* names[] = {"child",
                                  "self",
                                  "descendant",
                                  "ancestor",
                                  "descendant-or-self",
                                  "parent",
                                  "ancestor-or-self",
                                  "following-sibling",
                                  "preceding-sibling",
                                  "following",
                                  "preceding"};
    return axis <= A_PRECEDE ? names[axis] : NULL;
}

typedef struct query_token {
    uint32_t kind, begin, end;
} query_token_t;

typedef struct query_operator {
    uint32_t kind, token, base, function;
} query_operator_t;

static inline const char* query_function_name(unsigned function) {
    static const char* names[] = {"value",       "len",    "not",      "starts-with", "ends-with",
                                  "contains",    "substr", "tag-mask", "tag-range",   "count",
                                  "exists",      "empty",  "position", "last",        "num",
                                  "bcd",         "text",   "date",     "tag",         "class",
                                  "constructed", "number", "name"};
    return function < F_UNKNOWN ? names[function] : NULL;
}

static inline int query_word(const char* text, size_t begin, size_t end, const char* word) {
    size_t n = strlen(word);
    return end - begin == n && !memcmp(text + begin, word, n);
}

static inline unsigned query_function_kind(const char* text, const query_node_t* n) {
    for (unsigned i = 0; i < F_UNKNOWN; ++i)
        if (strlen(query_function_name(i)) == n->end - n->begin &&
            !memcmp(text + n->begin, query_function_name(i), n->end - n->begin))
            return i;
    return F_UNKNOWN;
}

#endif
