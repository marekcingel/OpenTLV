// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel
#include "tlv/query/plan.h"
#include "tlv/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "adversarial_plan.h"
#include "../diagnostic_invariant.h"

/* Public API only. Fixed arenas also make this driver usable with an entirely
 * MSan-instrumented C runtime, without an uninstrumented C++ standard library. */
static unsigned    seed, step;
static const char* trace;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "seed=%u step=%u trace=%s line=%d: %s\n", seed, step,                  \
                    trace ? trace : "regression", __LINE__, #x);                                   \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)
typedef union arena {
    uint64_t      align;
    unsigned char bytes[131088];
} arena;
static void* aligned(arena* a) {
    return (void*)(((uintptr_t)a->bytes + 15) & ~(uintptr_t)15);
}
static unsigned random_next(unsigned* state) {
    *state = *state * 1664525u + 1013904223u;
    return *state;
}
static tlv_tree_event_t event(void) {
    static const uint8_t tag = 1, value = 0;
    tlv_tree_event_t     result = {0};
    result.kind = TLV_TREE_ELEMENT;
    result.element.tag = tlv_tag(&tag, 1);
    result.element.value.data = &value;
    result.element.value.size = 1;
    return result;
}
static int initialize(const tlv_query_program_t* p, int retained, arena* memory,
                      tlv_query_exec_t** e, size_t* bytes) {
    size_t alignment;
    CHECK((retained ? tlv_query_eval_size(p, 2, 3, bytes, &alignment)
                    : tlv_query_exec_size(p, 2, bytes, &alignment)) == TLV_OK);
    CHECK(*bytes < sizeof memory->bytes - 16);
    CHECK((retained ? tlv_query_eval_init(p, NULL, aligned(memory), *bytes, 2, 3, 100000, e)
                    : tlv_query_exec_init(p, aligned(memory), *bytes, 2, 3, 100000, e)) == TLV_OK);
    return 0;
}

/* Independent reference state for /01[@len=$n]: B bind, F feed, E malformed
 * END, N null argument, X finish, R reset, S selected, V result, P pull. */
static int sequence(const tlv_query_program_t* p, int retained, const char* operations) {
    arena             memory;
    tlv_query_exec_t* e;
    size_t            bytes;
    int               bound = 0, invalid = 0, finished = 0;
    size_t            nodes = 0, cursor = 0;
    unsigned char     immutable[sizeof static_plan];
    memcpy(immutable, p, p->reserved);
    CHECK(initialize(p, retained, &memory, &e, &bytes) == 0);
    trace = operations;
    for (step = 0; operations[step]; ++step) {
        tlv_tree_event_t       input = event(), output;
        tlv_query_result_t     scalar;
        unsigned char          before[sizeof output], scalar_before[sizeof scalar];
        tlv_result_t           rc, expected = TLV_OK;
        int                    matched = 79;
        int                    was_invalid = invalid;
        tlv_query_diagnostic_t diagnostic = {0};
        /* Struct assignment need not copy padding in transactional snapshots. */
        memset(&output, 0xa5, sizeof output);
        memcpy(before, &output, sizeof output);
        memset(&scalar, 0xa5, sizeof scalar);
        memcpy(scalar_before, &scalar, sizeof scalar);
        switch (operations[step]) {
            case 'B':
                expected = nodes || invalid || finished ? TLV_ERR_INVALID_STATE
                           : bound                      ? TLV_ERR_INVALID_VALUE
                                                        : TLV_OK;
                rc = tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, &diagnostic);
                if (expected == TLV_OK) bound = 1;
                break;
            case 'F':
            case 'E':
                if (operations[step] == 'E') input.kind = TLV_TREE_END;
                if (invalid || finished)
                    expected = TLV_ERR_INVALID_STATE;
                else if (!bound || operations[step] == 'E') {
                    expected = TLV_ERR_INVALID_VALUE;
                    invalid = 1;
                } else if (nodes == 3) {
                    expected = TLV_ERR_LIMIT;
                    invalid = 1;
                } else
                    ++nodes;
                rc = tlv_query_exec_feed(e, &input, &matched, &diagnostic);
                CHECK(matched == (expected == TLV_OK ? !retained : 79));
                break;
            case 'N':
                expected = TLV_ERR_NULL_ARG;
                rc = tlv_query_exec_feed(e, NULL, &matched, &diagnostic);
                CHECK(matched == 79);
                break;
            case 'X':
                if (invalid || !bound) {
                    expected = invalid ? TLV_ERR_INVALID_STATE : TLV_ERR_INVALID_VALUE;
                    invalid = 1;
                } else
                    finished = 1;
                rc = tlv_query_exec_finish(e, &diagnostic);
                break;
            case 'R':
                rc = tlv_query_exec_reset(e);
                bound = invalid = finished = 0;
                nodes = cursor = 0;
                break;
            case 'S':
                expected = invalid ? TLV_ERR_INVALID_STATE : TLV_ERR_INVALID_ARG;
                rc = tlv_query_exec_selected(e, &output);
                CHECK(memcmp(&output, before, sizeof output) == 0);
                break;
            case 'V':
                expected = !finished || invalid ? TLV_ERR_INVALID_STATE
                           : retained           ? TLV_OK
                                                : TLV_ERR_INVALID_ARG;
                rc = tlv_query_exec_result(e, &scalar);
                if (expected == TLV_OK)
                    CHECK(scalar.kind == TLV_QUERY_RESULT_NODES);
                else
                    CHECK(memcmp(&scalar, scalar_before, sizeof scalar) == 0);
                break;
            case 'P':
                expected = !finished || invalid ? TLV_ERR_INVALID_STATE
                           : !retained          ? TLV_ERR_INVALID_ARG
                           : cursor == nodes    ? TLV_END
                                                : TLV_OK;
                rc = tlv_query_result_next(e, &output);
                if (expected == TLV_OK) {
                    ++cursor;
                    CHECK(output.element.tag.data[0] == 1);
                } else
                    CHECK(memcmp(&output, before, sizeof output) == 0);
                break;
            default: CHECK(0); return 1;
        }
        CHECK(rc == expected);
        /* Failed continuations are rejected before initialization; all other
         * diagnostic-producing transitions must describe their result. */
        if ((!was_invalid && strchr("BFEX", operations[step])) || operations[step] == 'N')
            CHECK(test_query_diagnostic_matches(rc, &diagnostic));
        CHECK(memcmp(immutable, p, p->reserved) == 0);
        tlv_query_exec_info_t info = {0};
        info.struct_size = sizeof info;
        CHECK(tlv_query_exec_info(e, &info) == TLV_OK);
        CHECK(info.invalid == invalid && info.finished == finished);
    }
    trace = NULL;
    return 0;
}

static int aliases(const tlv_query_program_t* p) {
    arena          memory, saved;
    unsigned char* base = aligned(&memory);
    size_t         bytes, alignment;
    CHECK(tlv_query_eval_size(p, 2, 3, &bytes, &alignment) == TLV_OK);
    /* Exact alias, both directions, prefix/suffix, one byte, adjacency. All
     * intervals remain readable inside the arena, including invalid alignment. */
    const ptrdiff_t offsets[] = {0,
                                 1,
                                 -1,
                                 16,
                                 -16,
                                 (ptrdiff_t)p->reserved - 1,
                                 (ptrdiff_t)p->reserved,
                                 -(ptrdiff_t)bytes + 1,
                                 -(ptrdiff_t)bytes};
    for (unsigned i = 0; i < sizeof offsets / sizeof *offsets; ++i) {
        memset(&memory, 0xa5, sizeof memory);
        tlv_query_program_t* image = (tlv_query_program_t*)(base + 32768);
        memcpy(image, p, p->reserved);
        unsigned char* storage = (unsigned char*)image + offsets[i];
        memcpy(&saved, &memory, sizeof memory);
        tlv_query_exec_t* output = NULL;
        int               overlap =
            offsets[i] >= 0 ? (size_t)offsets[i] < p->reserved : (size_t)-offsets[i] < bytes;
        int          bad = overlap || (uintptr_t)storage % alignment;
        tlv_result_t rc = tlv_query_eval_init(image, NULL, storage, bytes, 2, 3, 100000, &output);
        CHECK(rc == (bad ? TLV_ERR_INVALID_ARG : TLV_OK));
        if (bad) CHECK(output == NULL && memcmp(&saved, &memory, sizeof memory) == 0);
    }
    for (int retained = 0; retained < 2; ++retained) {
        tlv_query_exec_t* e;
        CHECK(initialize(p, retained, &memory, &e, &bytes) == 0);
        CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, NULL) == TLV_OK);
        memcpy(&saved, &memory, sizeof memory);
        tlv_tree_event_t input = event();
        int              matched = 87;
        input.element.tag.data = (const uint8_t*)e;
        CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_ERR_INVALID_ARG);
        CHECK(matched == 87 && memcmp(&saved, &memory, sizeof memory) == 0);
        input = event();
        input.element.value.data = (const uint8_t*)e + bytes - 1;
        CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_ERR_INVALID_ARG);
        CHECK(memcmp(&saved, &memory, sizeof memory) == 0);
        input = event();
        CHECK(tlv_query_exec_feed(e, &input, (int*)e, NULL) == TLV_ERR_INVALID_ARG);
        CHECK(tlv_query_exec_feed(e, &input, &matched, (tlv_query_diagnostic_t*)e) ==
              TLV_ERR_INVALID_ARG);
        CHECK(memcmp(&saved, &memory, sizeof memory) == 0);
        /* Tag and Value may share immutable program bytes. */
        input.element.tag.data = (const uint8_t*)p + p->text_offset + 1;
        input.element.value.data = input.element.tag.data;
        CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
        CHECK(tlv_query_exec_finish(e, NULL) == TLV_OK);
        CHECK(tlv_query_exec_result(e, (tlv_query_result_t*)e) == TLV_ERR_INVALID_ARG);
        CHECK(tlv_query_exec_reset(e) == TLV_OK);
        tlv_query_exec_t* sentinel = e;
        CHECK((retained ? tlv_query_eval_init(p, NULL, aligned(&memory), bytes - 1, 2, 3, 100000,
                                              &sentinel)
                        : tlv_query_exec_init(p, aligned(&memory), bytes - 1, 2, 3, 100000,
                                              &sentinel)) == TLV_ERR_BUFFER_TOO_SHORT);
        CHECK(sentinel == e);
    }
    memcpy(base, p, p->reserved);
    memcpy(&saved, &memory, sizeof memory);
    CHECK(tlv_query_plan_open(base, p->reserved, (const tlv_query_program_t**)base, NULL) ==
          TLV_ERR_INVALID_ARG);
    CHECK(tlv_query_plan_open(base, p->reserved, &p, (tlv_query_diagnostic_t*)base) ==
          TLV_ERR_INVALID_ARG);
    CHECK(memcmp(&saved, &memory, sizeof memory) == 0);
    /* Even a finalized nonmatch retains its borrowed Value until reset. */
    tlv_query_exec_t* e;
    CHECK(initialize(p, 1, &memory, &e, &bytes) == 0);
    CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, NULL) == TLV_OK);
    uint64_t         value[32] = {0};
    tlv_tree_event_t input = event();
    input.element.value.data = (const uint8_t*)value;
    input.element.value.size = sizeof value;
    int matched;
    CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
    CHECK(tlv_query_exec_finish(e, NULL) == TLV_OK);
    CHECK(tlv_query_exec_result(e, (tlv_query_result_t*)value) == TLV_ERR_INVALID_ARG);
    CHECK(value[0] == 0);
    /* Init output and environment descriptors may not be hidden in workspace. */
    memcpy(&saved, &memory, sizeof memory);
    CHECK(tlv_query_eval_init(p, NULL, e, bytes, 2, 3, 100000, (tlv_query_exec_t**)e) ==
          TLV_ERR_INVALID_ARG);
    CHECK(tlv_query_exec_init(p, e, bytes, 2, 3, 100000, (tlv_query_exec_t**)e) ==
          TLV_ERR_INVALID_ARG);
    CHECK(memcmp(&saved, &memory, sizeof memory) == 0);
    memset(aligned(&memory), 0, bytes);
    memcpy(&saved, &memory, sizeof memory);
    CHECK(tlv_query_eval_init(p, aligned(&memory), aligned(&memory), bytes, 2, 3, 100000, &e) ==
          TLV_ERR_INVALID_ARG);
    CHECK(memcmp(&saved, &memory, sizeof memory) == 0);
    return 0;
}

static int diagnostics(const tlv_query_program_t* p) {
    arena         memory;
    unsigned char reference[8][sizeof(tlv_query_diagnostic_t)];
    for (int retained = 0; retained < 2; ++retained) {
        tlv_query_exec_t* e;
        size_t            bytes;
        CHECK(initialize(p, retained, &memory, &e, &bytes) == 0);
        for (unsigned malformed = 0; malformed < 8; ++malformed) {
            CHECK(tlv_query_exec_reset(e) == TLV_OK);
            CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, NULL) ==
                  TLV_OK);
            tlv_tree_event_t input = event();
            int              matched = 79;
            if (malformed >= 6) {
                input.kind = TLV_TREE_BEGIN;
                CHECK(tlv_query_exec_feed(e, &input, &matched, NULL) == TLV_OK);
                input.kind = TLV_TREE_END;
            }
            switch (malformed) {
                case 0: input.skipped = 1; break;
                case 1: input.kind = TLV_TREE_END; break;
                case 2: input.kind = (tlv_tree_event_kind_t)99; break;
                case 3: input.depth = 1; break;
                case 4: input.element.tag.data = NULL; break;
                case 5: input.element.value.data = NULL; break;
                case 6: input.skipped = 1; break;
                case 7: input.depth = 1; break;
            }
            input.source.data = event().element.value.data;
            input.source.size = 1;
            input.offset = 17;
            matched = 79;
            tlv_query_diagnostic_t d;
            int                    bad_span = malformed == 4 || malformed == 5;
            CHECK(tlv_query_exec_feed(e, &input, &matched, &d) ==
                  (bad_span ? TLV_ERR_INVALID_ARG : TLV_ERR_INVALID_VALUE));
            CHECK(matched == 79 && d.kind == TLV_QUERY_ERROR_EVENTS);
            CHECK(d.expected &&
                  !strcmp(d.expected, bad_span
                                          ? "valid event span arguments"
                                          : "balanced complete canonical events without pruning"));
            CHECK((d.diagnostic.location.domain == TLV_LOCATION_INPUT &&
                   d.diagnostic.location.kind != TLV_LOCATION_UNKNOWN) &&
                  d.diagnostic.location.begin == 17 && !d.limit);
            if (!retained)
                memcpy(reference[malformed], &d, sizeof d);
            else
                CHECK(!memcmp(reference[malformed], &d, sizeof d));
            unsigned char original[sizeof d];
            memcpy(original, &d, sizeof d);
            CHECK(tlv_query_exec_finish(e, &d) == TLV_ERR_INVALID_STATE);
            CHECK(!memcmp(original, &d, sizeof d));
        }
        /* LIMIT detail survives rejected feed/finish continuations until reset. */
        CHECK(tlv_query_exec_reset(e) == TLV_OK);
        CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, NULL) == TLV_OK);
        tlv_tree_event_t       input = event();
        tlv_query_diagnostic_t d;
        int                    matched = 79;
        for (int i = 0; i < 3; ++i) CHECK(tlv_query_exec_feed(e, &input, &matched, &d) == TLV_OK);
        CHECK(tlv_query_exec_feed(e, &input, &matched, &d) == TLV_ERR_LIMIT);
        CHECK(d.kind == TLV_QUERY_ERROR_LIMIT && d.configured == 3);
        CHECK(d.limit && !strcmp(d.limit, retained ? "candidates" : "elements"));
        unsigned char original[sizeof d];
        memcpy(original, &d, sizeof d);
        CHECK(tlv_query_exec_finish(e, &d) == TLV_ERR_INVALID_STATE);
        CHECK(!memcmp(original, &d, sizeof d));
        CHECK(tlv_query_exec_feed(e, &input, &matched, &d) == TLV_ERR_INVALID_STATE);
        CHECK(!memcmp(original, &d, sizeof d));
        CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, &d) ==
              TLV_ERR_INVALID_STATE);
        CHECK(!memcmp(original, &d, sizeof d));
        CHECK(tlv_query_exec_context(e, 0) == TLV_ERR_INVALID_STATE);
        CHECK(tlv_query_exec_pruning(e, 1) == TLV_ERR_INVALID_STATE);
        CHECK(!memcmp(original, &d, sizeof d));
        CHECK(tlv_query_exec_reset(e) == TLV_OK);
        CHECK(tlv_query_exec_bind(e, "n", TLV_QUERY_RESULT_INTEGER, 1, NULL, 0, NULL) == TLV_OK);
        CHECK(tlv_query_exec_feed(e, &input, &matched, &d) == TLV_OK);
        CHECK(tlv_query_exec_finish(e, &d) == TLV_OK && d.kind == TLV_QUERY_ERROR_NONE);
    }
    return 0;
}

#include "adversarial_callbacks.h"
#include "adversarial_document_reinit.h"
#include "adversarial_native_test.h"

int main(int argc, char** argv) {
#if OPENTLV_QUERY_FRONTEND
    if (argc == 2 && !strcmp(argv[1], "--export")) return export_plans();
    if (argc == 2 && !strcmp(argv[1], "--retained-scale")) return retained_scale();
#endif
    const tlv_query_program_t* p = NULL;
    CHECK(tlv_query_plan_open(&static_plan, static_plan.header.reserved, &p, NULL) == TLV_OK);
    CHECK(diagnostics(p) == 0);
    if (argc == 3 && !strcmp(argv[1], "--sequence")) {
        CHECK(sequence(p, 0, argv[2]) == 0);
        CHECK(sequence(p, 1, argv[2]) == 0);
        return 0;
    }
    const char* regressions[] = {"XX",     "BFXF", "BFB",   "BEVXF",        "BERBFXVP",
                                 "BFXRBF", "SS",   "BXVRV", "BFFFFVXRBFXPP"};
    for (int retained = 0; retained < 2; ++retained) {
        for (unsigned i = 0; i < sizeof regressions / sizeof *regressions; ++i)
            CHECK(sequence(p, retained, regressions[i]) == 0);
        for (seed = 1; seed <= 256; ++seed) {
            unsigned rng = seed;
            char     operations[129];
            for (size_t i = 0; i < sizeof operations - 1; ++i)
                operations[i] = "BFFEXRNSVP"[random_next(&rng) % 10];
            operations[sizeof operations - 1] = 0;
            CHECK(sequence(p, retained, operations) == 0);
        }
    }
    CHECK(aliases(p) == 0);
    CHECK(native_profiles() == 0);
#if OPENTLV_QUERY_FRONTEND
    CHECK(loader_aliases() == 0);
    CHECK(callbacks() == 0);
    CHECK(raw_reinitialization() == 0);
#if OPENTLV_READER
    CHECK(reader_aliases() == 0);
#endif
#if OPENTLV_DOCUMENT && OPENTLV_READER && OPENTLV_WRITER
    CHECK(documents() == 0);
    CHECK(document_format_reinitialization() == 0);
#endif
#endif
    puts("adversarial: 512 seeded sequences, lifecycle regressions and storage matrix passed");
    return 0;
}
