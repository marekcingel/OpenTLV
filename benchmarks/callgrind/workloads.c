// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include "tlv/builtins/asn1/ber.h"
#include "tlv/document/document.h"
#include "tlv/query/program.h"
#include "tlv/reader/reader.h"
#include "tlv/writer/writer.h"

#include "schema_workloads.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(OPENTLV_CALLGRIND_INSTRUMENTATION)
#include <valgrind/callgrind.h>
#endif

enum { ENTRY_COUNT = 256, VALUE_SIZE = 16, ENTRY_SIZE = 18, WIRE_SIZE = 4608 };

typedef struct {
    uint8_t                wire[WIRE_SIZE];
    uint8_t                output[WIRE_SIZE];
    tlv_document_options_t document_options;
    void*                  query_program;
    void*                  query_workspace;
    size_t                 query_workspace_size;
    uint64_t               all_checksum;
    uint64_t               query_checksum;
    uint64_t               writer_checksum;
    schema_workloads_t     schema;
} workload_data_t;

typedef int (*workload_fn)(workload_data_t*, uint64_t*);

/* An independently assembled input avoids hiding a Writer regression in setup. */
static void prepare_input(workload_data_t* data) {
    size_t i;
    memset(data, 0, sizeof *data);
    for (i = 0; i < ENTRY_COUNT; ++i) {
        size_t   j;
        uint8_t* entry = data->wire + i * ENTRY_SIZE;
        uint64_t checksum;
        entry[0] = (uint8_t)(0x80 + i % 16);
        entry[1] = VALUE_SIZE;
        for (j = 0; j < VALUE_SIZE; ++j) entry[2 + j] = (uint8_t)(i + j);
        checksum = entry[0] + VALUE_SIZE + entry[2] + entry[ENTRY_SIZE - 1];
        data->all_checksum += checksum;
        if (entry[0] == 0x80) data->query_checksum += checksum;
    }
    data->writer_checksum = WIRE_SIZE + data->wire[0] + data->wire[WIRE_SIZE - 1];
}

static int element_checksum(tlv_tag_t tag, const uint8_t* value, size_t size, uint64_t* checksum) {
    if (tag.size != 1 || tag.data == NULL || value == NULL || size != VALUE_SIZE) return 0;
    *checksum += tag.data[0] + size + value[0] + value[size - 1];
    return 1;
}

static int run_reader(workload_data_t* data, uint64_t* checksum) {
    tlv_reader_t  reader;
    tlv_element_t element;
    size_t        count = 0;
    *checksum = 0;
    if (tlv_reader_init(&reader, data->wire, WIRE_SIZE, &tlv_format_ber) != TLV_OK) return 0;
    while (tlv_reader_next(&reader, &element) == TLV_OK) {
        if (!element_checksum(element.tag, element.value.data, (size_t)element.value.size,
                              checksum))
            return 0;
        ++count;
    }
    /* Clean EOF without naming the end status, so the harness builds against any revision. */
    return tlv_reader_at_end(&reader) && count == ENTRY_COUNT && *checksum == data->all_checksum;
}

static int run_writer(workload_data_t* data, uint64_t* checksum) {
    tlv_writer_t writer;
    size_t       i;
    if (tlv_writer_init(&writer, data->output, WIRE_SIZE, &tlv_format_ber) != TLV_OK) return 0;
    for (i = 0; i < ENTRY_COUNT; ++i) {
        const uint8_t* entry = data->wire + i * ENTRY_SIZE;
        if (tlv_writer_write(&writer, tlv_tag(entry, 1), entry + 2, VALUE_SIZE) != TLV_OK) return 0;
    }
    *checksum = tlv_writer_size(&writer) + data->output[0] + data->output[WIRE_SIZE - 1];
    return tlv_writer_size(&writer) == WIRE_SIZE && *checksum == data->writer_checksum;
}

static int run_document(workload_data_t* data, uint64_t* checksum) {
    tlv_document_t* document = NULL;
    tlv_node_t*     node;
    size_t          count = 0;
    int             valid = 1;
    *checksum = 0;
    if (tlv_document_parse(data->wire, WIRE_SIZE, &data->document_options, &document, NULL) !=
        TLV_OK)
        return 0;
    for (node = tlv_document_first(document); node != NULL; node = tlv_node_next(node)) {
        if (++count > ENTRY_COUNT ||
            !element_checksum(tlv_node_tag(node), tlv_node_value_data(node),
                              tlv_node_value_size(node), checksum)) {
            valid = 0;
            break;
        }
    }
    valid = valid && count == ENTRY_COUNT && tlv_document_count(document) == ENTRY_COUNT &&
            *checksum == data->all_checksum;
    tlv_document_free(document);
    return valid;
}

typedef struct {
    uint64_t checksum;
    size_t   count;
    int      valid;
} query_matches_t;

static tlv_visit_result_t query_match(const tlv_tree_event_t* event, void* context) {
    query_matches_t* matches = (query_matches_t*)context;
    ++matches->count;
    if (!element_checksum(event->element.tag, event->element.value.data,
                          (size_t)event->element.value.size, &matches->checksum))
        matches->valid = 0;
    return TLV_VISIT_CONTINUE;
}

static int run_query(workload_data_t* data, uint64_t* checksum) {
    tlv_query_exec_t* exec;
    tlv_tree_reader_t reader;
    query_matches_t   matches = {0, 0, 1};
    if (tlv_query_exec_init((const tlv_query_program_t*)data->query_program, data->query_workspace,
                            data->query_workspace_size, 0, ENTRY_COUNT, SIZE_MAX,
                            &exec) != TLV_OK ||
        tlv_tree_reader_init(&reader, data->wire, WIRE_SIZE, &tlv_format_ber, NULL, 0, 0,
                             ENTRY_COUNT) != TLV_OK ||
        tlv_query_program_visit(&reader, exec, query_match, &matches, NULL) != TLV_OK)
        return 0;
    *checksum = matches.checksum;
    return matches.valid && matches.count == ENTRY_COUNT / 16 && *checksum == data->query_checksum;
}

#define SCHEMA_WORKLOAD(name)                                                                      \
    static int run_##name(workload_data_t* data, uint64_t* checksum) {                             \
        return name(&data->schema, checksum);                                                      \
    }
SCHEMA_WORKLOAD(schema_check_shared)
SCHEMA_WORKLOAD(schema_validate_shared)
SCHEMA_WORKLOAD(schema_check_flat)
SCHEMA_WORKLOAD(schema_validate_flat)
SCHEMA_WORKLOAD(schema_check_recursive)
SCHEMA_WORKLOAD(schema_validate_recursive)
SCHEMA_WORKLOAD(der_schema_check_shared)
SCHEMA_WORKLOAD(der_schema_read_shared)
SCHEMA_WORKLOAD(der_schema_check_flat)
SCHEMA_WORKLOAD(der_schema_read_flat)
SCHEMA_WORKLOAD(der_schema_check_recursive)
SCHEMA_WORKLOAD(der_schema_read_recursive)
#undef SCHEMA_WORKLOAD

/* Each workload names its dataset; definition-check-only workloads read no input. */
typedef struct {
    const char* name;
    workload_fn run;
    const char* input_id;
    size_t      input_bytes;
} workload_t;

static const workload_t workloads[] = {
    {"reader", run_reader, "ber-flat-256x16-v1", WIRE_SIZE},
    {"writer", run_writer, "ber-flat-256x16-v1", WIRE_SIZE},
    {"document", run_document, "ber-flat-256x16-v1", WIRE_SIZE},
    {"query", run_query, "ber-flat-256x16-v1", WIRE_SIZE},
    {"schema_check_shared", run_schema_check_shared, "schema-shared-200-v1", 0},
    {"schema_validate_shared", run_schema_validate_shared, "schema-shared-200/ber-30-00-v1", 2},
    {"schema_check_flat", run_schema_check_flat, "schema-flat-16-v1", 0},
    {"schema_validate_flat", run_schema_validate_flat, "schema-flat-16/ber-flat-256x16-v1",
     SCHEMA_FLAT_WIRE},
    {"schema_check_recursive", run_schema_check_recursive, "schema-recursive-v1", 0},
    {"schema_validate_recursive", run_schema_validate_recursive,
     "schema-recursive/ber-nested-16x20-v1", SCHEMA_NESTED_WIRE},
    {"der_schema_check_shared", run_der_schema_check_shared, "der-schema-shared-200-v1", 0},
    {"der_schema_read_shared", run_der_schema_read_shared, "der-schema-shared-200/der-30-00-v1", 2},
    {"der_schema_check_flat", run_der_schema_check_flat, "der-schema-seq-of-octets-v1", 0},
    {"der_schema_read_flat", run_der_schema_read_flat,
     "der-schema-seq-of-octets/der-seq-of-256x16-v1", SCHEMA_DER_FLAT_WIRE},
    {"der_schema_check_recursive", run_der_schema_check_recursive, "der-schema-recursive-v1", 0},
    {"der_schema_read_recursive", run_der_schema_read_recursive,
     "der-schema-recursive/der-nested-16x20-v1", SCHEMA_NESTED_WIRE},
};

static void* allocate_aligned(size_t size, size_t alignment) {
    void* allocation = NULL;
    if (alignment < sizeof(void*)) alignment = sizeof(void*);
    if (size == 0 || posix_memalign(&allocation, alignment, size) != 0) return NULL;
    return allocation;
}

static int prepare_query(workload_data_t* data) {
    static const char        text[] = "//80";
    size_t                   scratch_size, scratch_alignment, workspace_alignment;
    tlv_query_program_info_t info;
    void*                    scratch;
    tlv_result_t             rc;
    memset(&info, 0, sizeof info);
    info.struct_size = sizeof info;
    rc = tlv_query_compile_scratch(text, sizeof text - 1, NULL, &scratch_size, &scratch_alignment,
                                   NULL);
    if (rc != TLV_OK) return 0;
    scratch = allocate_aligned(scratch_size, scratch_alignment);
    if (scratch == NULL) return 0;
    rc =
        tlv_query_compile(text, sizeof text - 1, NULL, scratch, scratch_size, NULL, 0, &info, NULL);
    if (rc == TLV_OK)
        data->query_program = allocate_aligned(info.program_size, info.program_alignment);
    if (data->query_program != NULL)
        rc = tlv_query_compile(text, sizeof text - 1, NULL, scratch, scratch_size,
                               data->query_program, info.program_size, &info, NULL);
    free(scratch);
    if (rc != TLV_OK || data->query_program == NULL) return 0;
    rc = tlv_query_exec_size((const tlv_query_program_t*)data->query_program, 0,
                             &data->query_workspace_size, &workspace_alignment);
    if (rc != TLV_OK) return 0;
    data->query_workspace = allocate_aligned(data->query_workspace_size, workspace_alignment);
    return data->query_workspace != NULL;
}

static uint64_t elapsed_ns(const struct timespec* start, const struct timespec* finish) {
    return (uint64_t)(finish->tv_sec - start->tv_sec) * UINT64_C(1000000000) +
           (uint64_t)finish->tv_nsec - (uint64_t)start->tv_nsec;
}

int main(int argc, char** argv) {
    static workload_data_t data;
    const workload_t*      workload = NULL;
    workload_fn            run = NULL;
    size_t                 index;
    unsigned long long     parsed;
    uint64_t               iterations, iteration, checksum = 0, total = 0;
    char*                  end;
    struct timespec        start, finish;
    int                    success = 1;
    if (argc != 3) {
        fprintf(stderr, "usage: %s WORKLOAD ITERATIONS\nworkloads:", argv[0]);
        for (index = 0; index < sizeof workloads / sizeof *workloads; ++index)
            fprintf(stderr, " %s", workloads[index].name);
        fprintf(stderr, "\n");
        return 2;
    }
    for (index = 0; index < sizeof workloads / sizeof *workloads; ++index)
        if (strcmp(argv[1], workloads[index].name) == 0) workload = &workloads[index];
    if (workload != NULL) run = workload->run;
    errno = 0;
    parsed = strtoull(argv[2], &end, 10);
    if (run == NULL || argv[2][0] < '0' || argv[2][0] > '9' || *end != '\0' || errno != 0 ||
        parsed == 0 || parsed > 100000000ULL) {
        fprintf(stderr, "unknown workload or ITERATIONS outside 1..100000000\n");
        return 2;
    }
    iterations = (uint64_t)parsed;
    prepare_input(&data);
    schema_workloads_init(&data.schema);
    if (tlv_document_options_init(&data.document_options, &tlv_format_ber) != TLV_OK ||
        (run == run_query && !prepare_query(&data))) {
        fprintf(stderr, "workload setup failed; the checkout may not support this driver\n");
        success = 0;
        goto cleanup;
    }
    /* Warm allocation/code paths and validate before collecting instruction counts. */
    if (!run(&data, &checksum) ||
        (run == run_writer && memcmp(data.output, data.wire, WIRE_SIZE) != 0)) {
        fprintf(stderr, "workload warmup produced an unexpected result\n");
        success = 0;
        goto cleanup;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        success = 0;
        goto cleanup;
    }
#if defined(OPENTLV_CALLGRIND_INSTRUMENTATION)
    CALLGRIND_START_INSTRUMENTATION;
    CALLGRIND_ZERO_STATS;
#endif
    for (iteration = 0; iteration < iterations; ++iteration) {
        if (!run(&data, &checksum)) {
            success = 0;
            break;
        }
        total += checksum;
    }
#if defined(OPENTLV_CALLGRIND_INSTRUMENTATION)
    CALLGRIND_DUMP_STATS;
    CALLGRIND_STOP_INSTRUMENTATION;
#endif
    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0) {
        perror("clock_gettime");
        success = 0;
    }
    if (success && run == run_writer && memcmp(data.output, data.wire, WIRE_SIZE) != 0) success = 0;
    if (success) {
        printf("{\"workload\":\"%s\",\"iterations\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64
               ",\"checksum\":%" PRIu64 ",\"input_bytes\":%zu,\"input_id\":\"%s\"}\n",
               workload->name, iterations, elapsed_ns(&start, &finish), total,
               workload->input_bytes, workload->input_id);
    } else {
        fprintf(stderr, "workload iteration produced an unexpected result\n");
    }
cleanup:
    free(data.query_workspace);
    free(data.query_program);
    return success ? 0 : 1;
}
