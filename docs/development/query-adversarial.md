# Query adversarial verification

[F6 / #536](https://github.com/marekcingel/OpenTLV/issues/536) verifies native API
sequences, storage relationships, callback lifetime and plan production after
F1–F5. It does not add Query syntax. The public headers remain the contract.

## Lifecycle oracle

`tests/query/adversarial.c` uses only public C APIs. It runs 256 deterministic
seeds with 128 operations each against both streaming and retained execution.
The reference state is independent of executor internals. Operations include
binding, valid and malformed events, NULL arguments, repeated finish, reset,
selected access, scalar/category access and result pulls. Every transition
checks its status, sentinel outputs, terminal/finished flags and immutable plan.
Retained capacity exhaustion, missing bindings and malformed events remain
terminal until reset. Separate provider-failure sequences verify the same
recovery boundary. S1 regressions cover repeated delayed selection followed by
terminal failure; generated native plans cover S0/S1/S2/D and scalar results.

| State | Bind | Feed | Finish | Results | Reset |
| --- | --- | --- | --- | --- | --- |
| Fresh | Once per declared variable | Requires all bindings | Requires all bindings | Unavailable | Fresh |
| Feeding | Rejected | Balanced events within budgets | Balanced EOF | S1 current publication only | Fresh |
| Finished | Rejected | Rejected, completed result preserved | Idempotent | Retained results available | Fresh |
| Failed | Rejected | Rejected | Rejected | Unavailable | Fresh |
| Active callback | Rejected | Rejected | Rejected | Rejected | Rejected |

`tlv_query_exec_reset()` preserves program, environment and budgets and clears
bindings, context, pruning, counters and borrowed results. The C++ `reset()`
delegates to C. Raw `exec_init`/`eval_init` still accept uninitialized storage;
they require exclusive ownership and cannot be used to overwrite storage active
on a callback stack. The library cannot inspect arbitrary uninitialized bytes
as an existing execution. No thread-local registry or hidden allocation is used.
Separate executions remain independent; this is not synchronization between threads.

## Storage relationships

The driver exercises exact aliasing, prefix/suffix and both overlap directions,
one-byte boundaries, adjacency and misalignment. Read-only static objects are
executed directly. Forbidden overlap returns `TLV_ERR_INVALID_ARG` before writes,
including diagnostic initialization. Capacity failure preserves the output handle.

| Storage pair | Contract |
| --- | --- |
| Program/image and execution/retained/candidate workspace | Disjoint; candidates are inside the measured execution workspace |
| Image and validation scratch | Disjoint; bounded loader validates before publishing |
| Program/image and output/diagnostic objects | Disjoint |
| Workspace and environment, hook array, tag/Format descriptors | Disjoint |
| Workspace and input, event object, Tag, Value, Source or bound spans | Disjoint |
| Output objects and workspace, program, descriptors or retained borrowed spans | Disjoint |
| Simultaneous outputs | Disjoint |
| Tag, Value, Source, immutable input and program payload | May alias; their owners must remain alive and immutable |
| Exactly adjacent storage | Supported when each address satisfies its own alignment |
| Document snapshot and discovery staging data | May be the same buffer |
| Document snapshot and Writer frames/scratch or Query workspace | Disjoint |

Provider contexts and opaque Document allocations are not introspectable caller
storage. Callers must obey their ownership contracts. A span must always describe
readable storage; overlap checks do not validate arbitrary addresses. Retained
output checks use a borrowed-address envelope to avoid scanning unrelated input;
possible overlaps are checked against exact spans, so gaps are not forbidden.

## Callbacks and Document revision

Native visitor, conversion and semantic-tag callbacks attempt feed, finish,
reset, bind, context, pruning and result access on their active execution. Those
operations fail without corrupting the outer operation. A nested independent
compiler invokes a name resolver which attempts the same operations. Resolver
failure is a compilation failure, not an execution phase: the surrounding
provider determines whether its execution succeeds or fails.

Document tests combine retained S0/S1/S2/D with erasing selected nodes/ancestors,
replacing their Values, inserting before/after, repeated erase, nested visits
and Document free. Replacement/insertion and nested traversal are rejected.
Erase/free are deferred through evaluation or the visitor callback, preserving
borrowed Tag/Value/node data; applying them invalidates execution. The backend
attaches each Document handle before feeding its event. Existing retained-source
location regressions verify metadata on those handles. After the call returns,
the caller still owns Document lifetime; revision checking is not a destruction
token for an externally freed Document.

## Plan equivalence and frontend-free builds

`generate_adversarial_plans.py` independently emits 77 C plans and matching C++11
constexpr expressions: three raw tags, child/descendant selection, four comparisons
constant/variable operands and comparisons at signed integer boundaries. Each runs with 32 input seeds and normal,
one-short candidate and exhausted-work budgets. The frontend-enabled runner also
compiles the corresponding text. It compares status, diagnostic category, result
kind, ordered unique ordinals, variables, profile, retention, provider and pattern
requirements. Exact and one-byte-short workspace capacities are checked per plan.

The family checks streaming and retained execution, flat and nested trees, and
execution with and without a relative context. It requires identical measured
workspace size/alignment across all three sources, including exact-capacity and
one-short failures. This exposed a missing explicit root in constexpr plans:
`child()`/`descendant()` had changed meaning when a context was installed.
Constexpr compilation now emits the same explicit root/path structure and keeps
absolute paths independent of that context. Regenerate constexpr images; inferred
`auto` use is unchanged, but explicit `plan<N, P>` result types and caller workspace
measurements must account for two additional node-plan instructions.

Source-free plans may omit source positions. The comparison requires diagnostic
category, provider status, source availability/offset, resource name/bound and
expected-condition equivalence. Query text offsets are compared only for generated
native images retaining the compiler's source map. The differential audit also
removed unused runtime search-pattern capacity and unused tag-provider IDs from
plan requirements.

`adversarial_native.h` additionally contains frontend-produced C initializers
with all source text removed for S0/S1/S2/D and count/exists/Value results. The
frontend-enabled driver compares their instructions and payload against current
compilation. Regenerate with `test-query-adversarial --export`. The frontend-free
driver executes the supported plans using the same C executor and independent
expected results; D event execution is rejected before publication.
The same driver also evaluates D plans through Document in frontend-enabled and
frontend-free Document-enabled builds, comparing node handles and revision failures.

## Reproduction and evidence

Build `test-query-adversarial` and, with C++ enabled, `test-query-equivalence`.
Both are registered with the `query;adversarial` CTest labels. The pure C driver
also runs under MSan without an uninstrumented C++ standard library.

```sh
ctest --test-dir build -L adversarial --output-on-failure
python tests/query/generate_adversarial_plans.py --check
python tests/query/adversarial_campaign.py --native build/tests/query/test-query-adversarial --equivalence build/tests/query/test-query-equivalence --output build/query-adversarial
```

On Windows use the configuration-specific executable paths. For a printed
failure sequence, `test-query-adversarial --sequence BFXRBF` replays it in both
backends. The campaign records logs, binary hashes, seeds and a JSON report;
sequence failures are reduced by deterministic deletion and saved as
`regression.txt`. Retain a minimized reproducer in the permanent regression list
before fixing a discovered failure. MSan retries only identified pre-main shadow
mapping failures, never sanitizer findings or ordinary test failures.

The hardening workflow runs ASan/UBSan, native x86, C-only MSan and frontend
ON/OFF static-plan configurations. The strict release gate requires F6,
`adversarial-lifecycle-storage` and `plan-equivalence-frontend-free` evidence for
the candidate commit. Local logs do not replace hosted or clean-candidate evidence.

## Local verification on 2026-10-06

| Check | Result |
| --- | --- |
| Windows Debug C unit suite | 684 passed |
| Windows Debug C++ unit suite | 176 passed |
| Native lifecycle/storage/callback campaign | 512 seeded sequences plus directed regressions passed |
| C/runtime/constexpr differential family | 77 plans, 32 seeds, three budgets, applicable streaming/retained modes passed |
| Linux Clang 18 ASan/UBSan | Query conformance, ABI and adversarial suites passed; final constexpr/context regressions passed |
| Frontend-free Clang 18 ASan/UBSan | All four native/static/constexpr/equivalence tests passed; frontend symbols absent |
| C-only MSan | Adversarial campaign passed on its first attempt |
| Allocation/recursion audits | 156 source roots and 146 archive roots passed |
| Documentation | C/C++ Doxygen with warnings as errors, strict MkDocs and inventory checks passed |
| Tooling | Pinned clang-format hook, generator consistency, license, release-gate and sequence-minimizer checks passed |

These are local worktree results. Hosted x86/platform jobs and the final
same-commit clean-candidate evidence gate were not run locally. The documentation
build did not include WebAssembly playground artifacts.
