# Query F1-F5 implementation audit

Audit date: 2026-10-06. Scope: the original 44 work packages in the supplied
`OpenTLV_Query_1.0_GitHub_Issues.md`, compared with current source and
[epic #518](https://github.com/marekcingel/OpenTLV/issues/518). The epic explicitly
replaces those children with delivery issues #519-#523; original F0 is included
in F1. The original planning document is evidence of intended scope, not an
instruction to create another set of GitHub issues.

## Phase status

| Delivery phase | Implementation assessment |
| --- | --- |
| [F1 / #519](https://github.com/marekcingel/OpenTLV/issues/519) | Implemented, including checked preparation/commit that rejects equal-size resolver drift before publishing a program. |
| [F2 / #520](https://github.com/marekcingel/OpenTLV/issues/520) | Typed VM, variables, functions, generic hooks, names, tags, sets and optimizer are implemented in C with positive/negative coverage. |
| [F3 / #521](https://github.com/marekcingel/OpenTLV/issues/521) | Bounded S1/S2, ordering, all Document axes and cross-backend/reference checks are implemented. |
| [F4 / #522](https://github.com/marekcingel/OpenTLV/issues/522) | Implemented Query integrations and owning facades, including Tag adapters, scoped dynamic/Definition/EMV resolvers, configured Formats, source events, ordinals and V1 compatibility. |
| [F5 / #523](https://github.com/marekcingel/OpenTLV/issues/523) | Hardening and candidate gates implemented; local checks below pass. Closing the delivery issue still requires passing CI and complete evidence for the final candidate commit. |

Benchmark measurements are advisory by the subsequent scope decision. Accepted
performance baselines and optimization are not prerequisites for these phase
assessments. Existing tests and a passing local worktree do not establish a
validated clean release candidate.

## Completed follow-up and remaining candidate verification

**Resolver stability across passes (original F1-02, #519 work package 7).**
`tlv_query_compile_prepare_size/prepare/commit` adds caller-owned preparation
and exact-byte validation before publication. It detects equal-size identifier
changes and preserves output storage and info on failure. All owning constructors
use it. The original single-call compiler remains available with its documented
stable-callback precondition; output-only info is never interpreted as input.
Native, C++ and binding regressions cover resolver drift and callback failures.

**Query extension capabilities (F4).** Dedicated consumer tests supplement the
common grammar corpus. All five owning language facades expose semantic Tag
callbacks, scoped dynamic and Definition resolvers, native EMV resolution,
conversion providers, configured Fixed Formats, source-bearing events, result
ordinals, V1 compatibility, completed-selection edits and contextual Schema.
Python shares immutable native Fixed configuration ownership; Go preserves its
Format value semantics when adapting compatible Document contexts; Rust callers
clone one `OwnedFixedFormat` to preserve native context identity. JS/WASM also
supports custom framing callbacks. The broader
[binding matrix](../concepts/bindings.md#capability-implementation-matrix)
continues to track general Reader/Writer/custom-Format gaps outside these Query
delivery changes; this audit does not claim whole-library facade parity.

**Candidate evidence (F5).** The reusable
[Query release candidate workflow](../../.github/workflows/query-release.yml)
consumes a hashed manifest from a successful same-commit run and invokes strict
validation. It does not infer passing phases from issue states or generate
capability claims from a symbol list. Collect evidence for the final clean
candidate after the final changes are committed and CI passes. See the
[release checklist](query-release.md) for the manifest and workflow contract.

## Findings fixed during this follow-up

- Canonical formatting can increase compiler scratch requirements. The Query
  fuzzer now sizes scratch from formatted text instead of treating a short-buffer
  rejection as a crash. The exact CI input is retained as
  `tests/fuzz/query/corpus/program/canonical-scratch-boundary` and passes replay.
- Lua protects execution and Document guards across callbacks, table metamethods,
  allocation failures and result projection. WASM preserves original callback
  exceptions, including `null`, `undefined` and an exception carrying the EOF code.
- Rust now owns contextual Query Schema programs/workspace/diagnostics and
  exposes retained results after raw event feeding.
- Python, Go, Lua and JS/WASM preserve contextual Schema paths, available
  offsets, expected values and native diagnostic categories. Consumer tests
  exercise valid/false assertions, resource bounds, provider lifetimes and
  immutable Document guards.
- Query and Schema previously copied an uninitialized Tree Reader diagnostic
  when depth/frame/node limits failed. Their callers now initialize absent
  detail and retain the actual failure status, preventing invalid spans from
  escaping into language bindings. The Reader's documented diagnostic contract
  is preserved.
- Structured pair fuzzing now covers callback errors, provider failures and
  result-type violations, legal input replacement, repeated NEED_MORE_DATA,
  exact/short workspace and reuse after failure.
- Root-only constructed Documents now reserve the Writer frame at depth zero
  when building Value snapshots. Lua retains its Document guard through
  allocation and protected diagnostic projection, including GC finalizers.
- C++ Boolean builder comments now describe eager native evaluation. Language
  guides and the binding matrix describe the new APIs and their ownership.

## Original work-package coverage

"Present" in this source map means an implementation and relevant tests were
found; it does not claim every candidate/platform run has passed. Deterministic
S1 classification is deliberately conservative; source retention uses the
explicit stable-input contract rather than an optional lookup callback.

| Package |Source/contract and relevant test evidence | Audit conclusion |
| --- | --- | --- |
| F0-01 language contract | `docs/concepts/query-language.md`: EBNF, numeric/raw-tag disambiguation, virtual root, axis ordering, eager booleans, storage/cost; 24 rule IDs mapped by `check_query_release.py`; `corpus.json` | Present; benchmark policy follows newer user direction |
| F0-02 opaque/versioned API | `tlv/include/tlv/query/query.h`, `program.h`, `v1_internal.h`; accessor/rebind code in `query.c`; `CallerSizedInfoPreservesUnknownAndUnavailableFields`; ABI runner | Present; compiled programs separate from fixed V1 storage |
| F0-03 bounded parse/format | `query.c` parse_n/format, `compiler.c` canonical format; `BoundedParsingFormattingAndCorruptAccess`, `CanonicalFormatRecompilesAndShortWritesAreAtomic`, exact V1 limits | Present |
| F0-04 diagnostics/limits | `program.h`, `query_error/query_limit`, parser/exec checked sizing; `UnsupportedFeaturesHavePreciseDiagnostics`, `CapacityAndNestingBoundariesPreserveStorage`, binding and reader-error tests | Implemented; facade Schema diagnostic projection corrected in this follow-up |
| F0-05 V1 hardening | `valid_query`, count/step checks, shared `match_internal.h`; `query_test.cpp`, V1 independent baseline in reference.py, parse/match fuzz harnesses | Present |
| F1-01 iterative frontend | `compiler.c` lex/parse and explicit tokens/operators/value arrays; nesting/text/state bounds; malformed/truncated/explicit numeric axis tests; compile fuzz dictionary | Present; no C recursion introduced |
| F1-02 immutable relocatable programs | compiler relative indices/text/payload, exact discovery and alignment, `program_load`, atomic short writes; external read-only image and checked preparation/commit tests | Implemented; exact comparison detects resolver drift before publication |
| F1-03 whole-plan classification | compiler `analyze`, S0/S1/S2/D info and retained rejection; `WholePlanRequirementsAndDocumentRejection`, deferred-order corpus | Present; deliberately conservative S1 profile is documented |
| F1-04 S0 matching | `execute.c` state machine, shared raw-byte node tests, union/intersection/difference; `DescendantUnionIsOrderedAndUnique`, mask/range/empty-tag tests | Present |
| F1-05 canonical events/resume | `tlv_query_exec_feed/finish/selected`, Tree Reader visit/existence adapters; balanced events, END original node, STOP/NEED_MORE_DATA tests | Present; no fragmented-Value reader claim |
| F1-06 metadata/bytes | `execute.c` borrowed Value operations, KMP prefix capacity and byte charging; `MetadataBytesAndAncestorPredicates`, `CustomEventsPreserveTagWidthsAndSourceHeaderSemantics`, contains exact-work tests | Present |
| F1-07 pruning/coverage | `PruningAndExistsExposePartialCoverage`, `ValidationAndWorkLimitsAreExplicit`, F3 malformed suffix tests; explicit `full_validation`/skipped info | Present |
| F1-08 independent oracle | `tests/query/reference.py`, `run.py`, `native.c`, versioned corpus; frozen V1 matching is independent of C | Present; oracle implements exercised language, not arbitrary application callbacks |
| F2-01 bounded typed VM | `evaluation.c` explicit frames/sets with backward AST references; five categories, int64 checks; F2 closed function, cardinality, overflow/eager errors tests | Present |
| F2-02 variables | copied declarations, unique referenced slots, `exec_bind`; missing/unknown/duplicate/type/UTF-8 tests, immutable program independent executions | Present |
| F2-03 closed functions/scalars | `query_function_kind` + `evaluation.c`; all closed function positive/negative feature corpus, scalar/cardinality/native builtin conversion tests | Present |
| F2-04 name adapters | `adapters.c`, Definition scopes and EMV resolver; copied raw identifiers, conflict/unknown and named-vs-raw tests | Implemented with checked resolver stability and owning facade adapters |
| F2-05 conversion providers | native hooks and aligned decoded scratch, capability IDs/environment compatibility; `StrictCodecErrorsAndEagerBooleanEvaluation`, `ProviderScratchAlignmentAndResultValidation` | Implemented in C; owning conversion callback facades have consumer tests |
| F2-06 Format tag capabilities | optional environment tag adapter, ASN.1 class/number/date in builtin source; `Asn1CapabilitiesAndUtcDateAdapter`, unsupported provider tests | Present; generic core has no protocol tag switch |
| F2-07 sets/optimizer | ordered retained sets and S0 identities, pure folding and guard sharing, canonical explain; six-mode optimized/unoptimized differential runner | Present |
| F3-01 scope evidence | bounded root-scope S1 summary profile in compiler/execute; END/primitive root decisions; `S1ScopePublicationStopResumeAndMalformedSuffix`, `S1RawFeedDecidesOnlyAtEndAndReportsOriginalNode` | Present with explicit conservative promotion to S2 |
| F3-02 reverse/sibling/position | retained axis evaluator, S0 predecessor evidence; `NestedDeferredOrderAndReverseContexts`, full axis/position corpus | Present |
| F3-03 bounded S2 | `retained_node_t`, exact eval_size/init, candidate overflow diagnostics and terminal invalidation; `CandidatesExactCapacityOverflowAndSourceLessIdentity`, `DeferredWindowsRetainStablePayloadAndResume` | Present; stable-input contract chosen instead of a lookup callback |
| F3-04 ordered unique deferred results | explicit node sets/ordinal frontier released at EOF, S1 disjoint root order; nested positive/negative ancestor and STOP/resume tests | Present; no source-offset identity |
| F3-05 complete Document backend | `document_backend.c` topology events and shared evaluator, D axes, revision check, optional constructed Value snapshot via Writer; source-less/mutation/allocator/snapshot tests | Present |
| F3-06 cross-backend equivalence | all axis/function phase inventory, positive/negative fixtures, every fixture byte split, generated composed/typed trees, S0/retained/Document and optimized/unoptimized modes | Implemented; native conformance is included in the local validation below |
| F4-01 checked Document selections | core Query Document pull/visit and C++ checked range; destruction/revision and deferred-free tests in `test_query_ranges.cpp` | Present |
| F4-02 completed-selection edits | native `tlv_document_query_edit`, C++ query_remove/replace/insert; same-exec capacity retry, original selection, ancestor dominance, insertion preflight, allocator partial count tests | Implemented with owning-language edit and invalidation regressions |
| F4-03 contextual Schema | `tlv/src/schema/query.c`, public `schema/query.h`, C++ validation methods; buffer/Document contextual rules and original Reader error tests | Implemented in C/C++ and all five owning language facades; contextual diagnostics and resource tests added |
| F4-04 CLI | `query_command.cpp` native compilation, typed vars, backend selection, scalar/existence/count, explain and error JSON; `tools/cli/test.cmake`, CLI common corpus runner | Present; no hidden streaming-to-Document fallback |
| F4-05 semantic diff | `document/diff.hpp`, CLI diff command; same-tag ancestor path/occurrence correspondence; original left/right selectors, one-sided selection, selected ancestor direct content; `DiffUsesOriginalPositionsAndExcludesUnselectedDescendants` | Minimum diff present; variables/providers explicitly unsupported by this minimal convenience surface, not silently interpreted |
| F4-06 idiomatic C++ | `query/program.hpp`, builder.hpp, Document methods, RAII and external workspace; C++ common corpus and caller-storage/move/resume/diagnostic tests | Implemented; eager Boolean evaluation comments corrected |
| F4-07 Rust | safe QueryProgram/Execution/providers/edit API and shared corpus runner | Implemented Query extensions, shared Fixed owner, Schema, source events and V1 format/reset/rebind; default/minimal-feature regressions |
| F4-08 Python | program.py and native query.c, providers/feed/scalars/Document/edit; common corpus and provider/ownership regressions | Implemented Query extensions, shared configured Format ownership, ordinals and V1 reset/rebind; full facade suite |
| F4-09 Go | program.go and capi bridges, C-owned pinned data, providers/feed/edit, common corpus and callback/Close tests | Implemented Query extensions, Fixed value compatibility, source feeds/ordinals and standalone V1 facade; full package suite |
| F4-10 Lua | program.c userdata, provider protection, feed/edit/Document invalidation, native diagnostic tables and corpus | Implemented Query extensions, source feeds/ordinals and resumable V1 matcher; allocation/finalizer regressions |
| F4-11 JS/WASM | native wasm wrapper + query.mjs owning program/exec/Document, int64 BigInt, copies after memory growth, disposal/provider guards, corpus | Implemented Query extensions, owning configured/custom Formats, source feeds/ordinals and V1 facade; callback lifetime/error regressions |
| F4-12 docs/examples | normative reference, Query guide, per-language guides, CLI guide, executable C/C++ examples | Guides and capability matrix describe final ownership and extension APIs |
| F5-01 bounded image loader | `image_header`, load_scratch/load canonical reconstruction+full byte compare; truncation/alias/field mutation/read-only page/environment/version tests | Present; same-version/endianness image only, no checksum-as-authentication shortcut |
| F5-02 properties/differential | seeded wire infrastructure, generated trees/33 composed and typed Queries, independent oracle, set/order laws, retained windows, reproducible/minimized failures | Present; finite fixed query families complement complete feature fixture corpus |
| F5-03 fuzz/sanitizers | parse/match/program/image/pairs targets, dictionary/seeds, ASan/UBSan workflow, persistent MSan corpus campaign with retained logs | Error/hook/replacement fuzz paths added and exercised under ASan/UBSan |
| F5-04 allocation/recursion/budgets | Clang transitive source graph and emitted archive dependency audits, counters and exact bounds in Query tests, native x86 workflow, separate callback boundary | Present; owning wrappers/Document construction intentionally outside allocation-free proof |
| F5-05 benchmarks | measured phase/scaling benchmark scenarios, baseline comparison script and CI measurement | User explicitly suspended mandatory timing gate; advisory and no optimization work required |
| F5-06 release/API evidence | normative/feature/C capability inventory, strict contained/hash/exact-commit evidence validation, ABI32/64 fixtures, all eight common runners | Implemented; passing final-candidate CI/evidence remains the closure requirement |

## Local verification and release boundary

The working branch retains local verification artifacts under `build/`; these
are review evidence, not a fabricated passing release manifest. Final results
are recorded with the implementation review. Hosted platform matrices and the
strict clean-candidate evidence check remain separate requirements.

The native regression `TreeResourceLimitsHaveOwnedSafeReaderDiagnostics` covers
frame, depth and element limits, including contextual Schema propagation. Rust
Schema limit tests originally exposed the invalid diagnostic span, so success
requires relinking against the repaired C library rather than rerunning a stale
binding binary.

Current local evidence from this follow-up:

| Check | Observed result |
| --- | --- |
| Windows native baseline before the diagnostic fix | Full CTest: 1,115/1,115 |
| Windows native after checked compilation | Query CTest: 132/132, including C/C++ corpus and native ABI |
| Linux ASan/UBSan after checked compilation | 82 native and 38 C++ Query tests; native 64-bit ABI snapshot matched |
| MemorySanitizer after checked compilation | Persistent corpus: 1,002 executions passed; earlier separate probe covered all four resource-diagnostic failure paths |
| Source and archive allocation/recursion audits | No violations; 142 source roots / 252 functions and 121 archive roots / 253 symbols |
| Rebuilt-core structured pair fuzzing | 701 executions / 11 seconds under ASan/UBSan, no finding |
| Query program fuzzing after the CI correction | Exact CI input replayed; 4,569 executions / 64 seconds under ASan/UBSan, no finding |
| Rust | Full workspace and final extension/default-disabled tests passed; all-target Clippy passed |
| Python | Full suite: 180 tests; final Query suite: 19 tests; 169 fixtures / 658 corpus checks |
| Lua and JS/WASM | Rebuilt modules passed extension/lifetime regressions and 169 fixtures / 3,416 corpus checks each; Lua includes injected allocation failures |
| Go | Full package suite and final 13 focused Query/V1 tests passed |

These checks establish the stated local behavior. They do not substitute for
the supported-platform matrix or the final clean-candidate evidence gate.
