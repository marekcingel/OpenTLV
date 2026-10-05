# Query conformance

`corpus.json` is a versioned test-only interchange format. Each case names its
normative rules, Query, encoded input, and expected ordered match offsets, typed scalar encoding or
diagnostic. The one-byte Fixed format uses `70` as its constructed identifier.
Offsets identify nodes only in these fixtures; production node identity is
preorder identity and does not require Source.

`reference.py` parses and evaluates selections over an independently decoded
tree. It does not call OpenTLV or interpret compiled program images. V1 fixtures
also run a separate frozen exact-path baseline. `native.c` executes the same
fixtures through the canonical C Tree Reader, optimized/unoptimized programs and S0/retained execution.
Each successful fixture compares optimized/unoptimized native modes, forced
retained execution, and Document execution (except intentionally unavailable
Source properties). The native adapter maps source-less Document handles to fixture
Reader preorder identities. Every byte split of each fixture also exercises a
stable backing buffer, repeated NEED_MORE_DATA and final completion. Global D
plans execute only over Document; unit tests verify rejection before Reader consumption. Run:

```sh
python tests/query/run.py --native build/tests/query/test-query-conformance
```

For Visual Studio builds, use `build/tests/query/Release/test-query-conformance.exe`.
CTest registers this comparison as `query-s0-conformance` when Python is available.

| Contract rules | Coverage |
| --- | --- |
| Q-V1-01 | V1 root/child corpus and native parse/matcher regression tests |
| Q-V1-02, Q-V1-03 | Native corrupt-storage, parse/format/rebind tests; C++ move/resume tests |
| Q-LANG-01 | Native compilation/sizing tests and explicit option checks |
| Q-GRAMMAR-01, Q-GRAMMAR-02 | Syntax diagnostics, grouped-path fixtures, native formatting fixed point |
| Q-NODE-01, Q-NODE-03 | Root/prefix/union corpus and relative-context native tests |
| Q-NODE-02 | Wildcard/mask/range corpus; native absent/empty/multibyte Tag tests |
| Q-CONTEXT-01 | Per-step/global positions, last, sequential predicates and filtered ancestors |
| Q-CONTEXT-02 | Ancestor corpus, nearest-ancestor positions and retained filtered evidence |
| Q-VALUE-01 | Finalized booleans/int64/bytes/strings, cardinality and typed conversion failures |
| Q-BINDING-01 | Native typed declaration/binding, independent execution, UTF-8, embedded NUL and reset tests |
| Q-ABI-01 | Native caller-sized program/execution info prefixes and preserved trailing-byte tests |
| Q-VALUE-02, Q-FUNCTION-02 | Byte primitive and boolean/length corpus; capability diagnostics |
| Q-VALUE-03 | Metadata corpus; native missing-Source and custom Header tests |
| Q-FUNCTION-01 | Native implemented-function arity/type checks; missing providers and invalid closed-function operands are rejected |
| Q-STORAGE-01, Q-STORAGE-02 | Native copy/sizing/atomic-short-write tests; compile/format fuzz target |
| Q-PLAN-01 | Ordered deferred union/intersection/difference and explicit retained capacity |
| Q-LIMIT-01 | Native nesting/capacity/work tests; bounded fuzz configurations |
| Q-EVENT-01, Q-EVENT-02 | Empty-container corpus; native unbalanced/STOP/NEED_MORE_DATA tests |
| Q-VALIDATE-01 | Native malformed suffix, existence and explicit pruning tests |
| Q-COST-01 | Bounded-work tests, literal/expression/runtime-pattern corpus and initial Query benchmark |

Later-phase language rules are specification boundaries, not claims of implemented
conformance. This corpus is deliberately small and the independent interpreter
implements its exercised subset; it is not a second production Query engine.

## F2 completion evidence (#520)

| Work package | Implementation and validation |
| --- | --- |
| Typed iterative evaluation | Five result categories, signed int64 bounds, validated backward references and caller-sized frames; scalar/cardinality/overflow tests |
| Typed bindings | Existing independent borrowed bindings and reset/suspension rules; runtime KMP capacity and embedded-NUL tests |
| Closed functions | Compile-time arity/type checks, conversions, complete Values, positional/global predicates, scalar finalization; corpus plus F2 unit tests |
| Namespaces | Copied resolver tags, Definition scopes and native EMV symbols; conflict, unknown, freed/mutated lookup data and name-predicate tests |
| Codec environment | Capability IDs, aligned per-instruction scratch, full-Value native codecs and original codec/source/span diagnostics; compatibility and eager error tests |
| Tag introspection | Raw tag identity, independent Format construction, optional ASN.1 semantic class/number and strict GeneralizedTime date provider |
| Sets and optimizer | Ordered unique identities over deferred evidence, explicit node/work limits, pure folding/self-step simplification/guarded selector sharing and explain; four-mode corpus |

F3 extends the retained evaluator to S2 and Document and adds a proven bounded
S1 root-scope profile. No expression silently falls back to V1. The test oracle implements its exercised
subset independently, not every provider or future language capability. Native
unit tests cover provider-specific date/name/tag behavior and continuation.

## F3 completion evidence (#521)

The `f3_rules` inventory is a phase gate: the runner fails if any listed implemented
rule lacks both positive and negative fixtures. Every axis, reverse/global position,
last, parent deduplication, delayed ordering, nested absolute context, S1 count and
predecessor existence has independent expected identities and oracle coverage.
Additional native tests cover Source-less identity, metadata errors after Document
edits, constructed Value regeneration, foreign backend rejection, exact candidate
capacity, terminal overflow, work budgets, callback continuation and malformed suffixes.
The existing native pruning tests retain explicit full/partial validation coverage.

S1 only labels independently completing root scopes; overlapping deferred selections
are S2. S2 explicitly retains all published descriptors, with stable borrowed input,
and releases results at virtual-root EOF. Document adds no hidden Query allocation;
its separate constructed Value buffer and Tree Writer staging workspace are explicit. See the language contract for
resource costs and the distinction between descriptor and payload retention.

The phase gate also inventories all closed functions, with positive and negative
fixtures; optional ASN.1 providers are reported as unavailable when disabled.
Twenty-four deterministic independently generated trees compare sixteen composed
queries across streaming/Document/optimized/unoptimized execution. Those expected
answers come exclusively from the test-only interpreter. Native process checks
run with bounded parallelism; `--jobs 1` selects sequential execution.
