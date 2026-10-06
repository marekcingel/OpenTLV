# Query conformance

F5 adds `--commit`, `--seed` and `--evidence` to the runner. The commit seed
mapping comes from the wire property infrastructure. Evidence separates trees,
queries and typed bindings from independently computed expected identities/scalars;
failure JSON preserves the complete reproducer. Generated trees compare optimized,
unoptimized, retained, Document and legal retained-prefix windows, including typed
integer/bytes/string parameters and set laws. `Property_query` runs this through
the property workflow. See [release evidence](../../docs/development/query-release.md)
for the strict candidate gate and required candidate artifacts.
The [F1-F5 implementation audit](../../docs/development/query-phase-audit.md)
maps all original work packages to source/tests and records final local
verification; a common-corpus pass alone does not establish full parity.

Checked compilation is covered by native and facade resolver-drift regressions.
The native corpus and owning constructors prepare once, then compare complete
recompiled images before publication. Compiler fuzzing retains the CI input
`tests/fuzz/query/corpus/program/canonical-scratch-boundary`: canonical whitespace
can increase scratch requirements, so the harness independently sizes the
formatted text before recompilation.

The native adapter's `image` mode writes same-version fuzz seeds, for example
`test-query-conformance "//5A" 5a00 image descendant-v5.bin`. Checked-in image seeds
are project-generated MIT data: descendant `//5A`, deferred
`//70[exists(5A)]`, and scalar `count(//5A)`. Regenerate when the private image
version changes; no cross-release serialization compatibility is promised.

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
retained execution, and Document execution with optional original source locations
enabled, including `@offset`/`@hlen`. The native adapter maps Document handles to fixture
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
programs without constructed Value dependencies need no encoding storage. Other
programs share slices of one encoded snapshot, with explicit Writer frames/scratch.
Native regressions cover nested/empty snapshot slices, allocator rejection and exact
work thresholds independent of spare buffer capacity. See the language contract for
resource costs and the distinction between descriptor and payload retention.

The phase gate also inventories all closed functions, with positive and negative
fixtures; optional ASN.1 providers are reported as unavailable when disabled.
The default twenty-four deterministic independently generated trees compare
thirty-three composed and parameterized queries across streaming/Document/
optimized/unoptimized execution. Those expected
answers come exclusively from the test-only interpreter. Native process checks
run with bounded parallelism; `--jobs 1` selects sequential execution.

With `--evidence DIR`, generated failures retain both the original JSON record
and a `failure-*-minimized.json` reproducer. The deterministic shrinker removes
subtrees, shortens primitive Values and removes predicates, with at most 128
native attempts. Each attempt recalculates independent expectations, including
changed source offsets, and keeps the original native exit category. Prefix
windows are adjusted to the reduced input extent. Diagnostic/provider fixtures
retain their original inputs. Run `python tests/query/test_minimize.py` to verify
the shrinker's framing, expectation and budget contracts.

## Adversarial API verification

The frontend-free `test-query-adversarial` driver and generated
`test-query-equivalence` family cover lifecycle, storage, native callbacks,
Document lifetime and plan sources. See the canonical
[F6 audit](../../docs/development/query-adversarial.md) for contracts, intentional
representation differences, replay, minimization and evidence commands.
