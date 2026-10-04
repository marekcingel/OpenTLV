# Query conformance

`corpus.json` is a versioned test-only interchange format. Each case names its
normative rules, Query, encoded input, and expected ordered match offsets or
diagnostic. The one-byte Fixed format uses `70` as its constructed identifier.
Offsets identify nodes only in these fixtures; production node identity is
preorder identity and does not require Source.

`reference.py` parses and evaluates selections over an independently decoded
tree. It does not call OpenTLV or interpret compiled program images. V1 fixtures
also run a separate frozen exact-path baseline. `native.c` executes the same
fixtures through the canonical C Tree Reader and S0 program. Run:

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
| Q-CONTEXT-01 | F1 candidate predicates; positional execution is a capability rejection |
| Q-CONTEXT-02 | Ancestor corpus and rejection of filtered ancestor evidence |
| Q-VALUE-01 | F1 result/operand type checks; general scalar execution is deferred |
| Q-BINDING-01 | Native typed declaration/binding, independent execution, UTF-8, embedded NUL and reset tests |
| Q-ABI-01 | Native caller-sized program/execution info prefixes and preserved trailing-byte tests |
| Q-VALUE-02, Q-FUNCTION-02 | Byte primitive and boolean/length corpus; capability diagnostics |
| Q-VALUE-03 | Metadata corpus; native missing-Source and custom Header tests |
| Q-FUNCTION-01 | Native implemented-function arity/type checks; future functions are rejected |
| Q-STORAGE-01, Q-STORAGE-02 | Native copy/sizing/atomic-short-write tests; compile/format fuzz target |
| Q-PLAN-01 | Deferred-union corpus and native S1/S2 capability diagnostics |
| Q-LIMIT-01 | Native nesting/capacity/work tests; bounded fuzz configurations |
| Q-EVENT-01, Q-EVENT-02 | Empty-container corpus; native unbalanced/STOP/NEED_MORE_DATA tests |
| Q-VALIDATE-01 | Native malformed suffix, existence and explicit pruning tests |
| Q-COST-01 | Bounded-work tests, literal-pattern corpus and initial Query benchmark |

Later-phase language rules are specification boundaries, not claims of implemented
conformance. This corpus is deliberately small and the independent interpreter
implements its exercised subset; it is not a second production Query engine.
