# Query language and execution contract

This specifies the XPath-inspired binary TLV Query language. It is not an
XPath conformance claim. Query delivery phases F0–F5 belong to OpenTLV's
Execution Foundation; they do not redefine architectural roadmap phases.

## Language selection and compatibility

**Q-V1-01.** `tlv_query_parse[_n]` selects the existing V1 language: nonempty,
even-length hexadecimal tags separated by `/`, with no whitespace, leading
slash, empty step or trailing slash. Hexadecimal case is insignificant. The
first step addresses roots, subsequent steps direct children. The inline
capacities remain 65 steps and 512 total tag bytes.

**Q-V1-02.** V1 Query is a self-contained, copyable value. Zero initialization
denotes an invalid empty Query. Its 648-byte union storage and native
`uint64_t` alignment are public storage contracts, not public field layouts.
Matcher storage is 16 bytes aligned for pointer and native `size_t` members.
Never inspect or modify opaque bytes. `count` and `step` validate boundaries
before returning information. Invalid storage cannot produce a borrowed range.

**Q-V1-03.** Length-delimited parsing reads exactly the supplied byte span;
empty text, embedded NUL and non-ASCII input are invalid. Parse failure leaves
Query unchanged. Canonical formatting emits uppercase tags and reports bytes
including NUL; a short output remains unchanged. A matcher borrows its Query.
Reset uses `matcher_init`; `matcher_rebind` preserves continuation only for
equivalent copies and requires the old copy alive through the call.

**Q-LANG-01.** `tlv_query_compile` explicitly selects full language version 1.
Options initialized by the current release have `struct_size == sizeof` the
current options structure. Other sizes/versions are rejected. Options are not
interpreted by guessing an older layout. Later extension rules require a new
explicitly supported structure size or language version.

## Grammar

**Q-GRAMMAR-01.** Outside literals, tokens are ASCII; whitespace separates
tokens and is otherwise insignificant. Embedded NUL is invalid everywhere.
String literals contain valid UTF-8, without unescaped control characters.
Inside strings, backslash escapes a quote or backslash. Byte literals contain
an even number of hex digits and may be empty. Keywords are case-sensitive.

```ebnf
query       = expression ;
expression  = union ;
union       = disjunction, { ("|" | "intersect" | "except"), disjunction } ;
disjunction = conjunction, { "or", conjunction } ;
conjunction = comparison, { "and", comparison } ;
comparison  = path, [ ("=" | "!=" | "<" | "<=" | ">" | ">="), path ] ;
path        = [ "/" | "//" ], filtered, { ("/" | "//"), filtered } ;
filtered    = primary, { "[", expression, "]" } ;
primary     = step | metadata | variable | integer | bytes | string
            | call | "(", expression, ")" ;
step        = [ axis, "::" ], test | "." | ".." ;
axis        = "child" | "descendant" | "descendant-or-self" | "self"
            | "parent" | "ancestor" | "ancestor-or-self"
            | "following-sibling" | "preceding-sibling"
            | "following" | "preceding" ;
test        = raw-tag | "*" | wildcard-tag | qualified-name ;
raw-tag     = hex-pair, { hex-pair } ;
wildcard-tag = (hex-pair | "??"), { hex-pair | "??" } ;
qualified-name = identifier, ":", identifier ;
metadata    = "@", ("len" | "offset" | "hlen" | "depth" | "index") ;
variable    = "$", identifier ;
integer     = [ "-" ], digit, { digit } ;
bytes       = "x'", { hex-pair }, "'" ;
string      = single-quoted-utf8 | double-quoted-utf8 ;
call        = identifier, "(", [ expression, { ",", expression } ], ")" ;
identifier  = letter, { letter | digit | "_" | "-" } ;
hex-pair    = hex-digit, hex-digit ;
```

**Q-GRAMMAR-02.** Operators are left associative, with precedence from low to
high as the productions above. Comparisons do not chain. A function's commas
separate arguments, not top-level expressions. Predicates bind to the preceding
primary before path composition. `//` abbreviates descendant navigation from
the preceding context. A path step `50` is a raw hexadecimal tag; a numeric
comparison operand `10` is decimal. A direct predicate `[10]` is positional.
An explicit axis such as `[child::50]` always denotes a raw tag test, including
when whitespace follows `::`; it never becomes a positional or scalar literal.
Bare even hex-looking identifiers such as `CAFE` are raw tags; names use a
namespace, including `emv:CAFE`. For symbols outside identifier syntax, the
planned `name(namespace, symbol)` function supplies string arguments. Odd raw
hexadecimal spellings such as `BAD` cannot silently become a truncated tag.

## Node model, order and context

**Q-NODE-01.** The virtual document root owns the ordered root sequence. It is
not a TLV Element and has no Tag, Value or Source. Absolute paths begin there.
The default relative context is that same virtual root. Streaming relative context can select a node by its zero-based preorder identity
using `tlv_query_exec_context` before feeding events. Absolute paths still use
the virtual root; Document handle contexts belong to the later Document backend.

**Q-NODE-02.** Tags are byte strings, compared without conversion to host
integers. Wildcard `*` includes absent and explicitly empty identifiers;
`??` consumes exactly one byte. Tag masks have equal pattern/mask widths,
require the same node tag width, and compare `(tag & mask) == (pattern & mask)`.
`tag-range(low, high)` uses inclusive unsigned-byte lexicographic order, with
the shorter prefix sorting first. Reversed bounds are invalid.

**Q-NODE-03.** Node identity is its traversal ordinal within one execution,
independent of tag, Source offset or Value equality. Results contain each node
at most once, in document preorder. Source offsets are optional metadata,
never identity. In the S0 callback surface, matching the same event through
multiple union branches produces one callback.

**Q-CONTEXT-01.** Predicates evaluate against the candidate node. Chained
predicates operate sequentially on the preceding selection. Positional
predicates use a one-based position; reverse-axis positional context uses axis
order before the final result is normalized to document order. Consequently
`//5A[1]` selects first matching children in their respective contexts whereas
`(//5A)[1]` selects the first node in the complete descendant selection.

**Q-CONTEXT-02.** F1 supports ancestor tests inside predicates as evidence
about the current node, never as ancestor projection. Node-returning ancestor
or parent axes require a later plan. Ancestor predicates with their own filters
and absolute paths nested inside a relative path are rejected in F1.
Execution starts at the whole root sequence and can select a relative context
by preorder identity; it does not reinterpret an interior Reader cursor as a root.

## Values, functions and unavailable metadata

**Q-VALUE-01.** Full-language result categories are ordered node sequences,
booleans, signed 64-bit integers, bytes and UTF-8 strings. Date conversion
produces signed UTC Unix seconds; precision/timezone conversion must be
explicit in the codec environment. No implicit string/bytes coercion exists.
Scalar conversion from a node sequence requires exactly one node; empty or
multiple nodes cause a cardinality diagnostic. `exists`, `empty` and `count`
accept node sequences without that restriction.

**Q-VALUE-02.** `value()` borrows the candidate's complete Value. Byte equality
and ordering compare bytes. `starts-with`, `ends-with`, `contains` and `substr`
operate on bytes; `substr` uses zero-based start and optional byte count,
clamping the requested span to the available bytes. Empty patterns match.
F1 `contains` accepts a compiled byte-literal pattern and uses caller-owned
prefix workspace. Runtime variable pattern sizing belongs to F2. No operation
extends a borrowed Value's lifetime.

**Q-VALUE-03.** `@len` is logical Value bytes; `@depth` is zero for roots;
`@index` is the zero-based sibling ordinal including nonmatching nodes.
`@offset` is the absolute original node start; `@hlen` is Source Header bytes,
not Tag plus Length by protocol assumption. Missing Source metadata causes an
unavailable-property diagnostic. Offset zero is a valid sourced position.
Source-less custom events and newly edited Document nodes must not fabricate it.

**Q-FUNCTION-01.** The closed function inventory is `count`, `exists`, `empty`,
`not`, `position`, `last`, `value`, `len`, `starts-with`, `ends-with`, `contains`,
`substr`, `num`, `bcd`, `text`, `date`, `tag`, `class`, `constructed`, `number`,
`name`, `tag-range`, and `tag-mask`. Arity and operand types are checked before
input consumption for implemented functions. Unknown functions are unsupported
capabilities, not arbitrary executable hooks. Conversion/Format capabilities
use the explicit future execution environment, not protocol knowledge in Query.

**Q-FUNCTION-02.** F1 implements node results, metadata comparisons, eager
boolean composition, byte functions, and tag tests. Both operands of `and` and
`or` are evaluated, so neither suppresses Source/type/resource errors. Full
typed conversions, variables, general scalar results and set intersection or
difference remain later-phase capabilities. Parsing a recognized later feature
must not partially execute it as a V1 path.
F1 metadata integer operands are nonnegative 64-bit values. Negative literals
are recognized but require the later signed scalar implementation.

## Storage and execution

**Q-STORAGE-01.** Compiler scratch, program and execution workspace have
independent size/alignment discovery. Compilation performs no internal heap
allocation or C call-stack recursion. The immutable program copies Query text
and uses internal indices/relative offsets, never process pointers. It can be
copied to aligned storage and shared across independent execution workspaces.
There is no cross-release serialized image compatibility promise or untrusted
image loader in F1. F5 validates external program images before execution.
Workspace initialization and formatting check alignment, image/version markers,
redundant extent, root and backward node references, and text spans. These checks
detect inconsistent internal images; pointer-only APIs still require the complete
readable compiler-produced allocation and cannot validate arbitrary external bytes.
The program must remain unchanged throughout execution; feed does not revalidate it.

**Q-STORAGE-02.** Compile-time name resolution and execution-time hooks have
different lifetimes. Copying the program cannot make external callbacks or
Format contexts self-contained. The F1 API rejects symbolic/hook capabilities;
their explicit environment is introduced by F2. Repeating sizing/compile with
the same bounded text/options yields identical requirements and output.

**Q-PLAN-01.** Execution levels apply to whole expressions: S0 decides at
complete node publication; S1 retains bounded depth summaries for scope evidence;
S2 requires explicit candidate capacity; D performs Document navigation with
work bounds. Ordered unions involving undecided ancestors can force S2/D even
if their individual branches appear S1. `//70[not(5A)] | //9F02` cannot promise
an unbuffered S1 ordered output. F1 rejects non-S0 capabilities before traversal.

**Q-LIMIT-01.** Defaults bound text, tokens, syntactic nesting and states.
Runtime depth, element count and work are caller parameters. Exact total runtime
storage depends on both the program and depth capacity, not Query text alone.
Every named resource failure reports its configured value. Internal program
offsets fit 32 bits; all native sizing arithmetic is checked before writes.

**Q-EVENT-01.** Query reuses BEGIN/ELEMENT/END. BEGIN and ELEMENT have complete
contiguous Values; END closes a matching depth and retains no parent payload.
Empty containers are BEGIN then END. Final Reader EOF completes the virtual
root; it is distinct from NEED_MORE_DATA and an END event. Custom events must
be balanced and have valid complete spans. Query does not reparse bytes or
construct a Document.

**Q-EVENT-02.** NEED_MORE_DATA publishes no partial event. Callback STOP consumes
the matching event exactly once; retaining execution and Reader permits resume.
Replacement input obeys the Reader frontier and unfinished-extent retention
rules. Execution retains only boolean state and sibling indices, not borrowed
Element/Source/Value pointers. A non-resumable error invalidates execution until
reset; parse/compile failures preserve existing outputs as documented in headers.

**Q-VALIDATE-01.** Default success at EOF means full structural traversal of
the requested input extent. An explicit callback STOP is partial coverage until
resumed to EOF. Finding a first match does not validate the remaining suffix.
F1 rejects skipped END events under the default policy.
`tlv_query_exec_pruning` explicitly permits proven exhausted forward-child
subtrees to be omitted; descendant plans and selected relative contexts are
conservatively drained. `tlv_query_exec_info` reports skipped extents and final
coverage. Pruning requires a proof that omitted descendants are irrelevant;
it must never silently hide unmatched malformed input. This is not automatic
Schema validation or DER semantic validation.

**Q-COST-01.** Frontend lexical/parsing work is linear in text/tokens, with
bounded explicit stacks. Semantic guard annotation can cost O(states squared)
for nested expressions, bounded by the compile state limit. Fixed S0 event work depends on program state count,
tag bytes and inspected Value bytes. Runtime workspace is O(states × depth)
plus explicit pattern-prefix scratch. `contains` costs O(Value + pattern);
other byte primitives charge inspected bytes. Constructed Values overlap, so
repeated scans may cost input bytes × depth. Work limits bound all executions;
later global Document axes must publish their own bounds rather than a universal
O(n) claim. Wrapper or Document ownership allocation is outside the C Query
allocation-free boundary.
