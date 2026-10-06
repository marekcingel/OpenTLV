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
union       = disjunction, { "|", disjunction } ;
disjunction = conjunction, { "or", conjunction } ;
conjunction = comparison, { "and", comparison } ;
comparison  = intersection, [ ("=" | "!=" | "<" | "<=" | ">" | ">="), intersection ] ;
intersection = path, { ("intersect" | "except"), path } ;
path        = [ "/" | "//" ], filtered, { ("/" | "//"), filtered } ;
filtered    = primary, { "[", expression, "]" } ;
primary     = step | metadata | variable | integer | bytes | string | "true" | "false"
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
high as the productions above. `intersect` and `except` bind more strongly
than `|`; both are left associative. Thus `A | B except C` means
`A | (B except C)`. Comparisons do not chain. A function's commas
separate arguments, not top-level expressions. Predicates bind to the preceding
primary before path composition. `//` abbreviates descendant navigation from
the preceding context. A path step `50` is a raw hexadecimal tag; a numeric
comparison operand `10` is decimal. A direct predicate `[10]` is positional.
An explicit axis such as `[child::50]` always denotes a raw tag test, including
when whitespace follows `::`; it never becomes a positional or scalar literal.
Bare even hex-looking identifiers such as `CAFE` are raw tags; names use a
namespace, including `emv:CAFE`. For symbols outside identifier syntax, the
`name(namespace, symbol)` function supplies string arguments. Odd raw
hexadecimal spellings such as `BAD` cannot silently become a truncated tag.

## Node model, order and context

**Q-NODE-01.** The virtual document root owns the ordered root sequence. It is
not a TLV Element and has no Tag, Value or Source. Absolute paths begin there.
The default relative context is that same virtual root. Streaming relative context can select a node by its zero-based preorder identity
using `tlv_query_exec_context` before feeding events. Absolute paths still use
the virtual root; Document execution selects a live node handle with `tlv_document_query_evaluate`.

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

**Q-CONTEXT-02.** S0 supports ancestor tests inside predicates as evidence.
Retained F2 also evaluates filtered ancestor sequences, using nearest-ancestor
position first and normalizing published results to document order. F3 implements parent, ancestor-or-self, descendant-or-self, sibling and global
axes and nested absolute expressions. Reverse-axis predicates use nearest-first
axis order; parentheses normalize the selected sequence before a global predicate.
Following excludes the context's descendants; preceding excludes its ancestors.
The virtual root is navigable with `..`, but never published as a TLV result.
Explicit tag tests, including `parent::*`, test concrete nodes only. Execution starts at the whole root sequence and can select a
relative context by preorder identity; it does not reinterpret an interior
Reader cursor as a root.

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
`contains` accepts literal, variable and expression patterns and uses caller-owned
prefix workspace. Patterns are bounded by compile option `max_pattern` (literal overflow is rejected
at compilation, runtime overflow at evaluation);
program info reports the prefix capacity in `pattern_bytes`. A pattern exceeding
that capacity reports a pattern limit, including when it exceeds the haystack. No operation
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
use the explicit execution environment, not protocol knowledge in Query.

**Q-FUNCTION-02.** F2 implements all five result categories, the closed function
inventory, metadata comparisons, eager boolean composition and tag tests. Both operands of `and` and
`or` are evaluated, so neither suppresses Source/type/resource errors. Typed
conversions decode complete Values through the compatible execution environment.
S0 union, intersection and difference combine decisions for the same published
node identity, preserving source order and eliminating duplicate matches without
retaining a node set. An operand requiring deferred evidence still makes the
whole expression unavailable to S0. Parsing a recognized later feature
must not partially execute it as a V1 path.
Integer operands use signed 64-bit limits, including `-9223372036854775808`.
No arithmetic syntax or implicit conversion is introduced. Metadata and lengths
above `INT64_MAX` report overflow. Negative substring starts or lengths report
an invalid value; nonnegative spans are clamped as specified by Q-VALUE-02.

**Q-BINDING-01.** Compile options declare integer, bytes and UTF-8 string
variables by name without `$`. The compiler validates operand types against
these declarations and copies the Query text. Declaration storage is borrowed
only during compilation. Duplicate declarations and undeclared references are
errors. Variable identifiers start with an ASCII letter and continue with
letters, digits, underscore or hyphen; `$min-1` is one name, not arithmetic.
The program retains only referenced variables, with one binding slot per unique
name. Unused declarations remain compile-environment data. Enumerate requirements
with `tlv_query_program_variable_count` and `tlv_query_program_variable`; names
are borrowed bounded spans in first-reference order. Binding unused declarations
is an unknown-variable error. `tlv_query_exec_bind` binds each referenced name exactly once before
any event; missing, unknown, duplicate and incompatible bindings are errors.
All referenced variables are required even if no candidate matches or input
is empty. Byte spans may contain embedded NUL and Query-like text; bindings
never pass through the lexer. Strings are validated UTF-8 and remain distinct
from bytes. Values are borrowed unchanged through execution, including suspension;
callers needing a copy provide their own stable storage. Reinitialization clears
bindings. Rebinding after an event, including STOP/NEED_MORE_DATA suspension,
is rejected. Independent executions can bind different values to one program.
Runtime-pattern `contains` uses the explicit compiled capacity; string literals
are copied into immutable program storage.

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
Format contexts self-contained. F2 copies resolved tag bytes into the program;
resolver/Definition storage is needed only while compiling. Providers, their
contexts and the Format remain borrowed throughout execution and suspension. Repeating sizing/compile with
the same bounded text/options yields identical requirements and output.
For checked two-pass compilation, discover workspace with
`tlv_query_compile_prepare_size`, compile once with `tlv_query_compile_prepare`,
then publish with `tlv_query_compile_commit`. Preparation reports exact final
program size and retains a complete immutable image in caller workspace. Commit
uses explicitly sized validation scratch from `tlv_query_program_load_scratch`,
re-resolves names and compares every program byte before writing final storage.
Changes to same-length identifiers are rejected, preserving output storage and
info. The independent low-level `tlv_query_compile` calls retain their original
stable-callback precondition; owning language constructors use checked compilation.

Canonical formatting may add whitespace. Rediscover compilation scratch for the
formatted text; the original text's exact scratch capacity need not suffice.

**Q-PLAN-01.** Execution levels apply to whole expressions: S0 decides at
complete node publication; S1 retains bounded depth summaries for scope evidence;
S2 requires explicit candidate capacity; D performs Document navigation with
work bounds. Ordered unions involving undecided ancestors can force S2/D even
if their individual branches appear S1. `//70[not(5A)] | //9F02` cannot promise
an unbuffered S1 ordered output. Use `tlv_query_exec_size/init` for S0/S1, and `tlv_query_eval_size/init` for S2
or Document execution. S0 also proves unfiltered preceding-sibling existence
inside local predicates with per-depth evidence, without retaining past nodes.
History projections and filtered sibling evidence use S2.

The proven S1 subset is one root tag selection with one predicate composed of
child/descendant tests, `not`, `exists`, `empty`, `count`, integer/boolean literals,
comparisons and eager boolean operators. For example, `70[not(5A)]`,
`A5[child::88]`, and `70[count(descendant::5A)>1]` decide at their END.
Selected root scopes cannot overlap, so scope completion also preserves preorder.
Nested selection contexts, unions, last-dependent predicates, projections and
other compositions conservatively use S2; no input-dependent queue is labelled S1.
`[88]` remains the decimal positional predicate, including after `A5`.
S1 primitive roots decide at publication because they have no children.
Empty constructed roots decide at END; EOF completes the virtual root.
Program info exposes decision timing, frame state slots, candidate descriptor
size/alignment and stable-input requirements. Source offsets never determine order.
These labels describe storage and decision timing for the complete expression,
not different language versions. A publication frontier is the earliest point
when a result can be delivered without a later decision changing its order.
F3 is the implementation milestone for deferred/Document execution, not an API mode.

S2 retains every published node in caller-sized descriptors and uses explicit
bounded VM node sets as its ordered frontier. An earlier unresolved selection
prevents any callback until balanced final EOF and successful evaluation. The
virtual root's completion deterministically releases ordered unique results;
STOP resumes the finalized cursor. Candidate capacity includes nonmatching nodes.
Overflow reports `candidates`, invalidates execution until reset and emits no
new callbacks. Previously emitted callbacks from other execution profiles are
never rolled back. Descriptors borrow complete spans; there is no hidden payload
copy or source recovery from offsets. All source and Format storage must remain
alive and immutable until reset, including across Reader window replacement.
This stable-input contract is independent of descriptor/workspace capacity.

D is reserved for global `preceding`/`following` navigation. Event feed and
Reader visit reject D before consuming input, including on empty input.
`tlv_document_query_evaluate` consumes the same program and iterative VM,
using public Document navigation and preorder identity. Initialize its workspace
with `eval_size/init`; optionally supply a context handle in that Document.
`tlv_document_query_next` supplies first/all/pull iteration, and
`tlv_document_query_program_visit` supports STOP/resume. Scalars use
`tlv_query_exec_result`. The Document and execution storage are separate.

Program info reports `constructed_values_required`: a conservative flag covering
Value access, length metadata and conversion-adapter event metadata. Pure navigation,
tag tests and `count()` require neither a Value buffer nor Writer staging: pass
NULL/zero for both. Primitive Values then borrow owning nodes.

When Values may be inspected, encode the entire Document once into a caller-owned
snapshot; all node Values are slices of it. `tlv_document_query_value_size` discovers
the complete encoding size using caller-provided Tree Writer staging (frames,
output and closing scratch), without summing overlapping subtrees. Discovery output
may be reused as the final snapshot. Evaluation writes directly into that snapshot;
it needs only the staging frames and scratch, not a separate staging output.
Discovery reports Writer capacity requirements for explicit resize/replay; it never uses the owning Document allocator.
Snapshot ranges are obtained through the existing canonical Reader; the adapter
adds no parser and uses no owning Document allocation.
This reproduces current Document encoding semantics, including insertion/removal,
rather than historical noncanonical wire spellings. Immutable canonical inputs
have equivalent streaming/Document results and types. With optional Document
source-location retention enabled, `@offset`/`@hlen` also agree with Reader
metadata for unchanged parsed nodes, including D-level navigation. These are
original input coordinates, not offsets in the canonical snapshot. Replacement
invalidates the edited node and ancestors; insertion/erasure invalidates ancestors.
Inserted/replacement nodes have no origin, and failed edits preserve metadata.
Missing or invalidated properties report Source diagnostics instead of fabricated
locations. Other failures include a retained source offset when available. A foreign
context or used execution is rejected. Document/Value storage must remain alive
and unchanged during iteration and callbacks.

**Q-LIMIT-01.** Defaults bound text, tokens, syntactic nesting and states.
Runtime depth, element count and work are caller parameters. Exact total runtime
storage depends on both the program and depth capacity, not Query text alone.
Every named resource failure reports its configured value. Internal program
offsets fit 32 bits; all native sizing arithmetic is checked before writes.

**Q-EVENT-01.** Query reuses BEGIN/ELEMENT/END. BEGIN and ELEMENT have complete
contiguous Values; END closes a matching depth and retains no parent payload.
Empty containers are BEGIN then END. Final Reader EOF completes the virtual
root; it is distinct from NEED_MORE_DATA and an END event. Custom events must
be balanced and have valid complete spans. The shared VM consumes events without
reparsing bytes or constructing a Document; its optional Document adapter uses
the canonical Reader to obtain Value ranges from the encoded snapshot.

**Q-EVENT-02.** NEED_MORE_DATA publishes no partial event. Callback STOP consumes
the matching event exactly once; retaining execution and Reader permits resume.
Replacement input obeys the Reader frontier and unfinished-extent retention
rules. S0 retains boolean state and sibling indices. S1 borrows one root's
complete metadata until its END, requiring stable storage throughout that scope;
raw feed retrieves a matched original BEGIN with `tlv_query_exec_selected`.
Retained evaluation also stores
borrowed Element/Source/Value pointers until reset; every published input span
must remain immutable and alive, even after the Reader frontier moves. A non-resumable error invalidates execution until
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
Retained feed builds parent/end indexes in O(nodes) with an explicit depth stack.
The shared VM uses O(states ? nodes + depth ? states) caller storage. It can scan
nodes for each selected context; arbitrary nested paths can be superlinear.
Document snapshot storage is O(encoded Document bytes), with each Value borrowing
a range rather than owning another subtree copy. A needed snapshot is encoded once
and decoded for node ranges. The existing generic Tree Writer can still copy bytes
at each ancestor: worst-case encoding costs O(bytes × depth); content-dependent
Formats preclude a universal linear-time claim. Discovery is outside execution.
Evaluation charges events, actual Value bytes processed by Writer sizing/copying/
encoding, decoded element extents, node scans and VM set operations. Spare staging,
scratch or snapshot capacity does not change work consumption. Programs without
constructed Value dependencies skip the entire encoding/decoding pass. Wrapper or Document ownership allocation is outside the C Query
allocation-free boundary.

**Q-ABI-01.** Compile options require the current `struct_size`. Program info
and execution info accept caller-sized output prefixes: callers set `struct_size`
to their writable extent, and writes cover at most the smaller of that extent
and the current structure. Program info requires the prefix through `result_kind`;
execution info requires the prefix through `elements`. The supplied extent and
unknown trailing bytes are preserved. Zero/undersized extents are rejected.
Callers predating this contract must rebuild; this cannot retroactively protect
an old ABI. Diagnostic, variable declaration and variable requirement structures
are fixed-layout value types; layout changes require an ABI change. Opaque program
and execution objects continue to use independent size/alignment discovery.
`expression_values` is the conservative intermediate-slot count and `instructions`
is the immutable expression instruction count; retained execution can revisit
instructions for distinct contexts and charges each evaluation to its work limit; byte
scanning and callback costs are separate. `variable_slots` counts unique bindings.

**Q-IMAGE-01.** External images enter through `tlv_query_program_load` with their
exact readable extent. Pointer-only APIs require compiler-owned or already
validated images. Discovery reads a copied fixed header and bounded text only;
loading reconstructs the image with the bounded compiler and compares every byte,
including types, constants, indices, guards, optimization and capability fields.
The original compile options, typed declarations, deterministic resolver and
compatible environment are required. A checksum cannot replace validation.

Internal image version 5 uses native-endian uint32 fields, relative offsets and
no pointers. Wrong version/byte order returns UNSUPPORTED_TYPE and IMAGE_VERSION
diagnostics before node access. No cross-release serialized-IR compatibility is
promised. Same-endian 32/64-bit sharing requires matching private layout and
environment contracts; reconstruction checks compatibility. Aligned immutable
images may reside in ROM. Validation scratch is separate, writable, caller-owned
and explicitly sized/aligned by `program_load_scratch`. Validation performs no
image writes, internal allocation or production recursion; its cost includes
bounded compilation. Instruction dependencies refer to earlier instructions and
the evaluator uses explicit bounded frames.

Tag-mask and tag-range functions select relative children, including in
predicates. `//70[tag-mask(x'5A', x'FF')]` selects containers having a matching
child; it does not test the candidate's own identifier. Predicate use requires S2
storage, reported by compile info. Release evidence is tracked by the
[Query release checklist](../development/query-release.md).

## F2 functions and providers

The following signatures are closed and checked at compilation. `nodes` denotes
an ordered node sequence and `bytes` and `string` remain distinct types.

| Function | Result and operands |
| --- | --- |
| `count(nodes)`, `exists(nodes)`, `empty(nodes)` | Integer, boolean, boolean; no cardinality restriction |
| `not(boolean-or-nodes)` | Boolean; node truth is nonempty |
| `position()`, `last()` | One-based position and size of the current predicate sequence |
| `value()` / `value(nodes)` | Complete borrowed Value bytes; exactly one real node |
| `len()` / `len(bytes-or-string)` | Candidate Value length / byte length |
| `starts-with(bytes, bytes)`, `ends-with(bytes, bytes)`, `contains(bytes, bytes)` | Boolean; byte matching, including NUL |
| `substr(bytes, integer[, integer])` | Borrowed byte subspan; zero-based start |
| `num(bytes-or-nodes)`, `bcd(bytes-or-nodes)`, `date(bytes-or-nodes)` | Signed int64; node arguments require exactly one node |
| `text(bytes-or-nodes)` | Validated UTF-8 string; exactly one node for node arguments |
| `tag()` / `tag(nodes)` | Raw canonical identifier bytes |
| `class()` / `class(nodes)`, `number()` / `number(nodes)` | Provider-defined semantic tag components as int64 |
| `constructed()` / `constructed(nodes)` | Format-defined constructed status |
| `name(string, string)` | Compile-time namespace/symbol selection with copied tag bytes |
| `tag-mask(bytes, bytes)`, `tag-range(bytes, bytes)` | Node tests; masks have equal widths and range endpoints are ordered |

Each chained predicate receives the sequence surviving its preceding predicate.
`//5A[2]` selects the second matching child at each descendant context;
`(//5A)[2]` selects the second node of the combined ordered result.
An integer predicate compares its value to the current one-based position.
Union/intersection/difference use node identity and emit each selected node once
in document order, including branches needing descendant or positional evidence.
No scalar is available until balanced EOF and successful evaluation. Retrieve it
with `tlv_query_exec_result`; pull node events with `tlv_query_result_next` or use
the resumable visitor. A retained visitor STOP occurs after full input validation
and resumes after the consumed selected node.

`tlv_query_definition_resolve` searches explicit Definition namespaces by exact
label and rejects unknown or ambiguous symbols. Definitions do not choose codecs.
`tlv_emv_query_resolve` uses native EMV Schema symbols, namespace `emv`, and the
explicit `PAN` alias for `pan`. Bare hex-looking symbols require a namespace or
`name('emv', 'symbol')` to distinguish them from raw tags. Compiled programs contain
no resolver pointers and need no execution-time dictionary lookup.

Compile options reference a `tlv_query_environment_t` for conversion capability
selection. The program stores stable nonzero IDs and per-call scratch requirements;
execution initialization checks IDs, function/result roles, scratch bounds and tag
capabilities before consuming input. The visitor also requires the same Format
object as the environment. All borrowed providers and contexts must be immutable
and safe for concurrent independent executions. Caller workspaces supply aligned
codec scratch (up to 16-byte alignment), with a separate region for each conversion
instruction so sibling expression results remain valid. Callbacks perform no
implicit Query allocation; their own costs and allocation policy are external to
the VM work guarantee and must be bounded by the application.

`tlv_query_builtin_hooks` adapts existing codecs: minimal signed big-endian NUM,
unsigned packed BCD of at most 18 digits, and UTF-8 TEXT. Domain adapters may replace
these explicit choices with other existing codecs and distinct capability IDs.
`tlv_asn1_query_tags` supplies BER/ASN.1 class and number; raw `tag()` always keeps
canonical identifier identity. Flat formats need an explicit semantic provider for
class/number. `constructed()` independently delegates to Format.
`tlv_asn1_query_date` accepts complete nonfractional UTC GeneralizedTime, validates
the Gregorian calendar and returns signed Unix seconds; unsupported precision or
timezone forms fail rather than silently losing information. Date values outside
1970 are valid when representable. Codec failures preserve their original status
in `diagnostic.codec` together with the Query span and sourced node offset.

Retained workspace is O(instructions ? (depth + node capacity)) plus retained
events, explicit pattern workspace, evaluation frames and per-instruction codec
scratch. Evaluation is iterative with validated backward child references, bounded
frames and no recursive C evaluation. Every frame dispatch, membership scan,
retention search and byte operation consumes the configured work budget. Exhausted
node/depth/work/pattern budgets fail; there is no hidden allocation or fallback.

`optimize=0` disables conservative rewrites. The enabled optimizer folds pure
constant comparisons/boolean pairs, simplifies terminal self steps and shares
identical guarded S0 tag selectors. It never folds a codec, drops a fallible
operand, or reorders eager boolean evaluation. `tlv_query_program_explain` reports
instruction kinds, types, whole-plan level, reused selectors and capability IDs;
program info reports optimized states and expression stack capacity. The independent
corpus compares optimized/unoptimized S0 and retained execution. These rewrites do
not imply global index planning or a universal linear-time execution guarantee.
