# Follow-up: reuse indefinite element boundaries

Status: proposed future work, recorded separately from the bounded decode
optimization in [#538](https://github.com/marekcingel/OpenTLV/issues/538).
No boundary reuse or new traversal API is implemented by that change.

## Motivation and existing behavior

The profiling example reported in #538 contains 200 roots, each with
32 constructed ancestors and one primitive leaf: 6,600 published elements
produce 112,200 identifier reads. These are the issue's reported counts,
not a new measurement made for this follow-up.

The current BER bounds resolver in `tlv/src/builtins/asn1/ber.c` calls
`tlv_ber_scan_contents_diag()` to locate the matching EOC before publishing
an indefinite parent. Tree Reader later decodes each descendant through
the same Format contract. Indefinite descendants therefore resolve boundaries
already visited by an ancestor's scan. Increasing nesting repeats this work;
reducing generic per-decode overhead does not remove the repeated scans.

Investigate whether validated boundary information can be reused during
traversal. Keep BER EOC recognition in ASN.1 Format code; any shared mechanism
must describe generic validated element extents without builtin dispatch in
Reader. Compare the cost and storage requirements before selecting a design.

## Contracts to preserve

The [Format contract](../concepts/format-contract.md) and public Reader headers
remain authoritative. In particular:

- Publish a parent only after its complete encoded extent is contiguous and
  validated. Preserve complete Element/Source results and canonical BEGIN,
  ELEMENT and END events; do not introduce early partial-parent publication.
- Incomplete non-final root input returns `TLV_NEED_MORE_DATA`; final truncation
  and malformed framing retain their existing error codes and diagnostics.
  Appending input cannot repair a child outside its complete parent's Value.
- Failed reads preserve caller outputs, cursor state and traversal frames.
  Preserve limits, subtree skipping, absolute offsets and END ordering.
- Input, Format configuration and all storage borrowed by retained results
  remain alive and immutable. Replacing or relocating an input window never
  relocates earlier views; callers release those views before reusing storage.
- Keep parsing allocation-free. Any additional workspace needs explicit sizing,
  ownership, lifetime, exhaustion and reset/reinitialization behavior.

## Acceptance criteria for a separate implementation

1. Reproduce the reported deep-indefinite workload with documented instrumentation
   and establish local counts. Measure increasing depth and root count, mixed
   definite/indefinite nesting, shallow inputs and representative non-BER formats.
2. Demonstrate fewer repeated boundary scans and a repeatable Release throughput
   gain. Report Reader, Tree Reader and Document separately, including workspace
   cost and shallow-input regressions; distinguish timing from instrumented runs.
3. Specify how reused extents are tied to their input window and Format, survive
   valid appends/discards, and become invalid after replacement or reinitialization.
   Do not silently depend on pointer identity or mutable external configuration.
4. Compare complete results, source ranges, errors and diagnostic metadata with
   the existing decoder for valid inputs, every truncation boundary, malformed
   and missing EOC, bounded children, depth limits and incremental retries.
5. Verify subtree skipping, stable retained views, independent interleaved
   readers, workspace exhaustion and failed retries. Document any proposed
   API/ABI change explicitly; it requires its own review and compatibility plan.
