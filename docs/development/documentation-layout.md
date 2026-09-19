# Where documentation belongs

Each page lives in exactly one section of [docs/](../README.md). Choose its
section by the page's primary purpose, and link to related material elsewhere.

| Section | Put here | Example |
| --- | --- | --- |
| `getting-started/` | Introductory material: install, build, first program | [Getting started](../getting-started/README.md) |
| `concepts/` | Explanations of how and why the library works | [Architecture](../concepts/architecture.md) |
| `guides/` | Task-oriented how-tos for one job | [Memory ownership](../guides/memory.md) |
| `formats/` | Wire formats and their reading, writing and byte examples | [Formats](../formats/README.md) |
| `profiles/` | Standards or industry semantics layered on a format | [DER](../profiles/der/README.md) |
| `cli/` | Command-line tools, one page per tool | [otlv](../cli/README.md) |
| `reference/` | Lookup material: API manuals, option tables, support matrices | [C API](../reference/c-api.md), [Compilers](../reference/compilers.md) |
| `development/` | Contributor material: tooling, fuzzing, docs conventions | [Fuzzing](fuzzing.md) |

## Section boundaries

`concepts/` explains a model or design decision; `guides/` shows how to complete
a task; `reference/` provides exact contracts, syntax, options and limits for
lookup. A guide should link to the relevant concept or reference instead of
copying it. Introductory build and first-program instructions belong in
`getting-started/`; contributor workflows belong in `development/`.

`formats/` describes wire encoding, identifier and length framing, format
callbacks and byte examples. `profiles/` describes validation rules, semantics
and the limits of implemented support built on those formats. For example,
the DER and CER format pages describe their framing, while their profile pages
describe recursive and value validation. DER and CER are sibling BER profiles;
EMV is a profile over BER-TLV. Cross-link these pages rather than duplicating
their contracts or implying complete protocol support.

## Generated API reference

The C and C++ API references are generated with Doxygen and embedded in the
site under `reference/api/` at build time; they are never committed. The
hand-written pages [c-api.md](../reference/c-api.md) and
[cxx-api.md](../reference/cxx-api.md) are their entry points in the navigation.
Guides and concepts link to those pages (and to their per-area sections) rather
than into the generated files, which do not exist in the repository. Generated
pages link back to the guides through the `@docs` Doxygen alias. Generate the
references before `mkdocs build`; see
[CONTRIBUTING.md](../../CONTRIBUTING.md#generate-the-c-api-reference).

## Versioned documentation

The site is published per release: `latest` is the development documentation
built from `develop`, and each released `X.Y` is built from its release tag and
stays available after later releases. Write pages for the current sources; do
not copy the documentation tree or add version-specific pages by hand. Links
that leave `docs/` point at the source of the same version. See
[CONTRIBUTING.md](../../CONTRIBUTING.md#publishing) for how versions are
published.

## Executable examples

Important examples (introductory C and C++ usage) are compiled sources under
`examples/`, not Markdown-only snippets. Place `<!-- example: examples/PATH -->`
directly above a fenced block to embed a source file verbatim; run
`python scripts/check_doc_examples.py --fix` to refresh the copy. CI fails when a
block differs from its source or the source no longer builds. Small illustrative
fragments may stay inline.

## Adding new topics

- **OTDL**: the planned definition language's syntax and specification belong
  in `reference/otdl/`, its model in `concepts/`, task-oriented usage in
  `guides/`, and tool commands in `cli/`. A definition language is distinct
  from the wire formats it describes; those remain in `formats/`.
- **Language bindings**: one directory per binding under `reference/bindings/`,
  for example `reference/bindings/<language>/`, with task-oriented usage in
  `guides/`.
- **Additional tooling**: a page or directory per tool in `cli/`; contributor
  tooling in `development/`.
- **New formats and profiles**: a directory under `formats/` or `profiles/`
  with a `README.md`, as the existing ones do.

Create these pages and directories when content is available; this layout
does not require placeholder pages or new OTDL, binding or tool documentation.

## Rules

- Give a section or topic a `README.md` when it needs an overview; a directory
  used only to group pages does not need a placeholder index.
- Add every new page to the `nav` in [mkdocs.yml](../../mkdocs.yml). Keep the
  GitHub index [docs/README.md](../README.md), site landing page
  [docs/index.md](../index.md), and project [README.md](../../README.md)
  aligned with the sections and entry points they describe. The GitHub index
  may link to an overview that leads to individual topic pages.
- When moving a page, update inbound links throughout the repository,
  including contributor documentation, examples and test documentation.
  Preserve heading anchors where possible and update fragment links when
  headings change.
- Run `mkdocs build --strict` to check site pages and anchors. Also check
  repository-relative links outside the site: the site build does not validate
  their targets after the hook rewrites them to GitHub URLs.
- Keep reorganizations limited to moves, navigation, link updates and minimal
  introductory text. Compare each moved page with its original to ensure
  technical content and examples are preserved.

## Migration for issue #186

The following paths are relative to `docs/`. Existing pages under `formats/`
and `profiles/` retain their paths unless listed here.

| Previous path | Current path |
| --- | --- |
| `getting-started.md` | [getting-started/README.md](../getting-started/README.md) |
| `architecture.md` | [concepts/architecture.md](../concepts/architecture.md) |
| `core-types.md` | [concepts/core-types.md](../concepts/core-types.md) |
| `value.md` | [concepts/value.md](../concepts/value.md) |
| `length.md` | [concepts/length.md](../concepts/length.md) |
| `endian.md` | [concepts/endian.md](../concepts/endian.md) |
| `memory.md` | [guides/memory.md](../guides/memory.md) |
| `schemas.md` | [guides/schemas.md](../guides/schemas.md) |
| `codecs.md` | [guides/codecs.md](../guides/codecs.md) |
| `copy.md` | [guides/copy.md](../guides/copy.md) |
| `scanner.md` | [guides/scanner.md](../guides/scanner.md) |
| `format-examples.md` | [formats/format-examples.md](../formats/format-examples.md) |
| `format-roadmap.md` | [formats/format-roadmap.md](../formats/format-roadmap.md) |
| `cli.md` | [cli/README.md](../cli/README.md) |
| `compilers.md` | [reference/compilers.md](../reference/compilers.md) |
| `fuzzing.md` | [development/fuzzing.md](fuzzing.md) |

This migration updates repository links but does not add redirects or retain
stub pages at old source paths. External links and bookmarks to moved source
pages must be updated using the table above. Published site URLs also change
when a page's output path changes; for example, `architecture/` becomes
`concepts/architecture/`. Moves from `cli.md` to `cli/README.md` and from
`getting-started.md` to `getting-started/README.md` keep their existing site
URLs with the current MkDocs directory-URL configuration. Old links to
unchanged site URLs and preserved heading anchors continue to work.
