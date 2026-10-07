# C++ API reference

The C++ API reference is generated from the public
[tlv++](../../tlv++/include/tlv++) headers with Doxygen and published with this
site. Open the [generated C++ API reference](api/cxx-api/html/index.html) for
the `tlv` namespace, classes and public headers. Include `tlv++/tlv.hpp` for
the complete configured header-only C++ API; using it still requires linking the C
library.

The [C++ public/native boundary](../concepts/cxx-native-boundary.md) describes
the current public facade, borrowed `tlv::format` views and explicit native
interoperability. Include `tlv++/native.hpp` separately for that interoperability API.
The [Format customization contract](../concepts/cxx-formats.md) defines application
Formats, traits, capability checks and shared adapters for higher-level consumers.
The [typed field and Value codec guide](../guides/codecs.md#c11-typed-fields-and-value-codecs)
describes C++11 field definitions, codec customization, typed lookup and writing.
The [built-in standards guide](../concepts/cxx-builtins.md) covers domain namespaces,
framing conveniences, shared ASN.1 codecs and standard-specific typed fields.

The `<tlv++/generator.hpp>` facade exposes `tlv::generate()`,
`generator_workspace_size()` and `make_generator_candidate()` using borrowed
Formats and caller-owned byte spans. See the
[deterministic wire generation contract](c-api.md#deterministic-wire-generation)
for limits, reproducibility, workspace and candidate-domain rules.

`tlv::generator` copies the options and manages reusable scratch storage.
`generate(case_index)` returns `expected<std::vector<tlv::byte>, tlv::error>`;
each successful result owns its bytes and survives later calls and generator
destruction. The case index argument overrides `options.case_index`, and call
order does not affect output. Initialize options with `{}` and supply the limits
and candidate domain explicitly. Format descriptor/context, candidate table and
identifier bytes remain borrowed and must stay alive and unchanged. Import a
native C Format explicitly with `tlv::native::borrow_format()`.

Native validation and generation failures use `expected`; C++ storage allocation
can throw `std::bad_alloc` or `std::length_error`, as with other owning C++ APIs.
The native generator and caller-buffer facade remain allocation-free. Use
separate instances or external synchronization for concurrent generation.

The following C++11 example generates three independent cases without managing
output capacity or workspace:

<!-- example: examples/tlv++/src/generate.cpp -->
```cpp
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#include <tlv++/generator.hpp>
#include <tlv++/formats/fixed_format.hpp>
#include <iostream>

int main() {
    const tlv::byte identifier[] = {static_cast<tlv::byte>(1)};
    const auto      candidate =
        tlv::make_generator_candidate(tlv::tag(tlv::bytes{identifier, 1}), 0, 128);
    tlv::generator_options options{};
    options.seed = 42;
    options.max_elements = 10;
    options.max_depth = 0;
    options.max_value_size = 128;
    options.max_case_size = 512;
    options.candidates = &candidate;
    options.candidate_count = 1;
    tlv::generator generator(tlv::fixed_format<1, 2, tlv::byte_order::big_endian>{}, options);
    for (uint64_t index = 0; index < 3; ++index) {
        auto wire = generator.generate(index);
        if (!wire) {
            std::cerr << wire.error().message() << '\n';
            return 1;
        }
        std::cout << "Case " << index << ": " << wire->size() << " bytes\n";
    }
    return 0;
}
```

- [Namespace `tlv`](api/cxx-api/html/namespacetlv.html)
- [Class index](api/cxx-api/html/classes.html) and
  [class list](api/cxx-api/html/annotated.html)
- [Public header index](api/cxx-api/html/files.html)

C declarations that the wrappers use link to the [C API reference](c-api.md)
instead of being repeated. For the concepts behind the wrappers, read
[architecture](../concepts/architecture.md),
[memory ownership](../guides/memory.md#custom-descriptors-and-c) and the
[schema guide](../guides/schemas.md); the C++ layer's ownership and error
contracts are stated on each declaration.

To build the reference locally, see the
"Generate the C++ API reference" section of [CONTRIBUTING.md](../../CONTRIBUTING.md).
The generated pages exist only in a built site or in the Documentation
workflow artifacts, so the direct links above do not resolve when this page is
read on GitHub.
