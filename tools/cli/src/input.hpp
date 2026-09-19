#ifndef OPENTLV_CLI_INPUT_HPP
#define OPENTLV_CLI_INPUT_HPP
#include <cstddef>
#include <cstdint>
#include <vector>
#include "options.hpp"

namespace cli {

// Decodes hex text (contiguous bytes or whitespace between complete pairs)
// and appends the bytes to `data`. Returns 0, 2 for malformed hex, or 3 when
// more than `limit` bytes would be produced.
int decode_hex(const char* text, std::size_t limit, std::vector<uint8_t>& data);

// Loads command input per options: from a file, from stdin, or by decoding
// --hex, applying --input-encoding when reading from a stream. Appends the
// decoded bytes to `data` (left empty on entry by convention, not cleared
// here). Returns 0 on success or a CLI exit code (see diagnostics.hpp) on
// failure; on failure `data` may still hold a partial result.
int read_input(const options& o, std::vector<uint8_t>& data);

} // namespace cli
#endif
