#ifndef OPENTLV_CLI_TAG_HPP
#define OPENTLV_CLI_TAG_HPP
#include "options.hpp"

namespace cli {
namespace commands {

// Runs the parsed "tag" command: decodes the hexadecimal BER tag, looks it up
// in the selected profile's dictionary (base context) and prints its metadata
// as text or JSON. An unknown tag is reported as a result with exit code 0;
// a malformed tag is a usage error (exit code 2).
int tag(const options& o);

// Runs the parsed "tags" command: lists every base-context dictionary entry of
// the selected profile, optionally filtered by a case-insensitive name
// substring (--search), in dictionary order, as text or JSON. An empty result
// is still success (exit code 0).
int tags(const options& o);

} // namespace commands
} // namespace cli
#endif
