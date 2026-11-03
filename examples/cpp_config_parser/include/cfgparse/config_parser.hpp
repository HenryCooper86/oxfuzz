// cfgparse: a small INI-style configuration parser (C++17).
//
// Accepted syntax, one construct per line:
//
//   # comment            ; comment
//   [section]
//   key = bare value
//   key = "quoted value with \"escapes\" and \n"
//
// Keys are [A-Za-z0-9_.-]+. Entries before the first [section] header belong
// to the unnamed section "". Lines end at '\n'; surrounding whitespace
// (including '\r') is ignored.
//
// This is an oxfuzz example target with one deliberately planted bug; see
// README.md in this directory.
#ifndef CFGPARSE_CONFIG_PARSER_HPP
#define CFGPARSE_CONFIG_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cfgparse {

struct Entry {
    std::string section;
    std::string key;
    std::string value;
};

struct Config {
    std::vector<Entry> entries;

    // Returns the last value assigned to `key` in `section`, if any.
    std::optional<std::string> get(std::string_view section, std::string_view key) const;
};

struct ParseResult {
    bool ok = false;
    std::size_t error_line = 0;  // 1-based line of the first error when !ok
};

// Parses `size` bytes of configuration text at `data` into `out`. The input is
// not required to be NUL-terminated; the parser works on the raw byte range
// without copying it first.
ParseResult parse_config(const std::uint8_t *data, std::size_t size, Config &out);

}  // namespace cfgparse

#endif  // CFGPARSE_CONFIG_PARSER_HPP
