#include "cfgparse/config_parser.hpp"

#include <cctype>
#include <cstring>

namespace cfgparse {
namespace {

bool is_space(char c) {
    return std::isspace(static_cast<unsigned char>(c)) != 0;
}

bool is_key_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '.' || c == '-';
}

const char *skip_space(const char *p, const char *end) {
    while (p < end && is_space(*p)) {
        ++p;
    }
    return p;
}

const char *trim_end(const char *begin, const char *end) {
    while (end > begin && is_space(end[-1])) {
        --end;
    }
    return end;
}

char unescape(char c) {
    switch (c) {
    case 'n':
        return '\n';
    case 't':
        return '\t';
    default:
        return c;  // covers \" and \\ as well
    }
}

// Reads a quoted value. `p` points just past the opening quote and `end` is
// one past the last byte of the line. Returns a pointer just past the closing
// quote, or nullptr when the value is unterminated.
//
// For every line except the last one, `*end` is the '\n' (or trailing
// whitespace) that ended the line, so reading it is harmless. On the last
// line of an input with no trailing newline, `end` is one past the end of the
// caller's buffer.
const char *read_quoted(const char *p, const char *end, std::string &out) {
    while (p <= end) {  // BUG: must be `p < end`; reads *end on an unterminated last line
        const char c = *p;
        if (c == '"') {
            return p + 1;
        }
        if (c == '\\' && p + 1 < end) {
            out.push_back(unescape(p[1]));
            p += 2;
            continue;
        }
        out.push_back(c);
        ++p;
    }
    return nullptr;
}

class LineParser {
public:
    explicit LineParser(Config &out) : out_(out) {}

    bool parse_line(const char *p, const char *end) {
        p = skip_space(p, end);
        end = trim_end(p, end);
        if (p == end || *p == '#' || *p == ';') {
            return true;
        }
        if (*p == '[') {
            return parse_section(p + 1, end);
        }
        return parse_assignment(p, end);
    }

private:
    bool parse_section(const char *p, const char *end) {
        if (end[-1] != ']') {
            return false;
        }
        const char *name_begin = skip_space(p, end - 1);
        const char *name_end = trim_end(name_begin, end - 1);
        for (const char *q = name_begin; q < name_end; ++q) {
            if (!is_key_char(*q)) {
                return false;
            }
        }
        section_.assign(name_begin, name_end);
        return true;
    }

    bool parse_assignment(const char *p, const char *end) {
        const void *eq_raw = std::memchr(p, '=', static_cast<std::size_t>(end - p));
        if (eq_raw == nullptr) {
            return false;
        }
        const char *eq = static_cast<const char *>(eq_raw);
        const char *key_end = trim_end(p, eq);
        if (key_end == p) {
            return false;
        }
        for (const char *q = p; q < key_end; ++q) {
            if (!is_key_char(*q)) {
                return false;
            }
        }

        Entry entry;
        entry.section = section_;
        entry.key.assign(p, key_end);

        const char *v = skip_space(eq + 1, end);
        if (v < end && *v == '"') {
            const char *after = read_quoted(v + 1, end, entry.value);
            if (after == nullptr) {
                return false;  // unterminated quoted value
            }
            after = skip_space(after, end);
            if (after < end && *after != '#' && *after != ';') {
                return false;  // trailing garbage after the closing quote
            }
        } else {
            entry.value.assign(v, end);
        }

        out_.entries.push_back(std::move(entry));
        return true;
    }

    Config &out_;
    std::string section_;
};

}  // namespace

std::optional<std::string> Config::get(std::string_view section, std::string_view key) const {
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        if (it->section == section && it->key == key) {
            return it->value;
        }
    }
    return std::nullopt;
}

ParseResult parse_config(const std::uint8_t *data, std::size_t size, Config &out) {
    ParseResult result;
    out.entries.clear();
    if (data == nullptr || size == 0) {
        result.ok = (size == 0);
        return result;
    }

    const char *cur = reinterpret_cast<const char *>(data);
    const char *const end = cur + size;
    LineParser parser(out);
    std::size_t line_no = 0;

    while (cur < end) {
        ++line_no;
        const void *nl_raw = std::memchr(cur, '\n', static_cast<std::size_t>(end - cur));
        const char *line_end = nl_raw != nullptr ? static_cast<const char *>(nl_raw) : end;
        if (!parser.parse_line(cur, line_end)) {
            result.error_line = line_no;
            return result;
        }
        cur = nl_raw != nullptr ? line_end + 1 : end;
    }

    result.ok = true;
    return result;
}

}  // namespace cfgparse
