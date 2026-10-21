#include <cstddef>
#include <cstdint>

class CommandParser {
    unsigned state = 0;
    int evaluate_payload(const std::uint8_t *data, std::size_t size) {
        if (!size) return 0;
        if (data[0] == '+') ++state;
        else if (data[0] == '-') --state;
        else if (size > 2 && data[0] == 's' && data[1] == '=') state = data[2];
        else return -1;
        if (size > 3 && data[3] == '!') state ^= 0xff;
        return static_cast<int>(state);
    }
public:
    int parse(const std::uint8_t *data, std::size_t size) {
        if (!data || size < 2) return -1;
        if (data[0] != ':') return -2;
        return evaluate_payload(data + 1, size - 1);
    }
};

int parse_command(const std::uint8_t *data, std::size_t size) {
    CommandParser parser;
    return parser.parse(data, size);
}
