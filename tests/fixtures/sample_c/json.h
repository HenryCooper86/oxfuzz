#ifndef HF_SAMPLE_JSON_H
#define HF_SAMPLE_JSON_H

#include <stddef.h>

enum JsonType {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
};

struct JsonValue {
    enum JsonType type;
    union {
        int boolean;
        double number;
        struct {
            char *data;
            size_t len;
        } string;
        struct {
            struct JsonValue **items;
            size_t count;
        } array;
        struct {
            char **keys;
            struct JsonValue **values;
            size_t count;
        } object;
    } v;
};

/* Parse a JSON document. Returns 0 on success, -1 on error.
   Untrusted input: ideal fuzzing target. */
int parse_value(const char *buf, size_t len, struct JsonValue *out);

/* Free a JsonValue tree. */
void json_free(struct JsonValue *v);

/* Format a JsonValue to a string (pure output, not a fuzz target). */
int json_dump(const struct JsonValue *v, char *out, size_t cap);

#endif