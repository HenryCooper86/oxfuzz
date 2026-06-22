#include "json.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static int parse_string(const char *buf, size_t len, const char **cur, struct JsonValue *out) {
    /* Expect opening quote. */
    if (*cur >= buf + len || **cur != '"') {
        return -1;
    }
    (*cur)++;
    const char *start = *cur;
    while (*cur < buf + len && **cur != '"') {
        if (**cur == '\\') {
            (*cur)++;
        }
        (*cur)++;
    }
    if (*cur >= buf + len) {
        return -1;
    }
    size_t slen = (size_t)(*cur - start);
    char *dst = malloc(slen + 1);
    if (!dst) {
        return -1;
    }
    memcpy(dst, start, slen);
    dst[slen] = '\0';
    out->type = JSON_STRING;
    out->v.string.data = dst;
    out->v.string.len = slen;
    (*cur)++;
    return 0;
}

static int parse_number(const char *buf, size_t len, const char **cur, struct JsonValue *out) {
    char *endptr = NULL;
    double val = strtod(*cur, &endptr);
    if (endptr == *cur) {
        return -1;
    }
    out->type = JSON_NUMBER;
    out->v.number = val;
    *cur = endptr;
    return 0;
}

static int parse_array(const char *buf, size_t len, const char **cur, struct JsonValue *out);

static int parse_value_inner(const char *buf, size_t len, const char **cur, struct JsonValue *out) {
    *cur = skip_ws(*cur, buf + len);
    if (*cur >= buf + len) {
        return -1;
    }
    char c = **cur;
    if (c == '"') {
        return parse_string(buf, len, cur, out);
    }
    if (c == '[') {
        return parse_array(buf, len, cur, out);
    }
    if (c == 't' || c == 'f') {
        if (*cur + 4 <= buf + len && strncmp(*cur, "true", 4) == 0) {
            out->type = JSON_BOOL;
            out->v.boolean = 1;
            *cur += 4;
            return 0;
        }
        if (*cur + 5 <= buf + len && strncmp(*cur, "false", 5) == 0) {
            out->type = JSON_BOOL;
            out->v.boolean = 0;
            *cur += 5;
            return 0;
        }
        return -1;
    }
    if (c == 'n') {
        if (*cur + 4 <= buf + len && strncmp(*cur, "null", 4) == 0) {
            out->type = JSON_NULL;
            *cur += 4;
            return 0;
        }
        return -1;
    }
    if (c == '-' || isdigit((unsigned char)c)) {
        return parse_number(buf, len, cur, out);
    }
    return -1;
}

static int parse_array(const char *buf, size_t len, const char **cur, struct JsonValue *out) {
    if (*cur >= buf + len || **cur != '[') {
        return -1;
    }
    (*cur)++;
    out->type = JSON_ARRAY;
    out->v.array.items = NULL;
    out->v.array.count = 0;
    size_t cap = 0;
    for (;;) {
        *cur = skip_ws(*cur, buf + len);
        if (*cur >= buf + len) {
            return -1;
        }
        if (**cur == ']') {
            (*cur)++;
            return 0;
        }
        struct JsonValue *item = malloc(sizeof(struct JsonValue));
        if (!item) {
            return -1;
        }
        if (parse_value_inner(buf, len, cur, item) != 0) {
            free(item);
            return -1;
        }
        if (out->v.array.count == cap) {
            cap = cap ? cap * 2 : 4;
            struct JsonValue **na = realloc(out->v.array.items, cap * sizeof(struct JsonValue *));
            if (!na) {
                free(item);
                return -1;
            }
            out->v.array.items = na;
        }
        out->v.array.items[out->v.array.count++] = item;
        *cur = skip_ws(*cur, buf + len);
        if (*cur >= buf + len) {
            return -1;
        }
        if (**cur == ',') {
            (*cur)++;
        } else if (**cur == ']') {
            (*cur)++;
            return 0;
        } else {
            return -1;
        }
    }
}

int parse_value(const char *buf, size_t len, struct JsonValue *out) {
    const char *cur = buf;
    if (parse_value_inner(buf, len, &cur, out) != 0) {
        return -1;
    }
    cur = skip_ws(cur, buf + len);
    if (cur != buf + len) {
        json_free(out);
        return -1;
    }
    return 0;
}

void json_free(struct JsonValue *v) {
    if (!v) {
        return;
    }
    switch (v->type) {
        case JSON_STRING:
            free(v->v.string.data);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->v.array.count; i++) {
                json_free(v->v.array.items[i]);
            }
            free(v->v.array.items);
            break;
        case JSON_OBJECT:
            /* Not implemented in this fixture. */
            break;
        default:
            break;
    }
}

int json_dump(const struct JsonValue *v, char *out, size_t cap) {
    if (!v || !out || cap == 0) {
        return -1;
    }
    switch (v->type) {
        case JSON_NULL:
            return snprintf(out, cap, "null");
        case JSON_BOOL:
            return snprintf(out, cap, v->v.boolean ? "true" : "false");
        case JSON_NUMBER:
            return snprintf(out, cap, "%g", v->v.number);
        case JSON_STRING:
            return snprintf(out, cap, "\"%s\"", v->v.string.data);
        default:
            return -1;
    }
}