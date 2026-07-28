#include <stdio.h>

int parse_line(char *output) {
    return gets(output) == NULL ? -1 : 0;
}
