#include <stdio.h>

int parse_line(char *output) {
    return fgets(output, 32, stdin) == NULL ? -1 : 0;
}
