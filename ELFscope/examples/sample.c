#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int square(int value)
{
    return value * value;
}

/* the local buffer is on purpose, without it the compiler never
   emits a stack protector and the hardening tests have nothing to see */
int main(int argc, char** argv)
{
    char label[32];
    int value = argc > 1 ? atoi(argv[1]) : 7;

    snprintf(label, sizeof(label), "square(%d)", value);
    printf("%s = %d\n", label, square(value));

    return (int)strlen(label) > 100;
}
