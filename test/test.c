#include <stdlib.h>
#include <stdio.h>
int x;
int main(int argc, char** argv) {
    /* printf("hello world %s\n", argv[1]); */
    /* int* p = malloc(sizeof(int)); */
    int* p = &x;
    printf("hi there %p\n", p);
    *p = 10;
    return 0;
}
