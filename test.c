#include <stdio.h>

int main () {
    printf("Hello world!");
     FILE* f = fopen(".\\test.txt", "w");
     fprintf(f, "Hello world!\n");
     fflush(f);
     fclose(f);
    return 0;
}