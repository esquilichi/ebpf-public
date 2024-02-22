#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *file = fopen("/tmp/arguments.txt", "a+");
    if (file == NULL) {
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        fprintf(file, "%s\n", argv[i]);
    }
    fclose(file);
    return 0;
}