#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv) {
    (void)argv;

    if (argc > 1) {
        printf("ERROR: This program doesn't require any arguments!\n");

        return -1;
    }

    printf("Process ID: %lu\n", GetCurrentProcessId());

    getchar();

    return 0;
}