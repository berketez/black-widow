#include <stdio.h>
#include <string.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

const char *get_greeting(void) {
    return "Hello from BlackWidow test binary";
}

void print_info(void) {
    printf("BlackWidow test binary v1.0\n");
    printf("Architecture: ARM64\n");
    printf("Purpose: Ghidra integration testing\n");
}

int main(int argc, char *argv[]) {
    print_info();
    int result = add(1, 2);
    printf("add(1, 2) = %d\n", result);
    printf("multiply(3, 4) = %d\n", multiply(3, 4));
    printf("%s\n", get_greeting());
    return 0;
}
