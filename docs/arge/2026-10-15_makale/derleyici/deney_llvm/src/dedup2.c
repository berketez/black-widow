#include <stdio.h>
__attribute__((noinline)) int gsame1(int x) { return x * 43 + 7; }
__attribute__((noinline)) int gsame2(int x) { return x * 43 + 7; }
int main(int argc, char **argv) { printf("%d %d\n", gsame1(argc), gsame2(argc + 1)); return 0; }
