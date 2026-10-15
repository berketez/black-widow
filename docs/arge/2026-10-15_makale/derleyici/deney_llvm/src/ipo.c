#include <stdio.h>
__attribute__((noinline)) static int k_const(int x, int mode) { return mode == 3 ? x * 7 : x - 1; }
__attribute__((noinline)) static int unused_arg(int x, int unused) { return x * 11; }
__attribute__((noinline)) static int by_ptr(const int *p) { return *p * 13; }
__attribute__((noinline)) static int ret_unused(int x) { printf("%d\n", x); return x; }
int tail(int x) { return k_const(x, 3); }
int main(int argc, char **argv) {
  int v = argc;
  int r = k_const(argc, 3) + k_const(argc + 1, 3) + unused_arg(argc, 42) + unused_arg(argc + 2, 43) + by_ptr(&v);
  ret_unused(r); ret_unused(r + 1);
  return tail(r);
}
