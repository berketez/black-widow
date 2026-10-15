#include <stdio.h>
#include <string.h>
#include <stdarg.h>
struct Big { long a, b, c, d; };
__attribute__((noinline)) struct Big mk(long x) { struct Big b = {x, x + 1, x + 2, x + 3}; return b; }
__attribute__((noinline)) int takes_char(signed char c, unsigned short s) { return c + s; }
__attribute__((noinline)) int vsum(int n, ...) { va_list ap; va_start(ap, n); int s = 0; for (int i = 0; i < n; i++) s += va_arg(ap, int); va_end(ap); return s; }
__attribute__((noinline)) int buf(const char *s) { char b[64]; strcpy(b, s); return (int)strlen(b); }
__attribute__((noinline)) int nobuf(int x) { int a[4] = {x, x+1, x+2, x+3}; return a[x & 3]; }
int main(int argc, char **argv) {
  struct Big b = mk(argc);
  printf("%ld %d %d %d\n", b.d, takes_char((signed char)argc, (unsigned short)argc), buf(argv[0]), nobuf(argc));
  return vsum(3, 1, 2, argc);
}
