#include <stdio.h>
/* bir kez çağrılan static: LastCallToStaticBonus ile satıriçi olmalı */
static int once(int x) { int s = 0; for (int i = 0; i < x; i++) { s += (i * i) ^ x; s ^= s >> 3; s += i % 7; } return s; }
/* iki kez çağrılan static, orta boy */
static int twice(int x) { int s = 1; for (int i = 0; i < x; i++) { s *= (i | 1); s ^= s >> 5; s += i % 11; s -= x / 3; } return s; }
__attribute__((always_inline)) static inline int ai(int x) { return x * 3 + 1; }
__attribute__((noinline)) static int ni(int x) { return x * 5 + 2; }
int g_api(int x) { return x + 7; }          /* global, küçük */
int g_unused(int x) { return x * 9 + 4; }   /* global, hiç çağrılmıyor */
static int s_unused(int x) { return x * 9 + 5; } /* static, hiç çağrılmıyor */
int main(int argc, char **argv) {
  int r = once(argc) + twice(argc) + twice(argc + 1) + ai(argc) + ni(argc) + g_api(argc);
  printf("%d\n", r);
  return 0;
}
