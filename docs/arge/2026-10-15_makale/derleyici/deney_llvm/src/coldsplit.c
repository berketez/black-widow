#include <stdio.h>
#include <stdlib.h>
int work(int *a, int n) {
  int s = 0;
  for (int i = 0; i < n; i++) {
    if (a[i] < 0) {
      fprintf(stderr, "negatif deger %d, indis %d\n", a[i], i);
      fprintf(stderr, "abort ediliyor\n");
      abort();
    }
    s += a[i];
  }
  return s;
}
int main(int argc, char **argv) { int a[3] = {argc, 2, 3}; return work(a, 3); }
