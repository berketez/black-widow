static long sq(long x) { return x * x; }
static long inc(long x) { return x + 1; }
static long apply(long (*op)(long), long *a, int n) {
  long s = 0;
  for (int i = 0; i < n; i++) { s += op(a[i]); if (s > 1000000) s -= op(s); }
  return s;
}
long run(long *a, int n) { return apply(sq, a, n) + apply(inc, a, n); }
