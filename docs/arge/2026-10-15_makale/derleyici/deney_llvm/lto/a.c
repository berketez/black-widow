__attribute__((noinline)) static int helper(int x) { return x * x + 3 * x + 1; }
int api(int x) { return helper(x) + 1; }
int api_unused(int x) { return x - 99; }
