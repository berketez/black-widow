__attribute__((noinline)) static int helper(int x) { return x * x * x - 2; }
int api(int);
int main(int argc, char **argv) { return api(argc) + helper(argc); }
