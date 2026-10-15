#include <stdio.h>
int same1(int x) { return x * 37 + 5; }
int same2(int x) { return x * 37 + 5; }
__attribute__((noinline)) static int ssame1(int x) { return x * 41 - 3; }
__attribute__((noinline)) static int ssame2(int x) { return x * 41 - 3; }
int (*volatile fp1)(int) = same1;
int (*volatile fp2)(int) = same2;
int main(int argc, char **argv) {
  printf("%d %d %d %d\n", fp1(argc), fp2(argc), ssame1(argc), ssame2(argc + 1));
  printf("%d\n", fp1 == fp2);
  return 0;
}
