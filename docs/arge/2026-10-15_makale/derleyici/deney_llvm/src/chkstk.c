#include <string.h>
void use(char*);
int big(int x){ char b[8192]; memset(b, x, sizeof b); use(b); return b[x]; }
