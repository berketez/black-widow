/* İkinci deney: -O2'de gerçek atlama tablosu ve Linux hedefli yığın koruyucu.
 * Başlık dosyası yok; Linux sysroot olmadan -c ile derlenebilsin diye. */
extern int f0(int), f1(int), f2(int), f3(int), f4(int), f5(int), f6(int);
extern char *strcpy(char *, const char *);
extern unsigned long strlen(const char *);
extern int *__errno_location(void);
int dispatch(int op, int v) {
    switch (op) {
    case 0: return f0(v);   case 1: return f1(v + 1); case 2: return f2(v * 2);
    case 3: return f3(v - 7); case 4: return f4(v ^ 3); case 5: return f5(v);
    case 6: return f6(v >> 1); default: return -1;
    }
}
int canary(const char *s) { char b[64]; strcpy(b, s); return (int)strlen(b); }
int seterr(int e) { *__errno_location() = e; return -1; }
