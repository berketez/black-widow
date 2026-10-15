/* Bambaşka yazılmış sürüm: farklı isimler, while döngüsü, ayrı sayaç */
int f(int *p, int n) {
    int s = 0;
    int k = 0;
    while (k < n) {
        s = s + *(p + k);
        k = k + 1;
    }
    return s;
}
