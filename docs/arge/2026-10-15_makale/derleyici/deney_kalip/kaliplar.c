/* Derleyici kalıp kataloğu deneyi.
 * Her kalıp ayrı, dışa açık bir fonksiyonda; main argv'den beslenir
 * (IPSCCP/sabit yayılımı fonksiyonları özelleştirmesin diye).
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NOINL __attribute__((noinline))

/* ---------- 1. switch ---------- */
/* Yoğun case'ler -> atlama tablosu beklenir */
NOINL int sw_dense(int x) {
    switch (x) {
    case 0: return 11; case 1: return 27; case 2: return 35;
    case 3: return 49; case 4: return 52; case 5: return 68;
    case 6: return 71; case 7: return 89; default: return -1;
    }
}
/* Seyrek case'ler -> ikili arama / karşılaştırma ağacı beklenir */
NOINL int sw_sparse(int x) {
    switch (x) {
    case 3: return 1; case 100: return 2; case 1000: return 3;
    case 5000: return 4; case 20000: return 5; case 77777: return 6;
    case 123456: return 7; default: return 0;
    }
}
/* Aynı hedefe giden küçük aralıklı case'ler -> bit testi beklenir */
NOINL int sw_bittest(int c) {
    switch (c) {
    case ' ': case '\t': case '\n': case '\r': case '\v': case '\f':
    case ',': case ';':
        return 1;
    default:
        return 0;
    }
}

/* ---------- 2. sabitle bölme / mod ---------- */
NOINL unsigned udiv7(unsigned x) { return x / 7; }
NOINL int sdiv7(int x) { return x / 7; }
NOINL unsigned umod10(unsigned x) { return x % 10; }
NOINL int sdiv16(int x) { return x / 16; }
NOINL uint64_t udiv1000_64(uint64_t x) { return x / 1000; }

/* ---------- 3. bit işlemleri, koşullu seçim ---------- */
NOINL int sel_max(int a, int b) { return a > b ? a : b; }
NOINL int sel_abs(int a) { return a < 0 ? -a : a; }
NOINL int sel_clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
NOINL int popcount_loop(unsigned x) { int c = 0; while (x) { x &= x - 1; c++; } return c; }
NOINL uint32_t bswap32_manual(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}
NOINL uint32_t rotl32(uint32_t x, int r) { return (x << (r & 31)) | (x >> ((32 - r) & 31)); }
NOINL int is_pow2(unsigned x) { return x && !(x & (x - 1)); }

/* ---------- 4. satır içi mem/str ---------- */
struct S16 { int a, b, c, d; };
NOINL void copy16(struct S16 *d, const struct S16 *s) { memcpy(d, s, sizeof *d); }
NOINL void zero64(char *p) { memset(p, 0, 64); }
NOINL void zero_n(char *p, size_t n) { memset(p, 0, n); }
NOINL size_t strlen_const(void) { return strlen("karadul"); }
NOINL int strcmp_const(const char *s) { return strcmp(s, "GET") == 0; }
NOINL int strncmp_const(const char *s) { return strncmp(s, "HTTP/1.", 7) == 0; }
/* el yazımı döngüler: idiom tanıma ile libc çağrısına dönüşür mü? */
NOINL void loop_zero(int *a, int n) { for (int i = 0; i < n; i++) a[i] = 0; }
NOINL void loop_copy(char *restrict d, const char *restrict s, int n) { for (int i = 0; i < n; i++) d[i] = s[i]; }
NOINL size_t loop_strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); }

/* ---------- 5. struct kopyalama/dönüş, varargs ---------- */
struct Big { long v[8]; };
NOINL struct Big make_big(long x) { struct Big b; for (int i = 0; i < 8; i++) b.v[i] = x + i; return b; }
NOINL long use_big(long x) { struct Big b = make_big(x); return b.v[3] + b.v[7]; }
struct Small { int a; int b; };
NOINL struct Small make_small(int x) { struct Small s = { x, x * 3 }; return s; }
NOINL int sum_va(int n, ...) {
    va_list ap; va_start(ap, n);
    int s = 0; for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap); return s;
}

/* ---------- 6. yığın koruyucu ve FORTIFY ---------- */
NOINL int ssp_copy(const char *src) {
    char buf[64];
    strcpy(buf, src);
    return (int)strlen(buf) + buf[3];
}
NOINL void fortify_memcpy(char *dst, const char *src, size_t n) {
    char tmp[32];
    memcpy(tmp, src, n);          /* boyut bilinmiyor -> _chk adayı */
    memcpy(dst, tmp, 32);
}
NOINL int fortify_snprintf(char *out, size_t cap, int v) {
    return snprintf(out, cap, "deger=%d", v);
}

/* ---------- 7. hata yolu: errno, -1, goto cleanup ---------- */
NOINL int read_file_head(const char *path, char *out, size_t cap) {
    int ret = -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    char *tmp = malloc(cap);
    if (!tmp) goto out_close;
    ssize_t n = read(fd, tmp, cap);
    if (n < 0) { errno = EIO; goto out_free; }
    memcpy(out, tmp, (size_t)n);
    ret = (int)n;
out_free:
    free(tmp);
out_close:
    close(fd);
    return ret;
}

/* ---------- 8. kuyruk çağrısı ---------- */
NOINL int tail_target(int x) { return x * 3 + 1; }
NOINL int tail_caller(int x) { return tail_target(x + 1); }
NOINL int tail_ext(const char *s) { return atoi(s + 1); }

/* ---------- 9. vektörleme ---------- */
NOINL void vadd(int *restrict a, const int *restrict b, const int *restrict c, int n) {
    for (int i = 0; i < n; i++) a[i] = b[i] + c[i];
}
NOINL int vsum(const int *a, int n) { int s = 0; for (int i = 0; i < n; i++) s += a[i]; return s; }
NOINL float vdot(const float *a, const float *b, int n) {
    float s = 0; for (int i = 0; i < n; i++) s += a[i] * b[i]; return s;
}

/* ---------- 10. kripto sabitleri: kodda nasıl kodlanıyor? ---------- */
NOINL void md5_init(uint32_t st[4]) {
    st[0] = 0x67452301; st[1] = 0xefcdab89; st[2] = 0x98badcfe; st[3] = 0x10325476;
}
static uint32_t crc_table[256];
NOINL void crc32_make_table(void) {
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[n] = c;
    }
}
NOINL uint32_t crc32_buf(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    while (n--) c = crc_table[(c ^ *p++) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}
NOINL void tea_encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}

int main(int argc, char **argv) {
    int x = argc > 1 ? atoi(argv[1]) : 3;
    const char *s = argc > 2 ? argv[2] : "GET";
    char buf[128];
    int arr[64], brr[64], crr[64];
    float fa[64], fb[64];
    for (int i = 0; i < 64; i++) { brr[i] = i ^ x; crr[i] = i + x; fa[i] = (float)i; fb[i] = (float)x; }
    long acc = 0;
    acc += sw_dense(x) + sw_sparse(x) + sw_bittest(x);
    acc += udiv7((unsigned)x) + sdiv7(x) + umod10((unsigned)x) + sdiv16(x) + (long)udiv1000_64((uint64_t)x);
    acc += sel_max(x, 5) + sel_abs(x) + sel_clamp(x, 0, 9) + popcount_loop((unsigned)x);
    acc += bswap32_manual((uint32_t)x) + rotl32((uint32_t)x, x) + is_pow2((unsigned)x);
    struct S16 a = { x, 1, 2, 3 }, b; copy16(&b, &a); acc += b.d;
    zero64(buf); zero_n(buf, (size_t)x & 63); acc += (long)strlen_const() + strcmp_const(s) + strncmp_const(s);
    loop_zero(arr, x & 63); loop_copy(buf, s, (int)strlen(s)); acc += (long)loop_strlen(s);
    acc += use_big(x) + make_small(x).b + sum_va(3, x, x + 1, x + 2);
    acc += ssp_copy(s); fortify_memcpy(buf, s, strlen(s) & 31); acc += fortify_snprintf(buf, sizeof buf, x);
    acc += read_file_head(argc > 3 ? argv[3] : "/etc/hosts", buf, sizeof buf);
    acc += tail_caller(x) + tail_ext(s);
    vadd(arr, brr, crr, 64); acc += vsum(arr, 64) + (long)vdot(fa, fb, 64);
    uint32_t st[4]; md5_init(st); crc32_make_table(); acc += crc32_buf((const uint8_t *)s, strlen(s));
    uint32_t v[2] = { st[0], st[1] }, k[4] = { 1, 2, 3, 4 }; tea_encrypt(v, k); acc += v[0];
    printf("%ld\n", acc);
    return 0;
}
