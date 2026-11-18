/*
 * P02 gerçek pozitif örneği (Linux ELF, nesne dosyası): bağlayıcı (ld.lld) bu makinede
 * olmadığı için yalnız derlenir (-c); ELF bölüm tablosu ve .text gerçektir.
 *   1. ptrace(PTRACE_TRACEME)          — kendini izleme kilidi
 *   2. /proc/self/status + "TracerPid:" — izleyici PID'i okuma
 *   3. rdtsc ... rdtsc (yalnız x86-64)  — zaman ölçümü
 * .rodata'da "0F 31" tuzağı: kod dışındaki bu baytlar rdtsc SAYILMAMALI (IMZA-02).
 * Başlık dosyası yok (Linux sysroot yok); bildirimler elle.
 */
typedef unsigned long uint64;
long ptrace(int request, int pid, void *addr, void *data);
void *fopen(const char *path, const char *mode);
char *fgets(char *s, int n, void *f);
int strncmp(const char *a, const char *b, unsigned long n);
int atoi(const char *s);
int fclose(void *f);
void exit(int code);

#define PTRACE_TRACEME 0

const unsigned char p02_tuzak[16] = {
    0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31,
    0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31, 0x00, 0x00,
};

static int izleyici_var(void) {
    char satir[256];
    void *f = fopen("/proc/self/status", "r");
    int sonuc = 0;
    if (!f) {
        return 0;
    }
    while (fgets(satir, sizeof(satir), f)) {
        if (strncmp(satir, "TracerPid:", 10) == 0) {
            sonuc = atoi(satir + 10) != 0;
            break;
        }
    }
    fclose(f);
    return sonuc;
}

static uint64 saat(void) {
#if defined(__x86_64__)
    return __builtin_ia32_rdtsc();
#else
    return 0;
#endif
}

int p02_denetle(int n) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        exit(1);
    }
    uint64 t0 = saat();
    volatile int toplam = 0;
    for (int i = 0; i < n; ++i) {
        toplam += i;
    }
    uint64 t1 = saat();
    if (t1 - t0 > 100000000UL || izleyici_var()) {
        exit(1);
    }
    return toplam + p02_tuzak[n & 7];
}
