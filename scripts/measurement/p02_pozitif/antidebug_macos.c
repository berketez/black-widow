/*
 * P02 gerçek pozitif örneği (macOS): bilinen üç anti-debug tekniği.
 *   1. ptrace(PT_DENY_ATTACH)                         — hata ayıklayıcı bağlanmasını engeller
 *   2. sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID) + P_TRACED — izleniyor muyum?
 *   3. rdtsc ... rdtsc zaman ölçümü (yalnız x86-64)  — adım adım yürütmeyi yakalar
 * Ayrıca salt okunur veride "0F 31" baytlarından oluşan bir tuzak dizisi var:
 * kod bölümü dışındaki bu baytlar rdtsc SAYILMAMALI (IMZA-02).
 *
 * Derleme: scripts/measurement/p02_pozitif/uret.sh
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__x86_64__)
#include <x86intrin.h>
#else
#include <mach/mach_time.h>
#endif

/* Tuzak: 7 adet "0F 31" çifti, __TEXT,__const içinde (yürütülmez). */
const unsigned char p02_tuzak[16] = {
    0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31,
    0x0f, 0x31, 0x0f, 0x31, 0x0f, 0x31, 0x00, 0x00,
};

static int izleniyor_mu(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid()};
    struct kinfo_proc bilgi;
    size_t boyut = sizeof(bilgi);
    bilgi.kp_proc.p_flag = 0;
    if (sysctl(mib, 4, &bilgi, &boyut, NULL, 0) != 0) {
        return 0;
    }
    return (bilgi.kp_proc.p_flag & P_TRACED) != 0;
}

static uint64_t saat(void) {
#if defined(__x86_64__)
    return __rdtsc();
#else
    return mach_absolute_time();
#endif
}

int main(int argc, char **argv) {
    (void)argv;
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    uint64_t t0 = saat();
    volatile int toplam = 0;
    for (int i = 0; i < argc * 1000; ++i) {
        toplam += i;
    }
    uint64_t t1 = saat();
    if (t1 - t0 > 100000000ULL || izleniyor_mu()) {
        puts("hata ayiklayici");
        return 1;
    }
    printf("%d %u\n", toplam, (unsigned)p02_tuzak[argc & 7]);
    return 0;
}
