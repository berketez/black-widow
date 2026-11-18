/*
 * Masum ikili kapısı — anti-debug gerçek pozitif örneği (P00).
 *
 * Üç bilinen macOS/x86-64 anti-debug tekniği, her biri gerçek çağrıyla:
 *   1. rdtsc ile zamanlama ölçümü (x86 komutu `0F 31`, kod bölümünde),
 *   2. ptrace(PT_DENY_ATTACH, 0, 0, 0) — hata ayıklayıcının bağlanmasını engeller,
 *   3. sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}) ile kp_proc.p_flag & P_TRACED.
 *
 * Derleme (ikili depo dışında durur; masum_kapi.py --pozitif-kur bunu çalıştırır):
 *   clang -arch x86_64 -O0 -o ~/karadul_olcum/masum_kapi/pozitif/antidebug_x86_64 \
 *         scripts/measurement/masum_kapi_pozitif/antidebug.c
 *
 * Çalıştırılması gerekmez (kapı ikiliyi yalnız okur). Çalıştırılırsa PT_DENY_ATTACH süreci
 * hata ayıklayıcıya kapatır; başka yan etkisi yoktur.
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int timing_check(void) {
    uint64_t t0 = read_tsc();
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    uint64_t t1 = read_tsc();
    return (t1 - t0) > 10000000ULL;  /* adım adım yürütülüyorsa çok yavaş */
}

static int traced_check(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    info.kp_proc.p_flag = 0;
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return 0;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int main(void) {
    if (traced_check() || timing_check()) {
        puts("debugger detected");
        return 1;
    }
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    puts("ok");
    return 0;
}
