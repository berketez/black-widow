/*
 * Karadul B25: Çok-mimari fixture kaynak dosyası.
 *
 * Bu dosya tests/fixtures/diverse/ altındaki birden fazla Mach-O / ELF / PE
 * binary'sini üretmek için kullanılır. Amaç pipeline'ı tek bir mimaride
 * (arm64 coreutils) değil, x86_64 ve farklı format'lar üstünde de
 * doğrulayabilmek.
 *
 * Derleme komutları README.md içinde.
 */
#include <stdio.h>
#include <string.h>

static int add(int a, int b) {
    return a + b;
}

static int multiply(int a, int b) {
    return a * b;
}

static const char *get_greeting(void) {
    return "Karadul cok-mimari fixture";
}

static void print_info(void) {
    printf("Karadul fixture v1.15.5\n");
    printf("Amac: x86_64 + arm64 + (ELF/Mach-O/PE) E2E pipeline testi\n");
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    print_info();
    int s = add(3, 4);
    int p = multiply(5, 6);
    printf("add(3,4)=%d multiply(5,6)=%d\n", s, p);
    printf("%s\n", get_greeting());
    if (s > 0 && p > 0) {
        printf("OK\n");
    }
    return 0;
}
