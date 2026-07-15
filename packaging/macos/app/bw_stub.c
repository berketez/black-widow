/* Black Widow .app arm64 başlatıcı stub'ı.
 *
 * CFBundleExecutable bir bash script olursa macOS mimariyi belirleyemiyor ve
 * "Intel için üretilmiş / Rosetta" uyarısı basıyor + bazı durumlarda hiç
 * açılmıyor. Bu gerçek arm64 Mach-O binary'si yalnızca yanındaki
 * bw_launch.sh'ı çalıştırır; tüm başlatma mantığı script'te kalır.
 * (HRMA reçetesinden uyarlandı, 2026-07-14.)
 */
#include <mach-o/dyld.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char exe[PATH_MAX];
    uint32_t sz = sizeof(exe);
    if (_NSGetExecutablePath(exe, &sz) != 0)
        return 1;
    char real[PATH_MAX];
    if (!realpath(exe, real))
        return 1;
    char *dir = dirname(real); /* .../Black Widow.app/Contents/MacOS */
    char script[PATH_MAX];
    snprintf(script, sizeof(script), "%s/bw_launch.sh", dir);
    execl("/bin/bash", "/bin/bash", script, (char *)NULL);
    perror("Black Widow baslatilamadi");
    return 1;
}
