/* Minimal <byteswap.h> shim for macOS (glibc-only header). */
#ifndef _BYTESWAP_H_SHIM
#define _BYTESWAP_H_SHIM
#define bswap_16(x) __builtin_bswap16(x)
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#endif
