/* Minimal config.h for standalone macOS build of gnulib hash modules. */
#ifndef _GL_CONFIG_H_INCLUDED
#define _GL_CONFIG_H_INCLUDED 1
#include <stdalign.h>   /* alignof (UNALIGNED_P makrosu kullaniyor) */
#define HAVE_OPENSSL_MD5    0
#define HAVE_OPENSSL_SHA1   0
#define HAVE_OPENSSL_SHA256 0
#define HAVE_OPENSSL_SHA512 0
#undef  WORDS_BIGENDIAN
#endif
