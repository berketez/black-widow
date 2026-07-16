/* Gerçek kullanım sürücüsü: bir tampon üzerinde CRC32 + MD5 + SHA1 + SHA256
   hesaplar. gnulib'in gerçek algoritma implementasyonlarını çağırır ki
   fonksiyon + değişken isimleri DWARF'ta korunsun (isimlendirme benchmark'ı).
   Bu dosya (driver) fixture'ın kendi kodudur; ölçüm asıl gnulib fonksiyonları
   üzerinde yapılır. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crc.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

static void print_digest(const char *label, const unsigned char *digest, size_t n)
{
  printf("%s: ", label);
  for (size_t i = 0; i < n; i++)
    printf("%02x", digest[i]);
  printf("\n");
}

/* Bir mesaji tampona kopyalayip dort ozeti de hesaplar. */
static int hash_message(const char *message)
{
  size_t length = strlen(message);
  unsigned char md5_out[16];
  unsigned char sha1_out[20];
  unsigned char sha256_out[32];

  md5_buffer(message, length, md5_out);
  sha1_buffer(message, length, sha1_out);
  sha256_buffer(message, length, sha256_out);
  uint32_t checksum = crc32_update(0, message, length);

  print_digest("md5", md5_out, sizeof md5_out);
  print_digest("sha1", sha1_out, sizeof sha1_out);
  print_digest("sha256", sha256_out, sizeof sha256_out);
  printf("crc32: %08x\n", checksum);
  return 0;
}

int main(int argc, char **argv)
{
  const char *input = argc > 1 ? argv[1] : "The quick brown fox jumps over the lazy dog";
  return hash_message(input);
}
