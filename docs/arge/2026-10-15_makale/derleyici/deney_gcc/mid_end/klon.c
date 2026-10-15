/* IPA klon adlarını gözlemlemek için küçük örnek (GCC orta katman). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct cift { long a; long b; long c[8]; };
extern void dis_cagri (const char *);

/* ipa-cp: tüm çağıranlar mode=3 geçirir -> .constprop */
static __attribute__((noinline)) long olcekle (long x, int mode)
{ long r = 0; for (int i = 0; i < mode; i++) r += x * i + (x >> i); return r; }

/* ipa-sra: işaretçiyle gelen yapının yalnız bir alanı okunur -> .isra */
static __attribute__((noinline)) long alan_oku (struct cift *p, int kullanilmayan)
{ return p->b * 3 + p->b / 7; }

/* ipa-split: ucuz erken çıkış + pahalı gövde -> .part */
static long bol (const char *s)
{
  if (!s) return 0;
  long t = 0;
  for (int i = 0; s[i]; i++) { t = t * 31 + s[i]; if (t % 97 == 3) dis_cagri (s + i); }
  if (t == 42) { fprintf (stderr, "hata %s\n", s); abort (); }
  return t;
}

/* ipa-icf: iki özdeş gövde */
__attribute__((noinline)) long ikiz_a (long x) { return x * 7 + 13; }
__attribute__((noinline)) long ikiz_b (long x) { return x * 7 + 13; }
static __attribute__((noinline)) long ikiz_c (long x) { return x * 5 + 11; }
static __attribute__((noinline)) long ikiz_d (long x) { return x * 5 + 11; }
long (*adres_al) (long) = ikiz_a;   /* ikiz_a'nın adresi alınıyor */
long (*adres_al2) (long) = ikiz_b;  /* ikiz_b'nin de: alias olamaz */

long kullan (long v, const char *s, struct cift *p)
{
  return olcekle (v, 3) + olcekle (v + 1, 3) + alan_oku (p, 0) + bol (s) + bol (s + 1)
         + ikiz_c (v) + ikiz_d (v + 2);
}
