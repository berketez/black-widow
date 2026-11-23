// P-ÜV4 yerel örnekleri: ikinci çeviri birimi (başlıkta tanımlı sınıfın ikinci zayıf tanımı) + main.
#include <cstdio>
#include <typeinfo>

#include "ornek.h"

extern "C" Basliktaki* ornek_baslik_yap_b(int tur) {
  if (tur == 0) return new BaslikTuretilmis;
  return new Basliktaki;
}

int main(int argc, char** argv) {
  (void)argv;
  int t = argc;
  int toplam = 0;
  Taban* a = ornek_taban_yap(t);
  toplam += a->f(t) + a->g(t);
  if (dynamic_cast<Tekli*>(a)) toplam += 1;
  std::printf("%s\n", typeid(*a).name());
  Ikinci* i = ornek_ikinci_yap(t);
  toplam += i->h(t);
  VTaban* v = ornek_vtaban_yap(t);
  toplam += v->v(t);
  if (VSol* s = dynamic_cast<VSol*>(v)) toplam += s->sol(t);
  Soyut* so = ornek_soyut_yap(t);
  toplam += so->s(t) + so->t(t);
  Basliktaki* b1 = ornek_baslik_yap_a(t);
  Basliktaki* b2 = ornek_baslik_yap_b(t);
  toplam += b1->b(t) + b2->b(t);
  std::exception* h = ornek_hata_yap(t);
  std::printf("%s %d\n", h->what(), toplam);
  delete a;
  delete i;
  delete v;
  delete so;
  delete b1;
  delete b2;
  delete h;
  return toplam & 1;
}
