// P-ÜV4 yerel örnekleri: sınıf tanımları (birinci çeviri birimi).
#include "ornek.h"

Taban::~Taban() {}
int Taban::f(int x) { return x + alan; }
int Taban::g(int x) { return x * 2 + alan; }

int Tekli::f(int x) { return x - alan; }

Ikinci::~Ikinci() {}
int Ikinci::h(int x) { return x ^ ikinci_alan; }

int Coklu::g(int x) { return x * 3 + alan; }
int Coklu::h(int x) { return x * 5 + ikinci_alan; }

VTaban::~VTaban() {}
int VTaban::v(int x) { return x + vt_alan; }
int VSol::sol(int x) { return x - 9; }
int VSag::sag(int x) { return x + 9; }
int Elmas::v(int x) { return x * 13 + vt_alan; }

Soyut::~Soyut() {}
int Soyut::t(int x) { return x * 17; }
int Somut::s(int x) { return x * 19; }

template <class T>
int Kap<T>::f(int x) {
  return x + static_cast<int>(deger) + alan;
}
template struct Kap<int>;
template struct Kap<double>;

int ornek::Dis::Ic::g(int x) { return x * 23; }

namespace {
struct Gizli : Taban {
  int f(int x) override { return x * 29 + alan; }
};
}  // namespace

const char* Hata::what() const noexcept { return "ornek hata"; }

extern "C" Taban* ornek_taban_yap(int tur) {
  switch (tur) {
    case 0: return new Taban;
    case 1: return new Tekli;
    case 2: return new Coklu;
    case 3: return new Kap<int>;
    case 4: return new Kap<double>;
    case 5: return new ornek::Dis::Ic;
    default: return new Gizli;
  }
}

extern "C" Ikinci* ornek_ikinci_yap(int tur) {
  if (tur == 0) return new Ikinci;
  return new Coklu;
}

extern "C" VTaban* ornek_vtaban_yap(int tur) {
  switch (tur) {
    case 0: return new VTaban;
    case 1: return new VSol;
    case 2: return new VSag;
    default: return new Elmas;
  }
}

extern "C" Soyut* ornek_soyut_yap(int) { return new Somut; }

extern "C" Basliktaki* ornek_baslik_yap_a(int tur) {
  if (tur == 0) return new Basliktaki;
  return new BaslikTuretilmis;
}

extern "C" std::exception* ornek_hata_yap(int) { return new Hata; }
