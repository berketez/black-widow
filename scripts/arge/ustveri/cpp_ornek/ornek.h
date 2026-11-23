// P-ÜV4 yerel örnekleri (keşif GT'si): Itanium ABI RTTI / vtable biçimlerinin her türünden bir sınıf.
// Derleme: derle.py (xcrun clang++, -O0 / -O2, arm64 / x86_64). Derleme çıktısı çalıştırılmaz, depoya girmez.
#pragma once

#include <exception>

// 1. taban (anahtar işlevi .cpp'de: typeinfo / vtable tek çeviri biriminde, güçlü tanım)
struct Taban {
  virtual ~Taban();
  virtual int f(int x);
  virtual int g(int x);
  int alan = 1;
};

// 2. tekli kalıtım
struct Tekli : Taban {
  int f(int x) override;
};

// 3. ikinci taban + çoklu kalıtım (ikincil vtable, this düzeltme thunk'ı)
struct Ikinci {
  virtual ~Ikinci();
  virtual int h(int x);
  int ikinci_alan = 2;
};

struct Coklu : Tekli, Ikinci {
  int g(int x) override;
  int h(int x) override;
};

// 4. sanal kalıtım (elmas; vtable grubu sanal taban ofsetiyle başlar)
struct VTaban {
  virtual ~VTaban();
  virtual int v(int x);
  int vt_alan = 3;
};
struct VSol : virtual VTaban {
  virtual int sol(int x);
};
struct VSag : virtual VTaban {
  virtual int sag(int x);
};
struct Elmas : VSol, VSag {
  int v(int x) override;
};

// 5. saf sanal (yuva __cxa_pure_virtual içe aktarımı)
struct Soyut {
  virtual ~Soyut();
  virtual int s(int x) = 0;
  virtual int t(int x);
};
struct Somut : Soyut {
  int s(int x) override;
};

// 6. şablon sınıf (iki örnek)
template <class T>
struct Kap : Taban {
  T deger{};
  int f(int x) override;
};

// 7. iç içe sınıf ve ad alanı
namespace ornek {
struct Dis {
  struct Ic : Taban {
    int g(int x) override;
  };
};
}  // namespace ornek

// 8. başlıkta tanımlı sınıf (anahtar işlevi yok: typeinfo / vtable her çeviri biriminde zayıf tanım)
struct Basliktaki {
  virtual ~Basliktaki() = default;
  virtual int b(int x) { return x * 7 + 1; }
};
struct BaslikTuretilmis : Basliktaki {
  int b(int x) override { return x * 11 + 3; }
};

// 9. dış (kitaplıktaki) tabandan türeyen sınıf: taban typeinfo'su içe aktarım bağı
struct Hata : std::exception {
  const char* what() const noexcept override;
};

// fabrikalar (main.cpp çağırır; -O2'de sınıflar atılmasın)
extern "C" Taban* ornek_taban_yap(int tur);
extern "C" Ikinci* ornek_ikinci_yap(int tur);
extern "C" VTaban* ornek_vtaban_yap(int tur);
extern "C" Soyut* ornek_soyut_yap(int tur);
extern "C" Basliktaki* ornek_baslik_yap_a(int tur);
extern "C" Basliktaki* ornek_baslik_yap_b(int tur);
extern "C" std::exception* ornek_hata_yap(int tur);
