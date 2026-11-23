// Karadul P-ÜV3 yerel örneği: Swift'e içe aktarılan C tipleri (HasImportInfo). -import-objc-header ile.
#include <stdint.h>
#import <Foundation/Foundation.h>

// etiket ad alanında yapı (typedef yok)
struct kd_nokta { int x; int y; };

// typedef'li adsız yapı
typedef struct { double a; double b; } KDCift;

// etiketli + typedef (etiket adı ile typedef adı farklı)
typedef struct kd_ozel_etiket { int v; } KDOzel;

// açık genişletilebilir enum (NS_ENUM benzeri)
typedef NS_ENUM(NSInteger, KDRenk) { KDRenkKirmizi, KDRenkMavi };

// seçenek kümesi (NS_OPTIONS)
typedef NS_OPTIONS(NSUInteger, KDSecenek) { KDSecenekA = 1, KDSecenekB = 2 };

// swift_name ile farklı Swift adı
struct __attribute__((swift_name("KDAdli"))) kd_c_adi { int z; };

// swift_name ile iç içe Swift adı
struct KDKapsayici { int k; };
struct __attribute__((swift_name("KDKapsayici.Ic"))) kd_ic { int w; };

// hata kodu enum'u (NS_ERROR_ENUM: Swift'te sentezlenmiş KDHata yapısı + KDHata.Code)
extern NSErrorDomain const KDHataAlani;
typedef NS_ERROR_ENUM(KDHataAlani, KDHataKodu) { KDHataBir = 1, KDHataIki = 2 };

// tip takma adı üstünden adsız enum
typedef NS_ENUM(NSInteger, KDDurum) { KDDurumAcik, KDDurumKapali } NS_SWIFT_NAME(KDDurumTuru);
