// Karadul P-ÜV3 yerel Swift örneği: içe aktarılan C / ObjC tiplerine uzantı ve uyum (HasImportInfo).
// Yalnız derlenir, ÇALIŞTIRILMAZ. C tipleri `ornek.h`'den (-import-objc-header).
import Foundation
import CoreGraphics

public protocol Olculebilir {
    func olc() -> Double
}

extension kd_nokta: Olculebilir { public func olc() -> Double { Double(x + y) } }
extension KDCift: Olculebilir { public func olc() -> Double { a + b } }
extension KDOzel: Olculebilir { public func olc() -> Double { Double(v) } }
extension KDRenk: Olculebilir { public func olc() -> Double { Double(rawValue) } }
extension KDSecenek: Olculebilir { public func olc() -> Double { Double(rawValue) } }
extension KDAdli: Olculebilir { public func olc() -> Double { Double(z) } }
extension KDKapsayici: Olculebilir { public func olc() -> Double { Double(k) } }
extension KDKapsayici.Ic: Olculebilir { public func olc() -> Double { Double(w) } }
extension KDHataKodu: Olculebilir { public func olc() -> Double { Double(code.rawValue) } }
extension KDHataKodu.Code: Olculebilir { public func olc() -> Double { Double(rawValue) } }
extension KDDurumTuru: Olculebilir { public func olc() -> Double { Double(rawValue) } }
extension CGPoint: Olculebilir { public func olc() -> Double { Double(x + y) } }
extension CGRect: Olculebilir { public func olc() -> Double { Double(width) } }
extension NSRange: Olculebilir { public func olc() -> Double { Double(length) } }
extension timespec: Olculebilir { public func olc() -> Double { Double(tv_sec) } }

func olcAny(_ o: Olculebilir) -> Double { o.olc() }

func iceAktarimKullan() -> [Double] {
    [olcAny(kd_nokta(x: 1, y: 2)), olcAny(KDCift(a: 1, b: 2)), olcAny(KDOzel(v: 3)), olcAny(KDRenk.mavi),
     olcAny(KDSecenek.B), olcAny(KDAdli(z: 4)), olcAny(KDKapsayici(k: 5)), olcAny(KDKapsayici.Ic(w: 6)),
     olcAny(KDHataKodu.iki), olcAny(KDHataKodu(.bir)), olcAny(KDDurumTuru.kapali), olcAny(CGPoint(x: 1, y: 1)),
     olcAny(CGRect(x: 0, y: 0, width: 3, height: 3)), olcAny(NSRange(location: 0, length: 2)),
     olcAny(timespec(tv_sec: 1, tv_nsec: 0))]
}
