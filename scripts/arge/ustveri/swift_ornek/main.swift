// Karadul P-ÜV3 yerel Swift örneği (yalnız derlenir, ÇALIŞTIRILMAZ).
// Kapsam: iç içe tipler, genel sınıf / yapı / enum, sınıf vtable'ı (yöntem, init, getter / setter,
// zaman uyumsuz yöntem, sınıf yöntemi), geçersiz kılma, yerel ve dış protokole uyum, @objc sınıf.
import Foundation

public protocol Sesli {
    func ses() -> String
    var ad: String { get }
}

public protocol Sayan {
    associatedtype Oge
    func say(_ o: Oge) -> Int
    func sifirla()
}

open class Hayvan {
    public var ad: String
    public var yas: Int = 0
    public init(ad: String) { self.ad = ad }
    public convenience init() { self.init(ad: "adsız") }
    open func ses() -> String { "..." }
    open var bacak: Int {
        get { 4 }
        set { yas = newValue }
    }
    open func bekle() async -> Int { yas }
    open class func tur() -> String { "hayvan" }
    public final func son() -> Int { yas + 1 }
    open subscript(i: Int) -> Int { i + yas }

    public struct Ic {
        public var x: Int
        public enum Derin { case a, b(Int) }
        public final class EnDerin { public var y = 2 }
    }
}

public final class Kedi: Hayvan, Sesli {
    public override func ses() -> String { "miyav" }
    public override var bacak: Int {
        get { 4 }
        set { yas = newValue + 1 }
    }
    public override init(ad: String) { super.init(ad: ad) }
    public override func bekle() async -> Int { 3 }
}

open class Kus: Hayvan {
    open func uc() -> Bool { true }
    open override func ses() -> String { "cik" }
}

public class Kutu<T> {
    public var deger: T
    public init(_ d: T) { deger = d }
    public func al() -> T { deger }
    public func koy(_ d: T) { deger = d }
    public class IcKutu { public var n = 0 }
}

public final class SayiKutusu: Kutu<Int>, Sayan {
    public func say(_ o: Int) -> Int { o + deger }
    public func sifirla() { deger = 0 }
    public override func al() -> Int { deger * 2 }
}

public struct Cift<A, B> {
    public var a: A
    public var b: B
}

public enum Sonuc<T: Equatable>: Equatable {
    case iyi(T)
    case kotu
}

public struct Nokta: Equatable, CustomStringConvertible, Sesli {
    public var x: Double
    public var y: Double
    public var ad: String { "nokta" }
    public func ses() -> String { "\(x),\(y)" }
    public var description: String { ses() }
}

public enum Yon: String, CaseIterable {
    case kuzey, guney, dogu, bati
}

@objc public class ObjcSinif: NSObject {
    @objc public var deger: Int = 0
    @objc public func artir() { deger += 1 }
    @objc public dynamic func dinamik() -> Int { deger }
    public func yalnizSwift() -> Int { deger * 3 }
}

public actor Sayac {
    public var n = 0
    public func artir() -> Int { n += 1; return n }
}

// Örnekler derleyicinin bütün tipleri koruması için kullanılır (ikili ÇALIŞTIRILMAZ).
@inline(never) func kullan(_ x: Any) { print(x) }

let k = Kedi(ad: "tekir")
kullan(k.ses())
kullan(Kus(ad: "serçe").uc())
kullan(Hayvan.Ic(x: 1))
kullan(Hayvan.Ic.Derin.b(2))
kullan(Hayvan.Ic.EnDerin().y)
kullan(Kutu("a").al())
kullan(Kutu<Int>.IcKutu().n)
kullan(SayiKutusu(5).say(3))
kullan(Cift(a: 1, b: "b"))
kullan(Sonuc.iyi(3) == Sonuc.kotu)
kullan(Nokta(x: 1, y: 2))
kullan(Yon.allCases)
kullan(ObjcSinif().yalnizSwift())
kullan(Sayac())
kullan(gizliKullan())
kullan(uzantiKullan())
kullan(iceAktarimKullan())
