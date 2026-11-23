// Karadul P-ÜV3 yerel Swift örneği: uzantı bağlamı (başka modülün tipine uzantı içinde tipler).
// Yalnız derlenir, ÇALIŞTIRILMAZ.
import Foundation

extension String {
    public struct UzantiIci { public var q = 1 }
    public enum UzantiEnum { case a, b }
}

extension Array {
    public final class UzantiKutu { public var n = 0 }
}

extension Array where Element == Int {
    public struct Kisitli { public var m = 1 }
}

extension Dictionary {
    public struct SozlukIci { public var k = 2 }
}

extension Date {
    public struct TarihIci { public var gun = 1 }
}

extension Optional {
    public enum SecenekIci { case yok }
}

extension NSObject {
    public struct NesneIci { public var o = 3 }
}

extension Int {
    public struct SayiIci {
        public var s = 4
        public enum EnIc { case e }
    }
}

// aynı modülün tipine uzantı (bağlam doğrudan tipin kendisi olmalı)
extension Hayvan {
    public struct HayvanEki { public var e = 5 }
}

extension Kutu where T == String {
    public struct MetinKutusuIci { public var t = "" }
}

func uzantiKullan() -> [Any] {
    [String.UzantiIci(), String.UzantiEnum.a, [Int].UzantiKutu().n, [Int].Kisitli(), [String: Int].SozlukIci(),
     Date.TarihIci(), Int?.SecenekIci.yok, NSObject.NesneIci(), Int.SayiIci(), Int.SayiIci.EnIc.e,
     Hayvan.HayvanEki(), Kutu<String>.MetinKutusuIci()]
}
