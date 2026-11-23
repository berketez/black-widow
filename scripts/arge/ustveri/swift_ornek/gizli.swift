// Karadul P-ÜV3 yerel Swift örneği: adsız bağlam (private / fileprivate tipler, işlev içi tipler).
// Yalnız derlenir, ÇALIŞTIRILMAZ.

private struct GizliYapi {
    var a = 1
    struct IcAcik { var b = 2 }
}

fileprivate class DosyaSinifi {
    func f() -> Int { 2 }
    func g() -> String { "g" }
}

fileprivate final class DosyaAltSinifi: DosyaSinifi {
    override func f() -> Int { 5 }
}

private enum GizliEnum {
    case x, y(Int)
}

struct AcikYapi {
    private struct IcGizli { var z = 3 }
    fileprivate enum IcDosya { case p }
    func yap() -> Int { IcGizli().z }
}

private class GizliGenel<T> {
    var t: T
    init(_ t: T) { self.t = t }
    func al() -> T { t }
}

private final class GizliSon {
    struct IcYapi { var u = 11 }
    func son() -> Int { IcYapi().u }
}

// özel yapı / enum içinde sınıf: sınıfın ObjC adı dış tipin ayracını taşır
private struct GizliKap {
    final class IcSinif { var w = 12 }
    struct IcIc { var z = 13 }
}

fileprivate enum GizliDurum {
    case a
    final class DurumSinifi { var d = 14 }
}

private protocol GizliProtokol {
    func gp() -> Int
}

private struct GizliUyan: GizliProtokol, Hashable {
    var v = 7
    func gp() -> Int { v }
}

func gizliKullan() -> [Any] {
    struct Yerel { var q = 9 }
    final class YerelSinif { var r = 10 }
    return [GizliYapi(), GizliYapi.IcAcik(), DosyaSinifi().g(), DosyaAltSinifi().f(), GizliEnum.y(1),
            AcikYapi().yap(), AcikYapi.IcDosya.p, GizliGenel(5).al(), GizliUyan().gp(), Yerel(), YerelSinif().r, GizliSon().son(), GizliSon.IcYapi(),
            GizliKap(), GizliKap.IcSinif().w, GizliKap.IcIc(), GizliDurum.a, GizliDurum.DurumSinifi().d]
}
