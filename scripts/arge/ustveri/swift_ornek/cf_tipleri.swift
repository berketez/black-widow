// Karadul P-ÜV3 yerel Swift örneği: içe aktarılan CF / CoreGraphics yabancı sınıfları (foreign class).
// Yalnız derlenir, ÇALIŞTIRILMAZ.
import Foundation
import CoreGraphics

public protocol Etiketli {
    func etiket() -> String
}

extension CFString: Etiketli { public func etiket() -> String { "cfstring" } }
extension CGColor: Etiketli { public func etiket() -> String { "cgcolor" } }
extension CGPath: Etiketli { public func etiket() -> String { "cgpath" } }
extension CFRunLoop: Etiketli { public func etiket() -> String { "cfrunloop" } }

func etiketle(_ e: Etiketli) -> String { e.etiket() }

func cfKullan() -> [String] {
    [etiketle("a" as CFString), etiketle(CGColor(gray: 0.5, alpha: 1)), etiketle(CGPath(rect: .zero, transform: nil)),
     etiketle(CFRunLoopGetMain())]
}
