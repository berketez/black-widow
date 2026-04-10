"""TypeScript .d.ts dosyalarindan export isimleri ile minified fonksiyon eslestirme.

Minified JS bundle'lar genellikle npm paketlerinin derlenmis halleridir.
Paketin TypeScript tanim dosyasi (.d.ts) export edilen fonksiyon, class
ve degisken isimlerini icerir. Bu modul .d.ts dosyasini parse edip
export isimlerini cikarir ve minified koddaki export'larla eslestirir.

Kaynak stratejisi:
1. DefinitelyTyped: @types/xxx paketi (npm registry)
2. Paketin kendi .d.ts dosyasi (package.json "types" alani)
3. unpkg.com CDN uzerinden indirme (fallback)

Eslestirme stratejisi:
- Export sirasi genellikle build tool'lar tarafindan korunur
- Isim uzunluklari ve tip bilgileri ile cross-validation
- Birden fazla .d.ts dosyasi birlestirme (declare module, re-export)

Kullanim:
    namer = DtsNamer()
    exports = namer.parse_dts(dts_content)
    mapping = namer.match_exports(minified_exports, exports)
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# unpkg.com uzerinden .d.ts indirme timeout'u (saniye)
_DEFAULT_TIMEOUT = 10
# Rate limit icin istekler arasi minimum bekleme (saniye)
_DEFAULT_DELAY_S = 0.05


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DtsExport:
    """Tek bir .d.ts export'u.

    Attributes:
        name: Export edilen isim.
        kind: Tur -- function, class, interface, type, const, enum, namespace, variable.
        signature: Tam tanim satiri (opsiyonel).
        is_default: default export mi.
        param_count: Fonksiyon ise parametre sayisi, degilse -1.
    """

    name: str
    kind: str
    signature: str = ""
    is_default: bool = False
    param_count: int = -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "signature": self.signature,
            "is_default": self.is_default,
            "param_count": self.param_count,
        }


@dataclass
class DtsMatchResult:
    """Export eslestirme sonucu.

    Attributes:
        matched: Basarili eslesmeler {minified_name: dts_name}.
        unmatched_minified: Eslesemeyen minified export'lar.
        unmatched_dts: Eslesemeyen .d.ts export'lar.
        confidence: Genel eslestirme guveni (0.0-1.0).
        method: Kullanilan eslestirme yontemi.
    """

    matched: dict[str, str] = field(default_factory=dict)
    unmatched_minified: list[str] = field(default_factory=list)
    unmatched_dts: list[str] = field(default_factory=list)
    confidence: float = 0.0
    method: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "unmatched_minified": self.unmatched_minified,
            "unmatched_dts": self.unmatched_dts,
            "confidence": self.confidence,
            "method": self.method,
        }


@dataclass
class DtsNamerResult:
    """DtsNamer genel sonucu.

    Attributes:
        success: Islem basarili mi.
        package_name: Islenen paket adi.
        exports_found: .d.ts'den cikan export sayisi.
        matches_found: Basarili eslestirme sayisi.
        mapping: Minified -> orijinal isim eslestirme.
        errors: Hata mesajlari.
    """

    success: bool = False
    package_name: str = ""
    exports_found: int = 0
    matches_found: int = 0
    mapping: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "package_name": self.package_name,
            "exports_found": self.exports_found,
            "matches_found": self.matches_found,
            "mapping": self.mapping,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Regex'ler — .d.ts export parse
# ---------------------------------------------------------------------------

# export function foo(...): ReturnType;
_RE_EXPORT_FUNCTION = re.compile(
    r"export\s+(?:declare\s+)?function\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)",
)

# export class Foo { ... }
_RE_EXPORT_CLASS = re.compile(
    r"export\s+(?:declare\s+)?(?:abstract\s+)?class\s+(\w+)",
)

# export interface Foo { ... }
_RE_EXPORT_INTERFACE = re.compile(
    r"export\s+(?:declare\s+)?interface\s+(\w+)",
)

# export type Foo = ...
_RE_EXPORT_TYPE = re.compile(
    r"export\s+(?:declare\s+)?type\s+(\w+)\s*(?:<[^>]*>)?\s*=",
)

# export const foo: Type = ...;  veya  export const foo = ...;
_RE_EXPORT_CONST = re.compile(
    r"export\s+(?:declare\s+)?const\s+(\w+)\s*[;:=]",
)

# export let/var foo ...
_RE_EXPORT_VAR = re.compile(
    r"export\s+(?:declare\s+)?(?:let|var)\s+(\w+)\s*[;:=]",
)

# export enum Foo { ... }
_RE_EXPORT_ENUM = re.compile(
    r"export\s+(?:declare\s+)?(?:const\s+)?enum\s+(\w+)",
)

# export namespace Foo { ... }
_RE_EXPORT_NAMESPACE = re.compile(
    r"export\s+(?:declare\s+)?namespace\s+(\w+)",
)

# export default ...
_RE_EXPORT_DEFAULT = re.compile(
    r"export\s+default\s+(?:function\s+|class\s+|abstract\s+class\s+)?(\w+)?",
)

# export { A, B, C }  veya  export { A as B }
_RE_EXPORT_LIST = re.compile(
    r"export\s*\{([^}]+)\}",
)

# Fonksiyon parametre sayisi hesaplama icin — virgullerden parametre say
def _count_params(params_str: str) -> int:
    """Parametre string'inden parametre sayisini hesapla.

    Nested parantez, bracket ve angle bracket icindeki virgulleri saymiyor.
    Arrow function (=>) icindeki '>' depth azaltmamali.
    """
    params_str = params_str.strip()
    if not params_str:
        return 0
    # Nested parantez/bracket icindeki virgulleri sayma
    # (<[{ depth birlikte, angle bracket <> ayri (=> ile karismasin)
    paren_depth = 0  # ( ) [ ] { }
    angle_depth = 0  # < >
    count = 1
    i = 0
    n = len(params_str)
    while i < n:
        ch = params_str[i]
        if ch in "([{":
            paren_depth += 1
        elif ch in ")]}":
            paren_depth = max(0, paren_depth - 1)
        elif ch == "<":
            angle_depth += 1
        elif ch == ">":
            # "=>" arrow function mu? O zaman depth azaltma
            if i > 0 and params_str[i - 1] == "=":
                pass  # Arrow function, skip
            else:
                angle_depth = max(0, angle_depth - 1)
        elif ch == "," and paren_depth == 0 and angle_depth == 0:
            count += 1
        i += 1
    return count


# ---------------------------------------------------------------------------
# DtsNamer class
# ---------------------------------------------------------------------------


class DtsNamer:
    """TypeScript .d.ts dosyalarindan export isim recovery.

    .d.ts dosyasini parse eder, export isimlerini cikarir ve
    minified fonksiyonlarla eslestirir.

    Attributes:
        timeout: HTTP istek timeout'u (saniye).
        delay_s: Istekler arasi bekleme suresi (saniye).
    """

    def __init__(
        self,
        timeout: int = _DEFAULT_TIMEOUT,
        delay_s: float = _DEFAULT_DELAY_S,
        fetcher: Any = None,
    ) -> None:
        """DtsNamer olustur.

        Args:
            timeout: HTTP istek timeout suresi.
            delay_s: Istekler arasi bekleme.
            fetcher: Test icin dependency injection -- fetch_dts_content yerine kullanilir.
                     callable(url: str) -> str | None seklinde olmali.
        """
        self.timeout = timeout
        self.delay_s = delay_s
        self._fetcher = fetcher

    def parse_dts(self, dts_content: str) -> list[DtsExport]:
        """Bir .d.ts dosyasinin icerigini parse edip export listesi cikar.

        Args:
            dts_content: .d.ts dosyasinin icerigi.

        Returns:
            Bulunan export'larin listesi.
        """
        if not dts_content or not dts_content.strip():
            return []

        exports: list[DtsExport] = []
        seen_names: set[str] = set()

        def _add(name: str, kind: str, signature: str = "",
                 is_default: bool = False, param_count: int = -1) -> None:
            if name and name not in seen_names:
                seen_names.add(name)
                exports.append(DtsExport(
                    name=name,
                    kind=kind,
                    signature=signature.strip(),
                    is_default=is_default,
                    param_count=param_count,
                ))

        # Fonksiyonlar
        for m in _RE_EXPORT_FUNCTION.finditer(dts_content):
            name = m.group(1)
            params = m.group(2)
            pc = _count_params(params)
            _add(name, "function", m.group(0), param_count=pc)

        # Class'lar
        for m in _RE_EXPORT_CLASS.finditer(dts_content):
            _add(m.group(1), "class", m.group(0))

        # Interface'ler
        for m in _RE_EXPORT_INTERFACE.finditer(dts_content):
            _add(m.group(1), "interface", m.group(0))

        # Type alias'lar
        for m in _RE_EXPORT_TYPE.finditer(dts_content):
            _add(m.group(1), "type", m.group(0))

        # Const'lar
        for m in _RE_EXPORT_CONST.finditer(dts_content):
            _add(m.group(1), "const", m.group(0))

        # Let/var
        for m in _RE_EXPORT_VAR.finditer(dts_content):
            _add(m.group(1), "variable", m.group(0))

        # Enum'lar
        for m in _RE_EXPORT_ENUM.finditer(dts_content):
            _add(m.group(1), "enum", m.group(0))

        # Namespace'ler
        for m in _RE_EXPORT_NAMESPACE.finditer(dts_content):
            _add(m.group(1), "namespace", m.group(0))

        # Default export
        for m in _RE_EXPORT_DEFAULT.finditer(dts_content):
            name = m.group(1)
            if name:
                _add(name, "default", m.group(0), is_default=True)

        # export { A, B, C } veya export { A as B }
        for m in _RE_EXPORT_LIST.finditer(dts_content):
            items_str = m.group(1)
            for item in items_str.split(","):
                item = item.strip()
                if not item:
                    continue
                # "A as B" -> orijinal isim A, export isim B
                as_match = re.match(r"(\w+)\s+as\s+(\w+)", item)
                if as_match:
                    _add(as_match.group(2), "re-export", f"{as_match.group(1)} as {as_match.group(2)}")
                else:
                    name = item.split()[0] if item.split() else item
                    if re.match(r"^\w+$", name):
                        _add(name, "re-export", name)

        return exports

    def match_exports(
        self,
        minified_exports: list[str],
        dts_exports: list[DtsExport],
    ) -> DtsMatchResult:
        """Minified export isimlerini .d.ts export'lariyla eslestirir.

        Strateji sirasi:
        1. Exact match: Isimler ayni ise (zaten eslesmis)
        2. Order-based: Export sirasi korunmus varsayimi ile 1:1 eslestirme
        3. Param-count match: Fonksiyon parametre sayisi esitligi ile eslestirme

        Args:
            minified_exports: Minified koddaki export isimleri (sirali).
            dts_exports: parse_dts() sonucu .d.ts export listesi (sirali).

        Returns:
            DtsMatchResult: Eslestirme sonucu.
        """
        result = DtsMatchResult()

        if not minified_exports or not dts_exports:
            result.unmatched_minified = list(minified_exports or [])
            result.unmatched_dts = [e.name for e in (dts_exports or [])]
            return result

        dts_names = [e.name for e in dts_exports]

        # --- Strateji 1: Exact match ---
        matched: dict[str, str] = {}
        remaining_min: list[str] = []
        remaining_dts: list[DtsExport] = list(dts_exports)

        for min_name in minified_exports:
            found = False
            for i, dts_exp in enumerate(remaining_dts):
                if min_name == dts_exp.name:
                    matched[min_name] = dts_exp.name
                    remaining_dts.pop(i)
                    found = True
                    break
            if not found:
                remaining_min.append(min_name)

        # Hepsi exact eslestiyse
        if not remaining_min:
            result.matched = matched
            result.unmatched_dts = [e.name for e in remaining_dts]
            result.confidence = 1.0
            result.method = "exact"
            return result

        # --- Strateji 2: Order-based matching ---
        # Kalan minified ve dts export'lari sirasina gore eslestirilir
        remaining_dts_names = [e.name for e in remaining_dts]

        if len(remaining_min) == len(remaining_dts):
            # Birebir siralama — yuksek guven
            order_matched: dict[str, str] = {}
            for min_name, dts_exp in zip(remaining_min, remaining_dts):
                order_matched[min_name] = dts_exp.name

            matched.update(order_matched)
            result.matched = matched
            result.confidence = 0.7
            result.method = "exact+order"
            return result

        # --- Strateji 3: Order-based with size difference ---
        # Daha fazla dts export varsa (type, interface gibi runtime'da olmayan seyler)
        # Sadece function ve const/variable olanlari filtrele
        runtime_dts = [e for e in remaining_dts if e.kind in ("function", "const", "variable", "class", "enum")]
        if len(remaining_min) == len(runtime_dts):
            order_matched = {}
            for min_name, dts_exp in zip(remaining_min, runtime_dts):
                order_matched[min_name] = dts_exp.name

            matched.update(order_matched)
            result.matched = matched
            result.unmatched_dts = [
                e.name for e in remaining_dts if e not in runtime_dts
            ]
            result.confidence = 0.55
            result.method = "exact+order_runtime_filtered"
            return result

        # --- Strateji 4: Best-effort partial match ---
        # Eslesmeyenleri raporla
        order_count = min(len(remaining_min), len(remaining_dts))
        partial_matched: dict[str, str] = {}
        for i in range(order_count):
            partial_matched[remaining_min[i]] = remaining_dts[i].name

        matched.update(partial_matched)
        result.matched = matched
        result.unmatched_minified = remaining_min[order_count:]
        result.unmatched_dts = [e.name for e in remaining_dts[order_count:]]
        # Confidence: eslesen oran
        total = len(minified_exports)
        result.confidence = len(matched) / total if total > 0 else 0.0
        result.method = "exact+partial_order"
        return result

    def fetch_dts_content(self, package_name: str, version: str = "latest") -> str | None:
        """npm paketinin .d.ts icerigini indir.

        Sirasyla dener:
        1. @types/{package_name} (DefinitelyTyped)
        2. Paketin kendi types dosyasi

        Args:
            package_name: npm paket adi (orn. "lodash").
            version: Paket versiyonu (orn. "4.17.21" veya "latest").

        Returns:
            .d.ts dosya icerigi veya None (basarisiz ise).
        """
        if self._fetcher:
            # Test mock
            url = f"https://unpkg.com/@types/{package_name}@{version}/index.d.ts"
            return self._fetcher(url)

        # Strateji 1: @types paketinden
        urls = [
            f"https://unpkg.com/@types/{package_name}@{version}/index.d.ts",
            f"https://unpkg.com/{package_name}@{version}/index.d.ts",
            f"https://unpkg.com/{package_name}@{version}/dist/index.d.ts",
            f"https://unpkg.com/{package_name}@{version}/types/index.d.ts",
        ]

        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "karadul/1.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    content = resp.read().decode("utf-8", errors="replace")
                    if content and "export" in content:
                        logger.info("DTS indirme basarili: %s", url)
                        return content
            except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
                logger.debug("DTS indirme basarisiz: %s — %s", url, exc)
                continue

        logger.warning("DTS bulunamadi: %s@%s", package_name, version)
        return None

    def load_dts_for_package(self, package_name: str, version: str = "latest") -> DtsNamerResult:
        """npm paketinin .d.ts dosyasindan export isimlerini cikar.

        Args:
            package_name: npm paket adi.
            version: Paket versiyonu.

        Returns:
            DtsNamerResult: Tum sonuc.
        """
        result = DtsNamerResult(package_name=package_name)

        content = self.fetch_dts_content(package_name, version)
        if content is None:
            result.errors.append(f".d.ts indirilemedi: {package_name}@{version}")
            return result

        exports = self.parse_dts(content)
        result.exports_found = len(exports)
        result.success = len(exports) > 0

        if not exports:
            result.errors.append(f".d.ts parse edildi ama export bulunamadi: {package_name}")

        return result

    def load_dts_from_file(self, dts_path: Path) -> list[DtsExport]:
        """Lokal .d.ts dosyasindan export isimlerini cikar.

        Args:
            dts_path: .d.ts dosya yolu.

        Returns:
            Export listesi.
        """
        try:
            content = dts_path.read_text(encoding="utf-8", errors="replace")
            return self.parse_dts(content)
        except OSError as exc:
            logger.error("DTS dosya okunamadi: %s — %s", dts_path, exc)
            return []

    def rename_minified(
        self,
        package_name: str,
        minified_exports: list[str],
        dts_content: str | None = None,
        version: str = "latest",
    ) -> DtsNamerResult:
        """Minified export isimlerini .d.ts kullanarak orijinal isimlere donustur.

        Tam workflow: fetch/parse + match.

        Args:
            package_name: npm paket adi.
            minified_exports: Minified koddaki export isimleri (sirali).
            dts_content: Varsa dogrudan .d.ts icerigi (fetch atlama).
            version: Paket versiyonu.

        Returns:
            DtsNamerResult: Tum sonuc.
        """
        result = DtsNamerResult(package_name=package_name)

        # .d.ts icerigini al
        if dts_content is None:
            dts_content = self.fetch_dts_content(package_name, version)

        if dts_content is None:
            result.errors.append(f".d.ts indirilemedi: {package_name}@{version}")
            return result

        # Parse
        exports = self.parse_dts(dts_content)
        result.exports_found = len(exports)

        if not exports:
            result.errors.append(f".d.ts parse edildi ama export bulunamadi: {package_name}")
            return result

        # Eslesitir
        match_result = self.match_exports(minified_exports, exports)
        result.mapping = match_result.matched
        result.matches_found = len(match_result.matched)
        result.success = result.matches_found > 0

        return result
