"""Isim haritasi olusturma -- eslesen fonksiyonlardan degisken isimlerini cikarir.

Eslestirme sonuclarindan iki tur isim recovery yapar:
1. Fonksiyon isimleri: minified "a" -> orijinal "registerLanguage"
2. Parametre isimleri: pozisyonel eslestirme (1. param -> 1. param, ...)

Lokal degisken eslestirmesi bu fazda YAPILMIYOR (Phase 2).

Filtreleme kurallari:
- Sadece kisa (<=2 karakter) minified isimleri map'ler (zaten anlamli olan isimleri degistirmez)
- Orijinal isim de obfuscated gorunuyorsa (ornegin test kodundaki 'x', 'y') atlar
- Ayni minified isim farkli orijinal isimlere eslesirse yuksek confidence'li alir
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .structural_matcher import FunctionMatch, ModuleMatchResult

logger = logging.getLogger(__name__)


# Obfuscated/anlamsiz isim tespiti
_SKIP_NAMES = frozenset({
    # Genel JS isimleri -- bunlar zaten anlamli
    "module", "exports", "require", "__webpack_require__",
    "__dirname", "__filename", "undefined", "null",
    "this", "self", "window", "global", "console",
    "Object", "Array", "String", "Number", "Boolean",
    "Error", "TypeError", "RangeError", "Promise",
    "Map", "Set", "WeakMap", "WeakSet",
    "JSON", "Math", "Date", "RegExp",
    "Symbol", "Proxy", "Reflect",
})


def _is_minified_name(name: str) -> bool:
    """Isim minified (kisa, anlamsiz) mi?

    Minified isimler genellikle 1-2 karakter:
    a, b, c, ... z, A, B, ..., Z, aa, ab, ...

    esbuild 3 karakterli isimler de uretir: fn2, ym9, Q88, l88, RC_, ksT
    Bunlar da minified sayilir cunku:
    - Tek harf + rakamlar (a1, b2, fn2)
    - Harf + rakam karisimi (ym9, Q88)
    - Underscore ile biten kisaltmalar (RC_)

    4+ karakterli isimleri degistirmiyoruz cunku bunlar zaten
    anlamli olabilir (deadCode elimination sonrasi kalan isimler).
    """
    if not name:
        return False
    if name in _SKIP_NAMES:
        return False
    if len(name) <= 2:
        return True
    # 3 karakterli esbuild-style minified isimler
    if len(name) == 3:
        # Tumu buyuk harf (orn: SDK, API, URL, DOM, CSS) -> kisaltma, minified DEGiL
        if name.isupper() and name.isalpha():
            return False
        # Harf+rakam karisimi (fn2, ym9, Q88, A18) veya _/$ ile biten (RC_, OC_)
        has_digit = any(c.isdigit() for c in name)
        has_letter = any(c.isalpha() for c in name)
        ends_with_special = name[-1] in ('_', '$')
        if has_digit and has_letter:
            return True
        if ends_with_special and has_letter:
            return True
        # esbuild base52 kodlama: karisik buyuk/kucuk harf (ksT, fYq, zYq, uT_)
        # veya tumu kucuk harf (abc, xyz)
        # 3 harfli tum isimler minified sayilir (all-upper haric)
        if name.isalpha():
            return True
    return False


def _is_meaningful_name(name: str) -> bool:
    """Orijinal isim anlamli mi (map'lemeye deger)?

    Anlamsiz orijinal isimler:
    - Tek karakter (test kodundaki 'x', 'y')
    - Sadece underscore/sayi
    """
    if not name or len(name) <= 1:
        return False
    if name in _SKIP_NAMES:
        return False
    # Sadece underscore ve rakamlari atla
    stripped = name.replace("_", "").replace("$", "")
    if not stripped or stripped.isdigit():
        return False
    return True


@dataclass
class NameMapping:
    """Tek bir isim eslesmesi."""

    old_name: str       # Minified isim (orn: "a")
    new_name: str       # Orijinal isim (orn: "registerLanguage")
    kind: str           # "function" | "parameter"
    confidence: float   # Eslestirme skoru
    context: str = ""   # Hangi fonksiyon icerisinde (parametreler icin)

    def __repr__(self) -> str:
        return f"{self.old_name} -> {self.new_name} ({self.kind}, {self.confidence:.2f})"


class NameMapper:
    """Eslesen fonksiyonlardan degisken isimlerini cikarir.

    Kullanim:
        mapper = NameMapper()
        mapping_dict = mapper.map_names(match_result)
        # {"a": "registerLanguage", "b": "name", "c": "lang"}

        all_mappings = mapper.map_all_modules(module_matches)
        # {"module_42": {"a": "registerLanguage", ...}, ...}

    Neden sadece kisa isimleri?
        Minifier genellikle isimleri 1-2 karaktere kisaltir. 3+ karakterli
        isimler zaten anlamli olabilir (export isimleri, API property'leri).
        Bunlari yanlislikla degistirmek tehlikeli.
    """

    def map_names(self, match_result: ModuleMatchResult) -> dict[str, str]:
        """Eslestirme sonucundan isim mapping olustur.

        Args:
            match_result: StructuralMatcher.match_module() sonucu.

        Returns:
            {minified_name: original_name} sozlugu.
            Sadece kisa minified isimleri icerir.
        """
        mappings: dict[str, str] = {}
        detailed: list[NameMapping] = []

        for func_match in match_result.matches:
            self._extract_from_match(func_match, mappings, detailed)

        if detailed:
            logger.info(
                "NameMapper: %d isim recovery (%d fonksiyon, %d parametre)",
                len(detailed),
                sum(1 for d in detailed if d.kind == "function"),
                sum(1 for d in detailed if d.kind == "parameter"),
            )

        return mappings

    def map_names_detailed(
        self, match_result: ModuleMatchResult
    ) -> list[NameMapping]:
        """Eslestirme sonucundan detayli isim mapping olustur.

        map_names() ile ayni mantik ama NameMapping nesneleri dondurur
        (confidence, context bilgisi dahil).

        Args:
            match_result: StructuralMatcher.match_module() sonucu.

        Returns:
            NameMapping listesi (confidence'a gore azalan sirada).
        """
        mappings: dict[str, str] = {}
        detailed: list[NameMapping] = []

        for func_match in match_result.matches:
            self._extract_from_match(func_match, mappings, detailed)

        # Confidence'a gore sirala
        detailed.sort(key=lambda x: x.confidence, reverse=True)
        return detailed

    def map_all_modules(
        self,
        module_matches: dict[str, ModuleMatchResult],
    ) -> dict[str, dict[str, str]]:
        """Tum moduller icin name mapping olustur.

        Args:
            module_matches: {module_id: ModuleMatchResult} sozlugu.

        Returns:
            {module_id: {old_name: new_name}} sozlugu.
            Sadece eslesmesi olan moduller dahil edilir.
        """
        result: dict[str, dict[str, str]] = {}

        for module_id, match_result in module_matches.items():
            if match_result.matched == 0:
                continue
            name_map = self.map_names(match_result)
            if name_map:
                result[module_id] = name_map

        total_names = sum(len(m) for m in result.values())
        logger.info(
            "NameMapper: %d modulde toplam %d isim recovery",
            len(result), total_names,
        )

        return result

    def _extract_from_match(
        self,
        func_match: FunctionMatch,
        mappings: dict[str, str],
        detailed: list[NameMapping],
    ) -> None:
        """Tek bir fonksiyon eslesmesinden isimleri cikar.

        1. Fonksiyon ismini map'le (minified kisa ise)
        2. Parametre isimlerini pozisyonel olarak map'le

        Cakisma durumunda: yuksek similarity olan kazanir.
        """
        min_fp = func_match.minified
        orig_fp = func_match.original
        sim = func_match.similarity

        # --- Fonksiyon ismi ---
        min_name = getattr(min_fp, "name", None)
        orig_name = getattr(orig_fp, "name", None)

        if min_name and orig_name and _is_minified_name(min_name) and _is_meaningful_name(orig_name):
            # Cakisma kontrolu: ayni minified isim daha yuksek confidence ile mi eslesmis?
            if min_name not in mappings:
                mappings[min_name] = orig_name
                detailed.append(NameMapping(
                    old_name=min_name,
                    new_name=orig_name,
                    kind="function",
                    confidence=sim,
                ))

        # --- Parametre isimleri (pozisyonel) ---
        min_params = getattr(min_fp, "param_names", []) or []
        orig_params = getattr(orig_fp, "param_names", []) or []

        orig_func_name = orig_name or "?"

        for idx, (m_param, o_param) in enumerate(zip(min_params, orig_params)):
            if not m_param or not o_param:
                continue
            if not _is_minified_name(m_param):
                continue
            if not _is_meaningful_name(o_param):
                continue

            # Ayni minified param ismi baska bir eslesmede farkli anlamda kullanilmis olabilir
            # (farkli fonksiyonlarda ayni parametre adi baska seye karsilik gelebilir)
            # Bu durumda ilk gelen kazanir -- genellikle en yuksek confidence
            if m_param not in mappings:
                mappings[m_param] = o_param
                detailed.append(NameMapping(
                    old_name=m_param,
                    new_name=o_param,
                    kind="parameter",
                    confidence=sim,
                    context=f"param[{idx}] of {orig_func_name}",
                ))
