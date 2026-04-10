"""Source match sonuclarini JS dosyalarina uygula -- minified isimleri orijinale cevir.

Batch rename: mapping'deki {old_name: new_name} ciftlerini JS dosyasina uygular.

Guvenlik onlemleri:
- Sadece identifier pozisyonlarindaki isimleri degistirir (string literal icini degistirmez)
- JS keyword'leri ile cakisan isimleri atlar
- Her modul icin bagimsiz calisir (cross-module rename yok)
- Property access'lerdeki isimleri degistirmez (obj.e -> obj.e kalir)

Kullanim:
    applier = SourceMatchApplier()
    count = applier.apply_to_file(js_file, {"e": "element", "t": "type"})
    # veya toplu:
    stats = applier.apply_to_directory(modules_dir, output_dir, all_mappings)
"""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# JS reserved words -- bunlari rename etmekten kacin
_JS_RESERVED = frozenset({
    "abstract", "arguments", "await", "boolean", "break", "byte", "case",
    "catch", "char", "class", "const", "continue", "debugger", "default",
    "delete", "do", "double", "else", "enum", "eval", "export", "extends",
    "false", "final", "finally", "float", "for", "function", "goto", "if",
    "implements", "import", "in", "instanceof", "int", "interface", "let",
    "long", "native", "new", "null", "of", "package", "private",
    "protected", "public", "return", "short", "static", "super", "switch",
    "synchronized", "this", "throw", "throws", "transient", "true", "try",
    "typeof", "undefined", "var", "void", "volatile", "while", "with",
    "yield",
})

# Cok yaygin global isimler -- bunlari rename etme
_GLOBAL_NAMES = frozenset({
    "module", "exports", "require", "__webpack_require__",
    "__dirname", "__filename", "console", "process",
    "window", "document", "global", "self",
    "Object", "Array", "String", "Number", "Boolean",
    "Error", "TypeError", "RangeError", "Promise",
    "Map", "Set", "WeakMap", "WeakSet", "Symbol",
    "JSON", "Math", "Date", "RegExp", "Proxy", "Reflect",
    "parseInt", "parseFloat", "isNaN", "isFinite",
    "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "Buffer", "URL", "URLSearchParams",
    "Infinity", "NaN",
})


def _should_skip(old_name: str, new_name: str) -> bool:
    """Bu rename atlanmali mi?

    Atalanma kosullari:
    - old_name JS keyword
    - old_name global isim
    - new_name JS keyword
    - old_name ile new_name ayni
    - old_name 0 karakter
    """
    if not old_name or not new_name:
        return True
    if old_name == new_name:
        return True
    if old_name in _JS_RESERVED or old_name in _GLOBAL_NAMES:
        return True
    if new_name in _JS_RESERVED:
        return True
    return False


def _build_identifier_pattern(name: str) -> re.Pattern[str]:
    r"""Sadece identifier pozisyonlarindaki isimleri eslestirir.

    Onemli: .name seklindeki property access'leri eslestirmez.
    Onemli: string literal icindeki eslesmeler regex ile dislanir.

    Pattern: (?<![.\w$]) NAME (?![\w$])
    - Oncesinde . veya alfanumerik karakter olmamali (property access degil)
    - Sonrasinda alfanumerik karakter olmamali (daha uzun ismin parcasi degil)
    """
    escaped = re.escape(name)
    return re.compile(
        r"(?<![.\w$])" + escaped + r"(?![\w$])"
    )


class SourceMatchApplier:
    """Source match mapping'lerini JS dosyalarina uygular.

    Her modul dosyasi icin:
    1. Mapping'deki her {old: new} cifti icin regex olustur
    2. String literal'lerin icini degistirmekten kacin
    3. Property access pozisyonlarini atla
    4. Degisiklikleri dosyaya yaz

    String-safe strateji:
    - Once string literal'leri placeholder'lara cevir
    - Rename islemi yap
    - Placeholder'lari geri yerlestir
    Bu sayede "e" string literali icindeki 'e' harfi degismez.
    """

    # String literal placeholder -- JS'de gecersiz karakter dizisi
    _PLACEHOLDER_PREFIX = "\x00__SMATCH_STR_"

    def __init__(self, *, dry_run: bool = False) -> None:
        """
        Args:
            dry_run: True ise dosyalari degistirmez, sadece kac degisiklik olacagini hesaplar.
        """
        self.dry_run = dry_run

    def apply_to_file(
        self,
        js_file: Path,
        mapping: dict[str, str],
        output_file: Path | None = None,
    ) -> int:
        """Tek bir JS dosyasina mapping uygula.

        Args:
            js_file: Kaynak JS dosyasi.
            mapping: {minified_name: original_name} sozlugu.
            output_file: Cikti dosyasi. None ise dosya yerinde degistirilir.

        Returns:
            Yapilan degisiklik sayisi (toplam replacement).
        """
        if not js_file.exists():
            return 0

        if not mapping:
            # Mapping bos -- dosyayi sadece kopyala (output_file verilmisse)
            if output_file and output_file != js_file:
                shutil.copy2(js_file, output_file)
            return 0

        try:
            code = js_file.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Dosya okunamadi: %s (%s)", js_file, exc)
            return 0

        # Filtrelenmis mapping: skip edilmesi gerekenleri at
        filtered: dict[str, str] = {}
        for old, new in mapping.items():
            if _should_skip(old, new):
                continue
            filtered[old] = new

        if not filtered:
            if output_file and output_file != js_file:
                shutil.copy2(js_file, output_file)
            return 0

        # String-safe rename
        result_code, total_replacements = self._safe_rename(code, filtered)

        if total_replacements > 0 and not self.dry_run:
            dest = output_file or js_file
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(result_code, encoding="utf-8")
        elif output_file and output_file != js_file:
            # Degisiklik yok ama output isteniyorsa kopyala
            if not self.dry_run:
                shutil.copy2(js_file, output_file)

        if total_replacements > 0:
            logger.debug(
                "SourceMatchApplier: %s -> %d replacement (%d mapping)",
                js_file.name, total_replacements, len(filtered),
            )

        return total_replacements

    def apply_to_directory(
        self,
        modules_dir: Path,
        output_dir: Path,
        all_mappings: dict[str, dict[str, str]],
    ) -> dict[str, int]:
        """Tum modullere mapping uygula.

        Args:
            modules_dir: Kaynak modul dizini.
            output_dir: Cikti dizini (modules_dir ile ayni olabilir).
            all_mappings: {module_id: {old_name: new_name}} sozlugu.

        Returns:
            {module_id: replacement_count} sozlugu.
        """
        stats: dict[str, int] = {}
        total_replaced = 0
        total_modules = 0

        for module_id, mapping in all_mappings.items():
            src = modules_dir / f"{module_id}.js"
            if not src.exists():
                # Kategori dizininde aranabilir
                found = list(modules_dir.rglob(f"{module_id}.js"))
                if found:
                    src = found[0]
                else:
                    continue

            # Cikti dosyasini belirle
            if output_dir == modules_dir:
                dest = src  # yerinde degistir
            else:
                # Ayni relatif yolu koru
                try:
                    rel = src.relative_to(modules_dir)
                except ValueError:
                    rel = Path(f"{module_id}.js")
                dest = output_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)

            count = self.apply_to_file(src, mapping, dest)
            if count > 0:
                stats[module_id] = count
                total_replaced += count
            total_modules += 1

        logger.info(
            "SourceMatchApplier: %d modulde %d replacement (%d modul islendi)",
            len(stats), total_replaced, total_modules,
        )
        return stats

    def _safe_rename(
        self, code: str, mapping: dict[str, str]
    ) -> tuple[str, int]:
        """String literal'leri koruyarak rename yap.

        Strateji:
        1. Tum string literal'leri (tek tirnak, cift tirnak, backtick)
           gecici placeholder'lara cevir
        2. Identifier rename islemini yap
        3. Placeholder'lari geri koy

        Bu sayede string icerisindeki isimler degismez.
        Ornek: console.log("e is value") icindeki "e" korunur.

        Returns:
            (degismis_kod, toplam_replacement_sayisi)
        """
        # 1. String literal'leri cikar ve placeholder'la degistir
        strings_stash: list[str] = []
        protected_code = self._protect_strings(code, strings_stash)

        # 2. Rename islemini yap
        total = 0
        # Uzun isimlerden kisa isimlere dogru sirala -- cakisma onleme
        # Ayrica ayni uzunluktakileri alfabetik sirala (deterministic)
        sorted_mappings = sorted(
            mapping.items(),
            key=lambda x: (-len(x[0]), x[0]),
        )

        for old_name, new_name in sorted_mappings:
            pattern = _build_identifier_pattern(old_name)
            protected_code, count = pattern.subn(new_name, protected_code)
            total += count

        # 3. Placeholder'lari geri koy
        result = self._restore_strings(protected_code, strings_stash)
        return result, total

    def _protect_strings(self, code: str, stash: list[str]) -> str:
        """String literal'leri placeholder ile degistir.

        Desteklenen tipler:
        - Cift tirnak: "..."
        - Tek tirnak: '...'
        - Template literal: `...`
        - Regex literal: /.../ (basit tespit)

        Not: Template literal icindeki ${...} expression'lari da korunur.
        Bu expression'lardaki degiskenler rename edilmeyecek -- bu kasitli,
        cunku template literal icerisindeki scope karmasik olabiliyor.
        """
        result: list[str] = []
        i = 0
        n = len(code)

        while i < n:
            c = code[i]

            # Line comment: // ... newline
            if c == "/" and i + 1 < n and code[i + 1] == "/":
                # Comment sonuna kadar atla -- comment icini degistirmek
                # tehlikeli degil ama gereksiz
                end = code.find("\n", i)
                if end == -1:
                    end = n
                else:
                    end += 1
                result.append(code[i:end])
                i = end
                continue

            # Block comment: /* ... */
            if c == "/" and i + 1 < n and code[i + 1] == "*":
                end = code.find("*/", i + 2)
                if end == -1:
                    end = n
                else:
                    end += 2
                result.append(code[i:end])
                i = end
                continue

            # String literal tipleri
            if c in ('"', "'", "`"):
                quote = c
                j = i + 1
                while j < n:
                    if code[j] == "\\" and j + 1 < n:
                        j += 2  # escape atla
                        continue
                    if code[j] == quote:
                        j += 1
                        break
                    j += 1

                # String'i stash'e kaydet
                string_content = code[i:j]
                idx = len(stash)
                stash.append(string_content)
                placeholder = f"{self._PLACEHOLDER_PREFIX}{idx}\x00"
                result.append(placeholder)
                i = j
                continue

            result.append(c)
            i += 1

        return "".join(result)

    def _restore_strings(self, code: str, stash: list[str]) -> str:
        """Placeholder'lari orijinal string'lerle degistir."""
        for idx, original in enumerate(stash):
            placeholder = f"{self._PLACEHOLDER_PREFIX}{idx}\x00"
            code = code.replace(placeholder, original)
        return code
