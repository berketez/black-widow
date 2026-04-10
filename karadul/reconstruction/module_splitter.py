"""Webpack modullerini mantiksal dosyalara ayir.

Webpack unpack ciktisindaki module_*.js dosyalarini okur, her modulun
rolunu belirler (React component, hook, utility, API, config) ve
uygun dizin yapisi altina yerlestirir. Import/export baglantilari
guncellenir.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from karadul.config import Config

logger = logging.getLogger(__name__)


# Kategori tanimlari -- modul icerik analizi ile eslestirme
_CATEGORY_PATTERNS: dict[str, list[re.Pattern]] = {
    "components": [
        re.compile(r"React\.createElement", re.IGNORECASE),
        re.compile(r"render\s*\("),
        re.compile(r"Component\s*\{"),
        re.compile(r"jsx|JSX"),
        re.compile(r"useState|useEffect|useRef|useMemo|useCallback"),
    ],
    "hooks": [
        re.compile(r"^(export\s+)?(function\s+)?use[A-Z]", re.MULTILINE),
        re.compile(r"return\s*\[.*useState"),
    ],
    "api": [
        re.compile(r"fetch\s*\("),
        re.compile(r"axios\.\w+\s*\("),
        re.compile(r"XMLHttpRequest"),
        re.compile(r"\.get\s*\(\s*['\"/]"),
        re.compile(r"\.post\s*\(\s*['\"/]"),
        re.compile(r"baseURL|endpoint|api[_-]?url", re.IGNORECASE),
    ],
    "utils": [
        re.compile(r"module\.exports\s*=\s*\{"),
        re.compile(r"export\s+(function|const|class)"),
        re.compile(r"exports\.\w+\s*="),
    ],
    "config": [
        re.compile(r"config|configuration|settings|options", re.IGNORECASE),
        re.compile(r"process\.env"),
        re.compile(r"\.env\b"),
        re.compile(r"defaults?\s*=\s*\{"),
    ],
    "types": [
        re.compile(r"type\s+\w+\s*="),
        re.compile(r"interface\s+\w+"),
        re.compile(r"enum\s+\w+"),
        re.compile(r"PropTypes"),
    ],
}


@dataclass
class SplitResult:
    """Module splitting sonucu.

    Attributes:
        success: Splitting basarili mi.
        total_modules: Toplam modul sayisi.
        categorized: Kategori -> modul sayisi eslesmesi.
        output_dir: Cikti dizini.
        entry_point: Entry point dosyasi yolu (varsa).
        module_map: Modul ID -> yeni dosya yolu eslesmesi.
        errors: Hata mesajlari.
    """

    success: bool
    total_modules: int
    categorized: dict[str, int]
    output_dir: Path | None
    entry_point: Path | None
    module_map: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class ModuleSplitter:
    """Webpack modullerini mantiksal dosyalara ayir.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def split(
        self,
        modules_dir: Path,
        output_dir: Path,
        static_results: dict | None = None,
    ) -> SplitResult:
        """Modulleri kategorilere ayir.

        Args:
            modules_dir: Webpack unpack ciktisindaki modullerin bulundugu dizin.
            output_dir: Kategorize edilmis modullerin yazilacagi dizin.
            static_results: Statik analiz sonuclari (import/export bilgisi).

        Returns:
            SplitResult: Sonuc.
        """
        errors: list[str] = []

        if not modules_dir.exists():
            return SplitResult(
                success=False,
                total_modules=0,
                categorized={},
                output_dir=None,
                entry_point=None,
                errors=[f"Modul dizini bulunamadi: {modules_dir}"],
            )

        # Modul dosyalarini bul
        module_files = sorted(modules_dir.glob("module_*.js"))
        if not module_files:
            # Direkt .js dosyalarini da dene
            module_files = sorted(modules_dir.glob("*.js"))

        if not module_files:
            return SplitResult(
                success=False,
                total_modules=0,
                categorized={},
                output_dir=None,
                entry_point=None,
                errors=["Modul dosyasi bulunamadi"],
            )

        # Cikti dizinlerini olustur
        categories = ["components", "hooks", "api", "utils", "config", "types", "src"]
        for cat in categories:
            (output_dir / cat).mkdir(parents=True, exist_ok=True)

        categorized: dict[str, int] = {cat: 0 for cat in categories}
        module_map: dict[str, str] = {}
        entry_point: Path | None = None

        for module_file in module_files:
            try:
                content = module_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append(f"Modul okunamadi: {module_file.name}: {exc}")
                continue

            # Modul ID'sini dosya adindan cikar
            module_id = self._extract_module_id(module_file.name)

            # Kategori tespit
            category = self._categorize_module(content)

            # Dosya adi olustur
            export_name = self._extract_export_name(content)
            if export_name:
                safe_name = self._safe_filename(export_name)
            else:
                safe_name = f"module_{module_id}"

            # Dosyayi yaz
            target_dir = output_dir / category
            target_file = target_dir / f"{safe_name}.js"

            # Cakisma kontrolu
            counter = 2
            while target_file.exists():
                target_file = target_dir / f"{safe_name}_{counter}.js"
                counter += 1

            try:
                # Header yorum ekle
                header = (
                    f"/**\n"
                    f" * Module {module_id} - {category}\n"
                    f" * Reconstructed by Karadul v1.0\n"
                    f" * Original: {module_file.name}\n"
                    f" */\n\n"
                )
                target_file.write_text(header + content, encoding="utf-8")
                categorized[category] = categorized.get(category, 0) + 1
                module_map[str(module_id)] = str(
                    target_file.relative_to(output_dir)
                )
            except OSError as exc:
                errors.append(f"Modul yazilamadi: {target_file}: {exc}")

            # Entry point tespiti (module 0 veya main)
            if module_id in ("0", "main", "entry"):
                entry_point = target_file

        total = len(module_files)

        # index.js olustur
        try:
            self._generate_index(output_dir, module_map, categories)
        except OSError as exc:
            errors.append(f"index.js olusturulamadi: {exc}")

        success = total > 0 and len(errors) < total
        logger.info(
            "Module splitting: %d modul -> %s",
            total,
            ", ".join(f"{cat}:{n}" for cat, n in categorized.items() if n > 0),
        )

        return SplitResult(
            success=success,
            total_modules=total,
            categorized=categorized,
            output_dir=output_dir,
            entry_point=entry_point,
            module_map=module_map,
            errors=errors,
        )

    def _categorize_module(self, content: str) -> str:
        """Modul iceriginden kategori tespit et.

        Args:
            content: JS modul icerigi.

        Returns:
            Kategori adi (components, hooks, api, utils, config, types, src).
        """
        scores: dict[str, int] = {}

        for category, patterns in _CATEGORY_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if pattern.search(content):
                    score += 1
            if score > 0:
                scores[category] = score

        if not scores:
            return "src"  # Varsayilan kategori

        # Hooks, components'den once kontrol: eger "use" prefix ile baslayan
        # fonksiyon export ediliyorsa hooks olsun
        if "hooks" in scores and scores.get("hooks", 0) >= scores.get("components", 0):
            return "hooks"

        return max(scores, key=lambda k: scores[k])

    @staticmethod
    def _extract_module_id(filename: str) -> str:
        """Dosya adindan modul ID'sini cikar.

        Args:
            filename: module_0.js, module_42.js, vb.

        Returns:
            Modul ID string'i.
        """
        match = re.search(r"module[_-]?(\w+)", filename)
        if match:
            return match.group(1)
        return Path(filename).stem

    @staticmethod
    def _extract_export_name(content: str) -> str | None:
        """Modul iceriginden export edilen ismi cikar.

        Ornek: exports.MyComponent = ..., module.exports = MyClass, vb.
        """
        # exports.X = pattern
        match = re.search(r"exports\.(\w+)\s*=", content)
        if match and match.group(1) not in ("__esModule", "default"):
            return match.group(1)

        # class X veya function X
        match = re.search(r"(?:class|function)\s+([A-Z]\w+)", content)
        if match:
            return match.group(1)

        # const X = React.createElement / React.memo / React.forwardRef
        match = re.search(
            r"(?:const|var|let)\s+([A-Z]\w+)\s*=\s*React\.",
            content,
        )
        if match:
            return match.group(1)

        return None

    @staticmethod
    def _safe_filename(name: str) -> str:
        """Dosya adi icin guvenli isim donusumu."""
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
        # camelCase -> kebab-case
        safe = re.sub(r"([a-z])([A-Z])", r"\1-\2", safe).lower()
        return safe or "module"

    @staticmethod
    def _generate_index(
        output_dir: Path,
        module_map: dict[str, str],
        categories: list[str],
    ) -> None:
        """Proje icin index.js dosyasi olustur.

        Args:
            output_dir: Cikti dizini.
            module_map: Modul ID -> dosya yolu eslesmesi.
            categories: Kategori listesi.
        """
        lines = [
            "/**",
            " * Auto-generated index - Karadul v1.0 Reconstruction",
            " */",
            "",
        ]

        for cat in categories:
            cat_dir = output_dir / cat
            if not cat_dir.exists():
                continue
            js_files = sorted(cat_dir.glob("*.js"))
            if not js_files:
                continue
            lines.append(f"// --- {cat.upper()} ---")
            for js_file in js_files:
                rel = js_file.relative_to(output_dir)
                module_name = js_file.stem.replace("-", "_")
                lines.append(
                    f'// const {module_name} = require("./{rel}");'
                )
            lines.append("")

        lines.append("// Entry point")
        if "0" in module_map:
            lines.append(f'require("./{module_map["0"]}");')
        else:
            lines.append("// No entry point detected")

        lines.append("")

        index_path = output_dir / "index.js"
        index_path.write_text("\n".join(lines), encoding="utf-8")
