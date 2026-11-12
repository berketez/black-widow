"""Output Formatter -- workspace ciktisini temiz, okunabilir dizin yapisina donusturur.

Pipeline ciktisini (workspace) alir ve kullaniciya sunulacak temiz bir
output dizini uretir. Dil tipine gore farkli strateji uygular:
  - Binary (C/C++): src/ altina module bazli .c/.h dosyalari
  - JS: src/ altina module bazli .js dosyalari
  - Swift: src/ altina .swift dosyalari

Cikti yapisi:
  output/
    src/                   # Yeniden kurulan kaynak; yerleşim kaynağa bağlı: CProjectBuilder
                           # ağacı (src/src/subsystem_*, include/, Makefile …) ya da proje
                           # ağacı yoksa main.c + modules/ + types/
    report.json            # Detayli analiz raporu
    report.html            # Gorsel rapor (browser'da acilabilir)
    naming_map.json        # İsim eşleştirmeleri
    dependency_graph.json  # Bagimlilik grafigi
    README.md              # Analiz özeti; anlattığı dizin yapısı diskteki çıktıdan üretilir
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.core.naming_labels import (
    NAMING_PROVENANCE_FILE,
    PROVENANCE_GLOBAL,
    SOURCE_C_NAMER,
    provenance_channel,
    provenance_confidence,
    provenance_evidence,
    provenance_label,
)
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# README'nin "Output Structure" bölümünde bir dizin için sıralanan en çok girdi; fazlası tek satırda
# sayıyla özetlenir (düz src/ binlerce dosya taşıyabilir).
README_TREE_MAX_ENTRIES = 20

# Biçimlendiricinin kendi yazdığı üst düzey çıktıların açıklaması. Yalnız diskte bulunan girdiye
# yazılır; listede olmayan girdi açıklamasız gösterilir.
_README_ENTRY_DESCRIPTIONS = {
    "src": "Reconstructed source code",
    "report.json": "Machine-readable analysis report",
    "report.html": "Visual report (open in browser)",
    "naming_map.json": "Name mappings and candidates (see Summary)",
    "dependency_graph.json": "Call graph / dependency info",
    "README.md": "This file",
}

# --- Temiz ad haritası (DIR/naming_map.json) -------------------------------------------------
# Biçim 1.1: ``mappings`` yalnız temiz çıktının koduna uygulanmış adlardır; geri kalan kayıtlar
# silinmez, gerekçesiyle ``candidates`` bölümüne taşınır. 1.0'da ``mappings`` toplanan her kaydı
# taşıyordu (imza veritabanı, bayt kalıbı vb. önerileri, eski = yeni girişler dahil).
NAMING_MAP_FORMAT_VERSION = "1.1"
# ``applied_check``: ``mappings``'in nasıl süzüldüğü.
APPLIED_CHECK_C_SOURCE = "c_source"        # src/ altındaki C kodunda doğrulandı
APPLIED_CHECK_NOT_CHECKED = "not_checked"  # doğrulanacak C kodu yok (ör. JS çıktısı)
# ``candidates`` kayıtlarındaki ``reason`` değerleri; geçersiz C adında ``reason``
# ``name_validity`` sözlüğündeki nedendir (invalid_c_identifier, invalid_c_keyword,
# invalid_type_name).
CANDIDATE_SAME_AS_ORIGINAL = "same_as_original"   # yeni ad, koddaki adla aynı: ad değişmedi
CANDIDATE_NOT_IN_CODE = "not_in_code"             # yeni ad temiz çıktının kodunda yok
# Adresten kurulmuş yer tutucu anahtar (c_namer ``FUN_{adres:08x}`` yazar). Ghidra o adresteki
# fonksiyona başka bir ad vermişse (``entry``, ``_FINI_0``, sembol adı) kodda geçen eski ad odur.
_ADDRESS_KEY_RE = re.compile(r"(?:FUN|sub)_([0-9a-fA-F]+)")

# Kod denetiminde okunan dosyalar ve C sözcük birimleri. Yorum ve dizgi/karakter sabitleri
# boşlukla değiştirilir: yorumdaki ``@calls FUN_x`` ya da dizgideki ad "kodda" sayılmaz.
_C_CODE_SUFFIXES = frozenset({".c", ".h"})
_C_NON_CODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)
# Ghidra çıktısında ``$`` taşıyan adlar var (Mach-O ``_fdopen$DARWIN_EXTSN``); tek sözcük sayılır.
_C_TOKEN_RE = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*")
_C_SCOPE_RE = re.compile(r"[{};]")
_C_TRAILING_NAME_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*$")

# Genel dalın (C/JS/Swift dışı) kopyaladığı kaynak dosya uzantıları
_GENERIC_SOURCE_SUFFIXES = frozenset({".c", ".h", ".js", ".ts", ".py", ".swift", ".go", ".java"})


@dataclass
class FormatResult:
    """Output formatting sonucu.

    Attributes:
        success: Basarili mi.
        output_dir: Cikti dizini.
        files_written: Yazilan dosya sayisi.
        src_files: src/ altindaki dosya sayisi.
        reports_generated: Uretilen rapor sayisi.
        errors: Hata mesajlari.
    """
    success: bool
    output_dir: Path
    files_written: int = 0
    src_files: int = 0
    reports_generated: int = 0
    errors: list[str] = field(default_factory=list)
    # Başarıyı bozmayan ama kullanıcının bilmesi gereken durumlar (ör. son aşamalar çıktı
    # üretmediği için daha erken bir aşamanın kaynağına düşüldü).
    warnings: list[str] = field(default_factory=list)


class OutputFormatter:
    """Workspace ciktisini temiz dizin yapisina donusturucu.

    Pipeline calismasi tamamlandiktan sonra, workspace'teki ham ciktiyi
    alir ve okunabilir, organize bir dizin yapisi uretir.

    Args:
        workspace: Pipeline workspace'i.
        pipeline_result: Pipeline calisma sonucu.
    """

    def __init__(
        self,
        workspace: Workspace,
        pipeline_result: PipelineResult,
    ) -> None:
        self._workspace = workspace
        self._result = pipeline_result
        self._warnings: list[str] = []

    def format_output(self, output_dir: Path, fmt: str = "clean") -> FormatResult:
        """Ciktiyi formatla.

        Args:
            output_dir: Hedef cikti dizini.
            fmt: Format tipi ("clean" veya "raw").

        Returns:
            FormatResult: Formatlama sonucu.
        """
        if fmt == "raw":
            return self._format_raw(output_dir)
        return self._format_clean(output_dir)

    def _format_raw(self, output_dir: Path) -> FormatResult:
        """Ham workspace ciktisini oldugu gibi kopyala."""
        errors: list[str] = []
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            ws_path = self._workspace.path
            files_written = 0
            for item in ws_path.iterdir():
                if item.is_dir():
                    dest = output_dir / item.name
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                    files_written += sum(1 for _ in dest.rglob("*") if _.is_file())
                elif item.is_file():
                    shutil.copy2(item, output_dir / item.name)
                    files_written += 1
        except Exception as exc:
            errors.append(f"Raw copy hatasi: {exc}")
            return FormatResult(
                success=False,
                output_dir=output_dir,
                errors=errors,
            )

        return FormatResult(
            success=True,
            output_dir=output_dir,
            files_written=files_written,
            errors=errors,
        )

    def _format_clean(self, output_dir: Path) -> FormatResult:
        """Temiz, organize cikti dizini uret."""
        errors: list[str] = []
        self._warnings = []
        files_written = 0
        src_files = 0

        output_dir.mkdir(parents=True, exist_ok=True)
        src_dir = output_dir / "src"
        src_dir.mkdir(exist_ok=True)

        # Dil tespiti
        language = self._detect_language()

        # 1. Kaynak dosyalarini kopyala ve organize et
        # Başka dilden derlenmiş ikilinin (C++, Rust, Go …) yeniden kurulan kaynağı da Ghidra'nın
        # C'sidir: reconstructed/ altında yalnız C varsa C dalı kullanılır. Genel dal bütün ara
        # aşamaları (annotated, merged, typed_iter1, project …) kopyalıyor ve eskiden düz
        # src/<dosya adı> yoluna yazdığı için aynı adlı dosyalar birbirini eziyordu (Debian pzstd,
        # language "cpp": 12 757 dosyadan 1 201'i kaldı; kalan, sıralı kopyada son gelen typed_iter1
        # kopyasıydı, olgun proje ağacı kayboldu).
        c_branch = language == "c" or (
            language not in ("javascript", "swift") and self._reconstructed_is_c_only()
        )
        if c_branch:
            src_count, errs = self._format_binary_sources(src_dir)
        elif language == "javascript":
            src_count, errs = self._format_js_sources(src_dir)
        elif language == "swift":
            src_count, errs = self._format_swift_sources(src_dir)
        else:
            src_count, errs = self._format_generic_sources(src_dir)

        src_files += src_count
        files_written += src_count
        errors.extend(errs)

        # Yeniden kurma asamasi kostuysa kaynak beklenir: tek dosya bile yazilamadiysa
        # sonuc basarili SAYILMAZ (raporlar yazilsa da). Reconstruct kosmadiysa
        # (or. --stage static) kaynaksiz cikti olagandir.
        reconstruct_ran = "reconstruct" in getattr(self._result, "stages", {})
        sources_missing = c_branch and reconstruct_ran and src_count == 0
        if sources_missing and not errs:
            errors.append("Temiz çıktıya kaynak dosyası yazılamadı: yeniden kurulan kaynak bulunamadı")

        # 2. Naming map uret
        naming_map = self._build_naming_map(src_dir, language)
        naming_map_path = output_dir / "naming_map.json"
        try:
            naming_map_path.write_text(
                json.dumps(naming_map, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            files_written += 1
        except Exception as exc:
            errors.append(f"naming_map.json yazma hatasi: {exc}")

        # 3. Dependency graph uret
        dep_graph = self._build_dependency_graph()
        dep_graph_path = output_dir / "dependency_graph.json"
        try:
            dep_graph_path.write_text(
                json.dumps(dep_graph, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            files_written += 1
        except Exception as exc:
            errors.append(f"dependency_graph.json yazma hatasi: {exc}")

        # 4. Report JSON
        reports_generated = 0
        report_json_path = output_dir / "report.json"
        try:
            report_data = self._build_report_json()
            report_json_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            files_written += 1
            reports_generated += 1
        except Exception as exc:
            errors.append(f"report.json yazma hatasi: {exc}")

        # 5. Report HTML
        report_html_path = output_dir / "report.html"
        try:
            from karadul.core.report_generator import ReportGenerator
            generator = ReportGenerator(self._result, self._workspace)
            html_content = generator.generate_html()
            report_html_path.write_text(html_content, encoding="utf-8")
            files_written += 1
            reports_generated += 1
        except Exception as exc:
            errors.append(f"report.html yazma hatasi: {exc}")

        # 6. README.md
        readme_path = output_dir / "README.md"
        try:
            readme_content = self._build_readme(language, src_files, naming_map, output_dir)
            readme_path.write_text(readme_content, encoding="utf-8")
            files_written += 1
        except Exception as exc:
            errors.append(f"README.md yazma hatasi: {exc}")

        success = (src_files > 0 or reports_generated > 0) and not sources_missing
        return FormatResult(
            success=success,
            output_dir=output_dir,
            files_written=files_written,
            src_files=src_files,
            reports_generated=reports_generated,
            errors=errors,
            warnings=list(self._warnings),
        )

    def _detect_language(self) -> str:
        """Pipeline sonucundan dil tespit et."""
        if "identify" in self._result.stages:
            lang = self._result.stages["identify"].stats.get("language", "")
            # identify stage stripped binary'lerde kaynak dili cikaramaz ve
            # LITERAL "unknown" yazar. Bu gecerli bir dil DEGIL; oyle kabul
            # edilirse _format_clean C dalina hic giremez, generic dala duser
            # ve reconstructed/ altindaki TUM ara asamalar (annotated, merged,
            # typed, commented, struct_recovered...) src/ altina DUZ kopyalanir.
            # Ayni isimli dosyalar birbirini ezer, alfabetik son gelen kazanir
            # (typed_iter1) -> kullanicinin en olgun ciktisi (commented yorumlar
            # + subsystem'lere ayrilmis project/ agaci) sessizce kaybolur, ustelik
            # ~1600 gereksiz dosya kopyalanir. "unknown" -> fallback tahminine dus.
            if lang and lang.lower() != "unknown":
                return lang.lower()

        # Fallback: workspace dosyalarindan tahmin
        reconstructed = self._workspace.get_stage_dir("reconstructed")
        if list(reconstructed.rglob("*.c")):
            return "c"
        if list(reconstructed.rglob("*.js")):
            return "javascript"
        if list(reconstructed.rglob("*.swift")):
            return "swift"
        return "unknown"

    # ------------------------------------------------------------------
    # Binary (C/C++) source formatting
    # ------------------------------------------------------------------
    def _format_binary_sources(self, src_dir: Path) -> tuple[int, list[str]]:
        """Binary reconstruction ciktisini src/ altina organize et."""
        errors: list[str] = []
        files_written = 0

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # CProjectBuilder ciktisi varsa (project/ dizini) VE icinde kaynak varsa.
        # Dizin var ama bossa (sonraki asamalar cikti uretmediyse) eskiden 0 dosya
        # kopyalanip "basarili" deniyordu: kullanici bos bir src/ aliyordu. Bos proje
        # dizini kullanilmaz; en olgun DOLU asamaya dusulur ve bu uyari olarak yazilir.
        project_dir = reconstructed / "project"
        if project_dir.exists() and any(project_dir.rglob("*.c")):
            files_written += self._copy_project_tree(project_dir, src_dir, errors)
            return files_written, errors
        if project_dir.exists():
            self._warnings.append(
                "Proje ağacı (reconstructed/project) boş: son aşamalar kaynak üretmedi; "
                "daha erken bir aşamanın çıktısı kullanıldı (yorum ve alt sistem klasörleri yok)"
            )

        # Yoksa en son islenenmis kaynagi bul
        # Oncelik: commented > typed > merged > decompiled
        source_dir = self._find_best_binary_source(reconstructed)
        if source_dir is None:
            errors.append("Binary reconstructed kaynak bulunamadi")
            return 0, errors

        # Ana dosya ve moduller
        modules_dir = src_dir / "modules"
        types_dir = src_dir / "types"
        modules_dir.mkdir(exist_ok=True)
        types_dir.mkdir(exist_ok=True)

        c_files = sorted(source_dir.rglob("*.c"))
        h_files = sorted(source_dir.rglob("*.h"))

        # main.c veya entry point tespiti
        main_candidates = ["main.c", "entry.c", "_main.c"]
        main_file = None
        module_files = []

        for f in c_files:
            if f.name.lower() in main_candidates:
                main_file = f
            else:
                module_files.append(f)

        # Entry point yoksa en buyuk dosyayi main yap
        if main_file is None and module_files:
            main_file = max(module_files, key=lambda f: f.stat().st_size)
            module_files.remove(main_file)

        # main.c kopyala
        if main_file:
            content = main_file.read_text(encoding="utf-8", errors="replace")
            content = self._clean_c_source(content)
            (src_dir / "main.c").write_text(content, encoding="utf-8")
            files_written += 1

        # Modul dosyalarini kategorize et
        for f in module_files:
            content = f.read_text(encoding="utf-8", errors="replace")
            category = self._categorize_c_module(f.name, content)
            dest_name = self._clean_filename(f.name)
            content = self._clean_c_source(content)
            dest = modules_dir / dest_name
            dest.write_text(content, encoding="utf-8")
            files_written += 1

        # Header dosyalari -> types/
        for f in h_files:
            content = f.read_text(encoding="utf-8", errors="replace")
            dest_name = self._clean_filename(f.name)
            (types_dir / dest_name).write_text(content, encoding="utf-8")
            files_written += 1

        # types.h kurtarildiysa kontrol et
        types_header = reconstructed / "types.h"
        if types_header.exists():
            content = types_header.read_text(encoding="utf-8", errors="replace")
            (types_dir / "types.h").write_text(content, encoding="utf-8")
            files_written += 1

        # Bos dizinleri temizle
        if not list(modules_dir.iterdir()):
            modules_dir.rmdir()
        if not list(types_dir.iterdir()):
            types_dir.rmdir()

        return files_written, errors

    def _find_best_binary_source(self, reconstructed: Path) -> Optional[Path]:
        """En iyi binary kaynak dizinini bul (en son islenmis)."""
        candidates = [
            reconstructed / "commented",
            reconstructed / "typed",
            reconstructed / "merged",
        ]
        for candidate in candidates:
            if candidate.exists() and list(candidate.rglob("*.c")):
                return candidate

        # Decompiled fallback
        deob_dir = self._workspace.get_stage_dir("deobfuscated")
        decompiled = deob_dir / "decompiled"
        if decompiled.exists() and list(decompiled.rglob("*.c")):
            return decompiled

        static_dir = self._workspace.get_stage_dir("static")
        ghidra_decompiled = static_dir / "ghidra_output" / "decompiled"
        if ghidra_decompiled.exists() and list(ghidra_decompiled.rglob("*.c")):
            return ghidra_decompiled

        return None

    def _copy_project_tree(
        self, project_dir: Path, src_dir: Path, errors: list[str],
    ) -> int:
        """CProjectBuilder ciktisini src/ altina kopyala."""
        files_written = 0
        try:
            for item in project_dir.iterdir():
                if item.is_dir():
                    dest = src_dir / item.name
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                    files_written += sum(1 for f in dest.rglob("*") if f.is_file())
                elif item.is_file():
                    shutil.copy2(item, src_dir / item.name)
                    files_written += 1
        except Exception as exc:
            errors.append(f"Project tree kopyalama hatasi: {exc}")
        return files_written

    # ------------------------------------------------------------------
    # JS source formatting
    # ------------------------------------------------------------------
    def _format_js_sources(self, src_dir: Path) -> tuple[int, list[str]]:
        """JS reconstruction ciktisini src/ altina organize et."""
        errors: list[str] = []
        files_written = 0

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # named_project varsa (NamingPipeline ciktisi)
        named_project = reconstructed / "named_project"
        if named_project.exists():
            files_written += self._copy_project_tree(named_project, src_dir, errors)
            return files_written, errors

        # Project dir (ProjectBuilder/Reconstructor ciktisi)
        project_dir = reconstructed / "project"
        if project_dir.exists():
            files_written += self._copy_project_tree(project_dir, src_dir, errors)
            return files_written, errors

        # Modules dir
        modules_dir_src = reconstructed / "modules"
        if modules_dir_src.exists():
            dest_modules = src_dir / "modules"
            dest_modules.mkdir(exist_ok=True)
            for f in sorted(modules_dir_src.rglob("*.js")):
                rel = f.relative_to(modules_dir_src)
                dest = dest_modules / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                content = f.read_text(encoding="utf-8", errors="replace")
                content = self._clean_js_source(content)
                dest.write_text(content, encoding="utf-8")
                files_written += 1

        # Ana kaynak dosyayi bul
        # Oncelik: commented > typed > params > nsa_named > renamed > deobfuscated
        main_file = self._find_best_js_source(reconstructed)
        if main_file:
            content = main_file.read_text(encoding="utf-8", errors="replace")
            content = self._clean_js_source(content)
            (src_dir / "main.js").write_text(content, encoding="utf-8")
            files_written += 1

        if files_written == 0:
            errors.append("JS reconstructed kaynak bulunamadi")

        return files_written, errors

    def _find_best_js_source(self, reconstructed: Path) -> Optional[Path]:
        """En iyi islenmis JS kaynak dosyasini bul."""
        # Suffix oncelik sirasi (en cok islenmis en once)
        suffixes = [".commented.js", ".typed.js", ".params.js", ".nsa_named.js", ".renamed.js"]
        for suffix in suffixes:
            candidates = list(reconstructed.glob(f"*{suffix}"))
            if candidates:
                return max(candidates, key=lambda f: f.stat().st_size)

        # Deobfuscated fallback
        deob_dir = self._workspace.get_stage_dir("deobfuscated")
        js_files = sorted(deob_dir.rglob("*.js"))
        if js_files:
            return max(js_files, key=lambda f: f.stat().st_size)

        return None

    # ------------------------------------------------------------------
    # Swift source formatting
    # ------------------------------------------------------------------
    def _format_swift_sources(self, src_dir: Path) -> tuple[int, list[str]]:
        """Swift reconstruction ciktisini src/ altina organize et."""
        errors: list[str] = []
        files_written = 0

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # Swift decompiled dosyalari (binary reconstruction uzerinden)
        swift_files = sorted(reconstructed.rglob("*.swift"))

        if not swift_files:
            # C ciktisini kullan (Ghidra hala C uretir)
            return self._format_binary_sources(src_dir)

        modules_dir = src_dir / "modules"
        modules_dir.mkdir(exist_ok=True)

        for f in swift_files:
            content = f.read_text(encoding="utf-8", errors="replace")
            dest = modules_dir / f.name
            dest.write_text(content, encoding="utf-8")
            files_written += 1

        return files_written, errors

    # ------------------------------------------------------------------
    # Generic source formatting
    # ------------------------------------------------------------------
    def _reconstructed_is_c_only(self) -> bool:
        """``reconstructed/`` altındaki kaynak dosyaları yalnız C mi (en az bir ``.c``, başka dil yok).

        Başka dilden kaynak da varsa (ör. ``.py`` ile ikilinin C'si) C dalı onları almaz; genel dal
        hepsini dizin yapısıyla kopyalar.
        """
        reconstructed = self._workspace.get_stage_dir("reconstructed")
        suffixes = {p.suffix for p in reconstructed.rglob("*")
                    if p.suffix in _GENERIC_SOURCE_SUFFIXES and p.is_file()}
        return ".c" in suffixes and suffixes <= _C_CODE_SUFFIXES

    def _format_generic_sources(self, src_dir: Path) -> tuple[int, list[str]]:
        """Bilinmeyen dil icin generic formatting."""
        errors: list[str] = []
        files_written = 0

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # Tum kaynak dosyalarini topla. Göreli yol korunur: aynı adlı iki dosya (farklı aşama ya da
        # paket dizini, ör. iki __init__.py) aynı src/<ad> yoluna yazılıp birbirini ezmesin.
        for f in sorted(reconstructed.rglob("*")):
            if f.is_file() and f.suffix in _GENERIC_SOURCE_SUFFIXES:
                dest = src_dir / f.relative_to(reconstructed)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                files_written += 1

        if files_written == 0:
            errors.append("Reconstructed kaynak dosya bulunamadi")

        return files_written, errors

    # ------------------------------------------------------------------
    # Naming map
    # ------------------------------------------------------------------
    def _build_naming_map(
        self, src_dir: Optional[Path] = None, language: str = "",
    ) -> dict[str, Any]:
        """Kaynaklardaki ad kayıtlarını topla; koda uygulananları ``mappings``'e ayır.

        Toplama sırası ve üstüne yazma kuralı değişmedi (binary_names, imza, bayt kalıbı,
        hesaplama kurtarma, JS manifestosu, c_namer; c_namer yer tutucu anahtarlarda kazanır).
        Ayırma :meth:`_separate_candidates`'te: ``src_dir`` temiz çıktının kaynak dizinidir;
        verilmezse kod denetimi yapılamaz (``applied_check: not_checked``).
        """
        naming_map: dict[str, Any] = {
            "version": NAMING_MAP_FORMAT_VERSION,
            "target": self._result.target_name,
            "mappings": {},
            "sources": [],
        }

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # 1. Binary names
        binary_names = self._workspace.load_json("reconstructed", "binary_names")
        if binary_names:
            names = binary_names.get("names", {})
            for orig, info in names.items():
                if isinstance(info, dict):
                    naming_map["mappings"][orig] = {
                        "new_name": info.get("recovered", orig),
                        "source": info.get("source", "binary_extractor"),
                        "confidence": info.get("confidence", 0.0),
                    }
            if names:
                naming_map["sources"].append("binary_name_extractor")

        # 2. Signature matches
        sig_matches = self._workspace.load_json("reconstructed", "signature_matches")
        if sig_matches:
            for match in sig_matches.get("matches", []):
                orig = match.get("original", "")
                if orig:
                    naming_map["mappings"][orig] = {
                        "new_name": match.get("matched", orig),
                        "source": "signature_db",
                        "confidence": match.get("confidence", 0.0),
                        "library": match.get("library", ""),
                    }
            naming_map["sources"].append("signature_db")

        # 3. Byte pattern matches
        bp_matches = self._workspace.load_json("reconstructed", "byte_pattern_matches")
        if bp_matches:
            for match in bp_matches.get("matches", []):
                if isinstance(match, dict):
                    orig = match.get("original_name", "")
                    if orig and orig not in naming_map["mappings"]:
                        naming_map["mappings"][orig] = {
                            "new_name": match.get("matched_name", orig),
                            "source": "byte_pattern",
                            "confidence": match.get("confidence", 0.0),
                        }
            naming_map["sources"].append("byte_pattern")

        # 4. Computation Recovery naming (signature fusion, CFG match)
        comp_recovery = self._workspace.load_json("reconstructed", "computation_recovery")
        if comp_recovery and comp_recovery.get("success"):
            fusion_layer = comp_recovery.get("layer_results", {}).get(
                "signature_fusion", {},
            )
            identifications = fusion_layer.get("identifications", {})
            _comp_added = 0
            for addr, fid in identifications.items():
                func_name = fid.get("function_name", "")
                if not func_name:
                    continue
                # Zaten baska kaynak tarafindan isimlendirilmisse atlama
                if func_name in naming_map["mappings"]:
                    continue
                # Sadece unnamed fonksiyonlara isim ver
                if not (func_name.startswith("FUN_") or func_name.startswith("sub_")
                        or func_name.startswith("thunk_")):
                    continue
                identified_as = fid.get("identified_as", "")
                fused_conf = fid.get("fused_confidence", 0.0)
                if identified_as and fused_conf >= 0.40:
                    # identified_as'i fonksiyon ismine cevir
                    clean_name = identified_as.replace(" ", "_").replace("-", "_").lower()
                    naming_map["mappings"][func_name] = {
                        "new_name": clean_name,
                        "source": "computation_recovery",
                        "confidence": fused_conf,
                        "category": fid.get("category", ""),
                    }
                    _comp_added += 1
            if _comp_added:
                naming_map["sources"].append("computation_recovery")

        # 5. Naming manifest (JS)
        naming_manifest_path = reconstructed / "named_project" / "naming-manifest.json"
        if naming_manifest_path.exists():
            try:
                manifest_data = json.loads(
                    naming_manifest_path.read_text(encoding="utf-8")
                )
                if isinstance(manifest_data, dict):
                    modules = manifest_data.get("modules", {})
                    for mod_id, mod_info in modules.items():
                        if isinstance(mod_info, dict) and mod_info.get("name"):
                            naming_map["mappings"][mod_id] = {
                                "new_name": mod_info["name"],
                                "source": mod_info.get("source", "naming_pipeline"),
                                "confidence": mod_info.get("confidence", 0.0),
                            }
                    naming_map["sources"].append("naming_pipeline")
            except (json.JSONDecodeError, OSError):
                pass

        # 6. C namer global renames (FUN_/DAT_ -> birlestirilmis final isim)
        # c_namer, reconstructed/src[/_iterN]/naming_map.json'a
        #   {"global": {"FUN_00101149": "quotearg", ...}, "per_function": {...}}
        # formatinda yazar (c_namer.py:1385-1396). Stripped ELF'te fonksiyon
        # isimlerinin ASIL kaynagi budur; onceki adimlar sadece import/kutuphane
        # isim-anahtarli girisleri doldurur. c_namer'in birlestirilmis (merged)
        # final ismi asildir -> mevcut FUN_/DAT_ girislerini ezer.
        # per_function bolumu lokal degisken adlaridir (fonksiyon-ici, cakisan
        # anahtarlar); duz sembol haritasina uymadigi icin dahil edilmez.
        placeholder_prefixes = ("FUN_", "DAT_", "sub_", "thunk_")
        c_namer_maps: list[Path] = []
        base_src_map = reconstructed / "src" / "naming_map.json"
        if base_src_map.exists():
            c_namer_maps.append(base_src_map)
        # src_iterN artan sirada islenir -> en son iterasyon kazanir
        iter_dirs = sorted(
            reconstructed.glob("src_iter*"),
            key=lambda p: (
                int(p.name[len("src_iter"):])
                if p.name[len("src_iter"):].isdigit()
                else -1
            ),
        )
        for iter_dir in iter_dirs:
            iter_map = iter_dir / "naming_map.json"
            if iter_map.exists():
                c_namer_maps.append(iter_map)

        c_namer_added = 0
        for map_path in c_namer_maps:
            try:
                c_data = json.loads(map_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(c_data, dict):
                continue
            global_renames = c_data.get("global", {})
            if not isinstance(global_renames, dict):
                continue
            # Ad ve köken AYNI yinelemeden gelir: her haritanın kendi kardeş köken kaydı okunur.
            provenance = self._read_c_namer_provenance(map_path)
            for orig, new_name in global_renames.items():
                if not isinstance(orig, str) or not isinstance(new_name, str):
                    continue
                if not new_name or new_name == orig:
                    continue
                if not orig.startswith(placeholder_prefixes):
                    continue
                # Güven, etiket ve kanal köken kaydından taşınır. Kayıt yoksa ya da kayıttaki ad
                # bu haritadaki adla aynı değilse güven bilinmiyordur: ``None`` yazılır, sabit bir
                # değer uydurulmaz (eskiden her ada 1.0 yazılıyordu).
                record = provenance.get(orig)
                if not isinstance(record, dict) or record.get("new_name") != new_name:
                    record = None
                naming_map["mappings"][orig] = {
                    "new_name": new_name,
                    "source": SOURCE_C_NAMER,
                    "confidence": provenance_confidence(record),
                    "label": provenance_label(record),
                    "channel": provenance_channel(record),
                    "evidence": provenance_evidence(record),
                }
                c_namer_added += 1
        if c_namer_added:
            naming_map["sources"].append(SOURCE_C_NAMER)

        return self._separate_candidates(
            naming_map, src_dir, language, self._ghidra_names_by_address())

    def _ghidra_names_by_address(self) -> dict[int, str]:
        """``static/ghidra_functions.json``: adres -> Ghidra'nın fonksiyona verdiği ad.

        Kayıt yoksa ya da okunamıyorsa boş sözlük: anahtarlar olduğu gibi kodda aranır.
        """
        data = self._workspace.load_json("static", "ghidra_functions")
        names: dict[int, str] = {}
        functions = data.get("functions") if isinstance(data, dict) else None
        for fn in functions if isinstance(functions, list) else []:
            if not isinstance(fn, dict) or not isinstance(fn.get("name"), str):
                continue
            try:
                names.setdefault(int(str(fn.get("address", "")), 16), fn["name"])
            except ValueError:
                continue
        return names

    @classmethod
    def _separate_candidates(
        cls, naming_map: dict[str, Any], src_dir: Optional[Path], language: str,
        ghidra_names: Optional[dict[int, str]] = None,
    ) -> dict[str, Any]:
        """Toplanan kayıtları uygulanmış eşlemeler ve uygulanmamış adaylar olarak ayır.

        ``mappings`` yalnız koda uygulanmış adları taşır; ``total_mappings`` onları sayar.
        Öbür kayıtlar SİLİNMEZ: aynı alanlarıyla, ``reason`` eklenerek ``candidates``'e gider.
        Eski 1.0 haritasındaki kayıt kümesi ``mappings`` ile ``candidates``'in birleşimidir (bir
        anahtar ikisinden yalnız birindedir).

        Kod denetimi temiz çıktıda C kodu varsa ya da dil C ise yapılır (kod hiç yazılamadıysa
        hiçbir ad uygulanmış sayılmaz). Başka dilde (JS modül adları C tanımlayıcısı değildir)
        yalnız eski = yeni girişler ayrılır ve ``applied_check`` ``not_checked`` olur.
        """
        if src_dir is not None and (language == "c" or cls._has_c_code(src_dir)):
            applied_check = APPLIED_CHECK_C_SOURCE
            code = cls._scan_c_code(src_dir)
        else:
            applied_check = APPLIED_CHECK_NOT_CHECKED
            code = None
        mappings: dict[str, Any] = {}
        candidates: dict[str, Any] = {}
        for orig, record in naming_map["mappings"].items():   # kayıtlar hep sözlük (yukarıda)
            reason = cls._candidate_reason(
                orig, record.get("new_name"), code, cls._name_in_code(orig, ghidra_names or {}))
            if reason is None:
                mappings[orig] = record
            else:
                candidates[orig] = {**record, "reason": reason}
        return {
            "version": naming_map["version"],
            "target": naming_map["target"],
            "applied_check": applied_check,
            "mappings": mappings,
            "total_mappings": len(mappings),
            "candidates": candidates,
            "total_candidates": len(candidates),
            "sources": naming_map["sources"],
        }

    @staticmethod
    def _name_in_code(key: str, ghidra_names: dict[int, str]) -> str:
        """Anahtarın kodda geçmesi beklenen eski adı.

        Adresten kurulmuş yer tutucu anahtarda (``FUN_00105dc0``) Ghidra'nın o adresteki
        fonksiyona verdiği ad (``entry``); öbür anahtarlarda ve adres bilinmiyorsa anahtarın
        kendisi.
        """
        m = _ADDRESS_KEY_RE.fullmatch(key)
        if m is None:
            return key
        return ghidra_names.get(int(m.group(1), 16), key)

    @staticmethod
    def _candidate_reason(
        orig: str, new_name: Any, code: Optional[tuple[set[str], set[str]]],
        name_in_code: Optional[str] = None,
    ) -> Optional[str]:
        """Kayıt uygulanmış bir eşlemeyse ``None``; değilse ``candidates``'teki gerekçesi.

        Sıra: eski = yeni -> geçersiz C adı -> kodda yok. ``code`` ``None`` ise (denetlenecek
        C kodu yok) yalnız ilk kural uygulanır. ``name_in_code``: kodda geçmesi beklenen eski ad
        (:meth:`_name_in_code`); verilmezse anahtarın kendisi. Yeni ad onunla aynıysa kod zaten
        bu adı taşıyordu: ad değişmedi.

        Kodda uygulanmış sayılmak (``code`` = (tanımlayıcılar, tanımlanan fonksiyon adları);
        ikisi de yorum ve dizgi dışındaki koddan):
          - yeni ad bir fonksiyon tanımının adı ve eski ad hiçbir fonksiyon tanımının adı değil
            (eski ad bazı çağrılarda kalmış olsa da tanım yeni adı taşıyor); ya da
          - eski ad hiçbir tanımın adı değil, yeni ad kodda geçiyor ve eski ad kodda hiç geçmiyor
            (veri adları, gövdesi çıktıda olmayan fonksiyonlar).
        Eski ad hâlâ bir tanımın adıysa öneri o fonksiyona uygulanmamıştır; yeni ad başka bir
        fonksiyonun tanımında ya da bir alan/yerel adı olarak geçse bile (``start``).
        """
        if new_name == orig or new_name == name_in_code:
            return CANDIDATE_SAME_AS_ORIGINAL
        if code is None:
            return None
        old = name_in_code or orig
        from karadul.reconstruction.name_validity import lexical_reject_reason

        invalid = lexical_reject_reason(new_name)
        if invalid is not None:
            return invalid
        identifiers, defined = code
        if new_name in defined and old not in defined:
            return None
        if old not in defined and new_name in identifiers and old not in identifiers:
            return None
        return CANDIDATE_NOT_IN_CODE

    @staticmethod
    def _has_c_code(src_dir: Path) -> bool:
        """``src_dir`` altında en az bir .c/.h dosyası var mı."""
        if not src_dir.is_dir():
            return False
        return any(p.suffix in _C_CODE_SUFFIXES and p.is_file() for p in src_dir.rglob("*"))

    @classmethod
    def _scan_c_code(cls, src_dir: Path) -> tuple[set[str], set[str]]:
        """``src_dir`` altındaki .c/.h kodunun tanımlayıcıları ve tanımlanan fonksiyon adları.

        Yorumlar ve dizgi/karakter sabitleri atılır. Fonksiyon tanımı: dosya kapsamında (ayraç
        derinliği 0) açılan ``{``'den önceki başlık ``ad(...)`` ile bitiyorsa ``ad``; C anahtar
        sözcükleri sayılmaz (dengesiz bir ayraçtan sonra ``if (...) {`` tanım sanılmasın).
        Dizin yoksa iki küme de boştur.
        """
        identifiers: set[str] = set()
        defined: set[str] = set()
        if not src_dir.is_dir():
            return identifiers, defined
        for path in sorted(src_dir.rglob("*")):
            if path.suffix not in _C_CODE_SUFFIXES or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            code = _C_NON_CODE_RE.sub(" ", text)
            identifiers.update(_C_TOKEN_RE.findall(code))
            defined.update(cls._defined_function_names(code))
        return identifiers, defined

    @staticmethod
    def _defined_function_names(code: str) -> set[str]:
        """Yorumsuz C metninde dosya kapsamında tanımlanan fonksiyonların adları."""
        from karadul.reconstruction.name_validity import C_KEYWORDS

        names: set[str] = set()
        depth = 0
        boundary = 0
        for m in _C_SCOPE_RE.finditer(code):
            ch = m.group()
            if ch == "{":
                if depth == 0:
                    name = OutputFormatter._definition_name(code[boundary:m.start()])
                    if name is not None and name not in C_KEYWORDS:
                        names.add(name)
                depth += 1
            elif ch == "}":
                depth = max(depth - 1, 0)
                if depth == 0:
                    boundary = m.end()
            elif depth == 0:
                boundary = m.end()
        return names

    @staticmethod
    def _definition_name(header: str) -> Optional[str]:
        """``... ad(parametreler)`` biçiminde biten başlıktaki ``ad``; değilse ``None``.

        Son ``)``'nin eşi olan ``(`` geriye doğru sayılarak bulunur (parametrede iç içe ayraç
        olabilir: işlev göstericisi).
        """
        head = header.rstrip()
        if not head.endswith(")"):
            return None
        depth = 0
        for i in range(len(head) - 1, -1, -1):
            if head[i] == ")":
                depth += 1
            elif head[i] == "(":
                depth -= 1
                if depth == 0:
                    m = _C_TRAILING_NAME_RE.search(head, 0, i)
                    return m.group(1) if m else None
        return None

    @staticmethod
    def _read_c_namer_provenance(map_path: Path) -> dict[str, Any]:
        """``naming_map.json``'ın yanındaki köken kaydının genel (``global``) bölümü.

        Dosya yoksa, okunamıyorsa ya da biçimi beklenen gibi değilse boş sözlük döner; o zaman
        adlar güvensiz (``None``) ve "doğrulanmadı" etiketiyle yazılır.
        """
        try:
            data = json.loads((map_path.parent / NAMING_PROVENANCE_FILE).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        records = data.get(PROVENANCE_GLOBAL) if isinstance(data, dict) else None
        return records if isinstance(records, dict) else {}

    # ------------------------------------------------------------------
    # Dependency graph
    # ------------------------------------------------------------------
    def _build_dependency_graph(self) -> dict[str, Any]:
        """Bagimlilik grafigini olustur."""
        graph: dict[str, Any] = {
            "version": "1.0",
            "target": self._result.target_name,
            "nodes": [],
            "edges": [],
        }

        # Call graph JSON'u oku
        static_dir = self._workspace.get_stage_dir("static")
        deob_dir = self._workspace.get_stage_dir("deobfuscated")

        call_graph_json = deob_dir / "ghidra_call_graph.json"
        if not call_graph_json.exists():
            call_graph_json = static_dir / "ghidra_call_graph.json"

        if call_graph_json.exists():
            try:
                cg_data = json.loads(
                    call_graph_json.read_text(encoding="utf-8", errors="replace")
                )
                if isinstance(cg_data, dict):
                    # Ghidra call graph formati
                    functions = cg_data.get("functions", cg_data.get("nodes", []))
                    calls = cg_data.get("calls", cg_data.get("edges", []))

                    seen_nodes: set[str] = set()
                    for func in functions:
                        name = func if isinstance(func, str) else func.get("name", "")
                        if name and name not in seen_nodes:
                            graph["nodes"].append({"id": name, "type": "function"})
                            seen_nodes.add(name)

                    for call in calls:
                        if isinstance(call, dict):
                            graph["edges"].append({
                                "from": call.get("caller", call.get("from", "")),
                                "to": call.get("callee", call.get("to", "")),
                            })
                        elif isinstance(call, (list, tuple)) and len(call) >= 2:
                            graph["edges"].append({
                                "from": str(call[0]),
                                "to": str(call[1]),
                            })
                elif isinstance(cg_data, list):
                    # Basit liste formati: [[caller, callee], ...]
                    for entry in cg_data:
                        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                            graph["edges"].append({
                                "from": str(entry[0]),
                                "to": str(entry[1]),
                            })
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Call graph okunamadi: %s", exc)

        graph["total_nodes"] = len(graph["nodes"])
        graph["total_edges"] = len(graph["edges"])
        return graph

    # ------------------------------------------------------------------
    # Report JSON
    # ------------------------------------------------------------------
    def _build_report_json(self) -> dict[str, Any]:
        """Pipeline sonuclarini detayli JSON rapora donustur."""
        from karadul import __version__
        from datetime import datetime, timezone

        report: dict[str, Any] = {
            "karadul_version": __version__,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "target": {
                "name": self._result.target_name,
                "hash": self._result.target_hash,
            },
            "pipeline": {
                "success": self._result.success,
                "total_duration": round(self._result.total_duration, 3),
                "stages": {},
            },
            "statistics": {},
        }

        # Stage bilgileri
        for name, sr in self._result.stages.items():
            report["pipeline"]["stages"][name] = {
                "success": sr.success,
                # Atlanan asama HATA degil (success=False tasir ama skipped=True).
                "skipped": sr.skipped,
                "skip_reason": sr.skip_reason,
                "duration": round(sr.duration_seconds, 3),
                "stats": sr.stats,
                "errors": sr.errors,
                "artifact_count": len(sr.artifacts),
            }
        report["pipeline"]["skipped_stages"] = self._result.get_skipped_stages()
        report["pipeline"]["failed_stages"] = self._result.get_failed_stages()

        # Ozet istatistikler
        if "static" in self._result.stages:
            st = self._result.stages["static"].stats
            report["statistics"]["functions"] = st.get(
                "functions_found",
                st.get("ghidra_function_count", st.get("functions", 0)),
            )
            report["statistics"]["strings"] = st.get(
                "strings_found",
                st.get("ghidra_string_count", st.get("string_count", 0)),
            )

        if "reconstruct" in self._result.stages:
            st = self._result.stages["reconstruct"].stats
            report["statistics"]["modules_extracted"] = st.get("modules_extracted", 0)
            report["statistics"]["variables_renamed"] = st.get("variables_renamed", 0)
            report["statistics"]["coverage_percent"] = st.get("coverage_percent", 0)

        return report

    # ------------------------------------------------------------------
    # README.md
    # ------------------------------------------------------------------
    def _build_readme(
        self,
        language: str,
        src_files: int,
        naming_map: dict[str, Any],
        output_dir: Optional[Path] = None,
    ) -> str:
        """Analiz özeti README.md üret.

        ``output_dir`` verilirse "Output Structure" bölümü ve "Source Files" sayısı diskteki
        çıktıdan türetilir (eskiden dile göre elle yazılmış sabit bir ağaç basılıyordu:
        ``src/main.c``, ``src/modules/``, ``src/types/``; proje ağacı yazılan çıktıda bunların
        hiçbiri yoktu). Verilmezse yapı bölümü yazılmaz, kaynak sayısı ``src_files``'tır.
        """
        from karadul import __version__
        from datetime import datetime, timezone

        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        total_mappings = naming_map.get("total_mappings", 0)
        src_root = output_dir / "src" if output_dir is not None else None
        if src_root is not None and src_root.is_dir():
            # Diskteki sayı: biçimlendiricinin sayacı diskteki dosya sayısından farklı olabilir
            # (genel dal eskiden aynı adlı dosyaları ezip her yazmayı sayıyordu).
            src_files = self._count_files(src_root)

        lang_display = {
            "c": "C/C++",
            "javascript": "JavaScript",
            "swift": "Swift",
            "go": "Go",
        }.get(language, language.upper() if language else "Unknown")

        status = "SUCCESS" if self._result.success else "PARTIAL"

        lines = [
            f"# Black Widow Analysis -- {self._result.target_name}",
            "",
            f"Generated by Black Widow (Karadul) v{__version__} at {now}",
            "",
            "## Summary",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Target | `{self._result.target_name}` |",
            f"| SHA-256 | `{self._result.target_hash or 'N/A'}` |",
            f"| Language | {lang_display} |",
            f"| Status | {status} |",
            f"| Duration | {self._result.total_duration:.1f}s |",
            f"| Source Files | {src_files} |",
            f"| Names Recovered | {total_mappings} |",
        ]
        if "total_candidates" in naming_map:
            lines.append(f"| Name Candidates (not applied) | {naming_map['total_candidates']} |")
        lines.append("")
        applied_check = naming_map.get("applied_check")
        if applied_check == APPLIED_CHECK_C_SOURCE:
            lines.extend([
                "`Names Recovered` counts only renames that appear in the code under `src/` "
                "(`naming_map.json` → `mappings`). Proposals that did not reach the code, "
                "entries whose new name equals the old one and names that are not valid C "
                "identifiers are listed separately with a reason "
                "(`naming_map.json` → `candidates`).",
                "",
            ])
        elif applied_check == APPLIED_CHECK_NOT_CHECKED:
            lines.extend([
                "`Names Recovered` was not checked against the code (no C source to check); "
                "entries whose new name equals the old one are listed separately "
                "(`naming_map.json` → `candidates`).",
                "",
            ])

        # Dizin yapısı: yazılan dosya ve dizinlerden (README.md bu listeden hemen sonra yazılır).
        if output_dir is not None:
            lines.extend(["## Output Structure", "", "```"])
            lines.extend(self._output_tree_lines(output_dir))
            lines.extend(["```", ""])

        # Pipeline ozeti
        lines.append("## Pipeline Stages")
        lines.append("")
        lines.append("| Stage | Status | Duration | Details |")
        lines.append("|-------|--------|----------|---------|")

        for name, sr in self._result.stages.items():
            if sr.skipped:
                # Atlanan asama HATA degil; eskiden success=False yuzunden FAIL.
                status_icon = "SKIPPED"
                reason = sr.skip_reason or "no reason recorded"
                details = reason.replace("|", "\\|")  # tablo hucresini bolmesin
            else:
                status_icon = "PASS" if sr.success else "FAIL"
                details_parts = []
                for k, v in list(sr.stats.items())[:3]:
                    details_parts.append(f"{k}={v}")
                details = ", ".join(details_parts) if details_parts else "-"
            lines.append(
                f"| {name} | {status_icon} | {sr.duration_seconds:.1f}s | {details} |"
            )

        lines.extend([
            "",
            "## How to Use",
            "",
        ])

        if language == "c":
            lines.extend([
                "The `src/` directory contains recovered C source code.",
                "You can browse it with any C-aware editor (VS Code, CLion).",
                "Note: This is decompiled code -- it may not compile directly.",
                "",
            ])
        elif language == "javascript":
            lines.extend([
                "The `src/` directory contains recovered JavaScript source.",
                "You can browse it with any JS editor.",
                "If a `package.json` exists, run `npm install && npm start`.",
                "",
            ])

        lines.extend([
            "---",
            f"*Black Widow (Karadul) v{__version__} -- Reverse Engineering Suite*",
        ])

        return "\n".join(lines)

    @staticmethod
    def _count_files(directory: Path) -> int:
        """``directory`` altındaki (alt dizinler dahil) dosya sayısı."""
        return sum(1 for p in directory.rglob("*") if p.is_file())

    @classmethod
    def _output_tree_lines(cls, output_dir: Path) -> list[str]:
        """Çıktı dizininin iki düzeyli ağacı; her satır diskteki bir girdidir.

        Üst düzey girdiler ve üst düzey dizinlerin çocukları sıralanır; dizinin yanına içindeki
        dosya sayısı yazılır. Bir dizinde :data:`README_TREE_MAX_ENTRIES`'ten çok girdi varsa kalanı
        tek satırda sayıyla özetlenir. README.md henüz yazılmadığı için diskte yoksa "This file"
        olarak eklenir: bu liste kurulduktan hemen sonra yazılan dosyanın kendisidir.
        """
        def label(path: Path) -> str:
            return f"{path.name}/" if path.is_dir() else path.name

        def note(path: Path, description: Optional[str]) -> str:
            parts = [description] if description else []
            if path.is_dir():
                n = cls._count_files(path)
                parts.append(f"{n} file" if n == 1 else f"{n} files")
            return ", ".join(parts)

        def order(paths) -> list[Path]:
            return sorted(paths, key=lambda p: (not p.is_dir(), p.name.lower(), p.name))

        def children(directory: Path) -> list[Path]:
            return order(directory.iterdir())

        rows: list[tuple[str, str]] = []

        def add(entries: list[Path], depth: int, top_level: bool) -> None:
            for entry in entries[:README_TREE_MAX_ENTRIES]:
                description = _README_ENTRY_DESCRIPTIONS.get(entry.name) if top_level else None
                rows.append(("  " * depth + label(entry), note(entry, description)))
                if top_level and entry.is_dir():
                    add(children(entry), depth + 1, top_level=False)
            hidden = len(entries) - README_TREE_MAX_ENTRIES
            if hidden > 0:
                rows.append(("  " * depth + f"... ({hidden} more)", ""))

        top = list(output_dir.iterdir()) if output_dir.is_dir() else []
        if not (output_dir / "README.md").exists():
            top.append(output_dir / "README.md")
        add(order(top), 1, top_level=True)

        width = max((len(text) for text, _ in rows), default=0) + 1
        lines = [f"{output_dir.name}/"]
        for text, comment in rows:
            lines.append(f"{text.ljust(width)}# {comment}" if comment else text)
        return lines

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------
    @staticmethod
    def _clean_c_source(content: str) -> str:
        """Decompiled C kodunu temizle ve formatla."""
        # Fazla bos satirlari azalt (3+ -> 2)
        content = re.sub(r"\n{4,}", "\n\n\n", content)

        # Ghidra'nin undefined degiskenlerini temizle (ama icerik kaybetme)
        # undefined4 -> uint32_t, undefined8 -> uint64_t vb.
        type_map = {
            "undefined8": "uint64_t",
            "undefined4": "uint32_t",
            "undefined2": "uint16_t",
            "undefined1": "uint8_t",
            "undefined": "uint8_t",
        }
        for old, new in type_map.items():
            content = content.replace(old, new)

        return content

    @staticmethod
    def _clean_js_source(content: str) -> str:
        """JS kaynak kodunu temizle."""
        # Fazla bos satirlari azalt
        content = re.sub(r"\n{4,}", "\n\n\n", content)
        return content

    @staticmethod
    def _categorize_c_module(filename: str, content: str) -> str:
        """C dosyasini kategorize et (networking, crypto, ui vb.)."""
        lower_name = filename.lower()
        lower_content = content.lower()

        categories = {
            "networking": ["socket", "connect", "send", "recv", "http", "url"],
            "crypto": ["encrypt", "decrypt", "aes", "sha", "md5", "ssl", "hmac"],
            "ui": ["view", "window", "button", "controller", "nsview", "uiview"],
            "io": ["fopen", "fread", "fwrite", "file", "stream", "read", "write"],
        }

        for cat, keywords in categories.items():
            for kw in keywords:
                if kw in lower_name or kw in lower_content[:2000]:
                    return cat

        return "misc"

    @staticmethod
    def _clean_filename(name: str) -> str:
        """Dosya adini temizle."""
        # Ozel karakterleri kaldir
        clean = re.sub(r"[^\w.\-]", "_", name)
        return clean or "unnamed.c"
