"""Output Formatter -- workspace ciktisini temiz, okunabilir dizin yapisina donusturur.

Pipeline ciktisini (workspace) alir ve kullaniciya sunulacak temiz bir
output dizini uretir. Dil tipine gore farkli strateji uygular:
  - Binary (C/C++): src/ altina module bazli .c/.h dosyalari
  - JS: src/ altina module bazli .js dosyalari
  - Swift: src/ altina .swift dosyalari

Cikti yapisi:
  output/
    src/                   # Reconstructed source (duzenlenmis)
      main.c (veya .js)
      modules/             # Modul bazli ayrilmis dosyalar
      types/               # Kurtarilan tipler (struct, enum)
    report.json            # Detayli analiz raporu
    report.html            # Gorsel rapor (browser'da acilabilir)
    naming_map.json        # Tum isim eslestirmeleri
    dependency_graph.json  # Bagimlilik grafigi
    README.md              # Analiz ozeti
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)


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
        files_written = 0
        src_files = 0

        output_dir.mkdir(parents=True, exist_ok=True)
        src_dir = output_dir / "src"
        src_dir.mkdir(exist_ok=True)

        # Dil tespiti
        language = self._detect_language()

        # 1. Kaynak dosyalarini kopyala ve organize et
        if language == "c":
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

        # 2. Naming map uret
        naming_map = self._build_naming_map()
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
            readme_content = self._build_readme(language, src_files, naming_map)
            readme_path.write_text(readme_content, encoding="utf-8")
            files_written += 1
        except Exception as exc:
            errors.append(f"README.md yazma hatasi: {exc}")

        success = src_files > 0 or reports_generated > 0
        return FormatResult(
            success=success,
            output_dir=output_dir,
            files_written=files_written,
            src_files=src_files,
            reports_generated=reports_generated,
            errors=errors,
        )

    def _detect_language(self) -> str:
        """Pipeline sonucundan dil tespit et."""
        if "identify" in self._result.stages:
            lang = self._result.stages["identify"].stats.get("language", "")
            if lang:
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

        # CProjectBuilder ciktisi varsa (project/ dizini)
        project_dir = reconstructed / "project"
        if project_dir.exists():
            files_written += self._copy_project_tree(project_dir, src_dir, errors)
            return files_written, errors

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
    def _format_generic_sources(self, src_dir: Path) -> tuple[int, list[str]]:
        """Bilinmeyen dil icin generic formatting."""
        errors: list[str] = []
        files_written = 0

        reconstructed = self._workspace.get_stage_dir("reconstructed")

        # Tum kaynak dosyalarini topla
        source_exts = {".c", ".h", ".js", ".ts", ".py", ".swift", ".go", ".java"}
        for f in sorted(reconstructed.rglob("*")):
            if f.is_file() and f.suffix in source_exts:
                dest = src_dir / f.name
                shutil.copy2(f, dest)
                files_written += 1

        if files_written == 0:
            errors.append("Reconstructed kaynak dosya bulunamadi")

        return files_written, errors

    # ------------------------------------------------------------------
    # Naming map
    # ------------------------------------------------------------------
    def _build_naming_map(self) -> dict[str, Any]:
        """Tum isim eslestirmelerini birlestir."""
        naming_map: dict[str, Any] = {
            "version": "1.0",
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

        naming_map["total_mappings"] = len(naming_map["mappings"])
        return naming_map

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
                "duration": round(sr.duration_seconds, 3),
                "stats": sr.stats,
                "errors": sr.errors,
                "artifact_count": len(sr.artifacts),
            }

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
    ) -> str:
        """Analiz ozet README.md uret."""
        from karadul import __version__
        from datetime import datetime, timezone

        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        total_mappings = naming_map.get("total_mappings", 0)

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
            "",
            "## Output Structure",
            "",
            "```",
            "output/",
        ]

        # Dizin yapisi
        lines.append("  src/                  # Reconstructed source code")
        if language == "c":
            lines.append("    main.c              # Entry point")
            lines.append("    modules/            # Subsystem modules")
            lines.append("    types/              # Recovered structs/enums")
        elif language == "javascript":
            lines.append("    main.js             # Main application code")
            lines.append("    modules/            # Webpack modules")
        elif language == "swift":
            lines.append("    modules/            # Swift source files")

        lines.extend([
            "  report.json           # Machine-readable analysis report",
            "  report.html           # Visual report (open in browser)",
            "  naming_map.json       # All name recovery mappings",
            "  dependency_graph.json # Call graph / dependency info",
            "  README.md             # This file",
            "```",
            "",
        ])

        # Pipeline ozeti
        lines.append("## Pipeline Stages")
        lines.append("")
        lines.append("| Stage | Status | Duration | Details |")
        lines.append("|-------|--------|----------|---------|")

        for name, sr in self._result.stages.items():
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
