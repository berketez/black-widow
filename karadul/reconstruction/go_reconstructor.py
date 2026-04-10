"""Go proje yeniden olusturma.

GOPCLNTAB'dan gelen bilgilerle tam Go proje yapisi olusturur:
- go.mod dosyasi (BUILDINFO'dan)
- Paket yapisi (package name -> dizin)
- main.go ve diger .go dosyalari
- Her fonksiyonu ilgili pakete yerlestirme
- Tip tanimlarini ilgili dosyalara ekleme

Reconstruct edilen proje derlenmez (fonksiyon body'leri yok)
ama YAPI ve ISIMLER korunur — %90+ isim kurtarma hedefi.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class GoReconstructor:
    """Go proje yapisi yeniden olusturucu.

    GOPCLNTAB, BUILDINFO ve type descriptor verilerinden
    orijinal Go proje yapisini mumkun oldugunca sadik bir
    sekilde yeniden olusturur.

    Olusturulan yapilar:
    - go.mod (modul adi + dependency listesi)
    - Paket dizinleri (her Go paketi icin bir dizin)
    - .go dosyalari (fonksiyon imzalari + tip tanimlari)
    - main.go (main paketi icin giris noktasi)
    """

    def reconstruct(self, analysis_results: dict[str, Any], output_dir: Path) -> dict[str, Any]:
        """Go proje yapisini olustur.

        Args:
            analysis_results: Analyzer'dan gelen analiz sonuclari.
                Beklenen anahtarlar:
                - gopclntab: Fonksiyon listesi ve kaynak dosyalar
                - buildinfo: Go versiyonu, modul adi, dependency'ler
                - types: Struct/interface/method tanimlari
                - packages: Paket yapisi analizi

            output_dir: Cikti dizini.

        Returns:
            Reconstruction raporu (istatistikler + dosya listesi).
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        gopclntab = analysis_results.get("gopclntab", {})
        buildinfo = analysis_results.get("buildinfo", {})
        types_data = analysis_results.get("types", {})
        packages_data = analysis_results.get("packages", {})

        report: dict[str, Any] = {
            "output_dir": str(output_dir),
            "files_created": [],
            "packages_created": 0,
            "functions_placed": 0,
            "types_placed": 0,
        }

        # 1. go.mod olustur
        go_mod_path = self._create_go_mod(buildinfo, output_dir)
        if go_mod_path:
            report["files_created"].append(str(go_mod_path))

        # 2. Paket dizinlerini olustur ve fonksiyonlari yerlestir
        functions = gopclntab.get("functions", [])
        packages = self._organize_by_package(functions, buildinfo)

        module_path = buildinfo.get("module_path", "module")

        for pkg_name, pkg_functions in sorted(packages.items()):
            pkg_dir = self._create_package_dir(pkg_name, module_path, output_dir)
            if not pkg_dir:
                continue

            report["packages_created"] += 1

            # Bu paketteki type'lari bul
            pkg_types = self._get_types_for_package(pkg_name, types_data)

            # .go dosyasini olustur
            go_file = self._create_go_file(
                pkg_name=pkg_name,
                pkg_dir=pkg_dir,
                functions=pkg_functions,
                types=pkg_types,
            )
            if go_file:
                report["files_created"].append(str(go_file))
                report["functions_placed"] += len(pkg_functions)
                report["types_placed"] += len(pkg_types.get("structs", []))
                report["types_placed"] += len(pkg_types.get("interfaces", []))

        # 3. main.go ozel isleme
        if "main" in packages:
            main_file = output_dir / "main.go"
            if not main_file.exists():
                # main paketi baska dizindeyse kopyala
                for pkg_name, pkg_dir_check in [("main", output_dir)]:
                    pass  # Zaten 2. adimda olusturuldu

        report["total_files"] = len(report["files_created"])

        logger.info(
            "Go reconstruction: %d dosya, %d paket, %d fonksiyon, %d tip",
            report["total_files"],
            report["packages_created"],
            report["functions_placed"],
            report["types_placed"],
        )

        return report

    # ------------------------------------------------------------------
    # go.mod olusturma
    # ------------------------------------------------------------------

    def _create_go_mod(self, buildinfo: dict[str, Any], output_dir: Path) -> Path | None:
        """go.mod dosyasi olustur.

        Args:
            buildinfo: BUILDINFO parse sonucu.
            output_dir: Proje kok dizini.

        Returns:
            Olusturulan go.mod dosya yolu.
        """
        module_path = buildinfo.get("module_path", "")
        go_version = buildinfo.get("go_version", "")
        dependencies = buildinfo.get("dependencies", [])

        if not module_path:
            module_path = "reconstructed/module"

        # Go versiyon numarasini temizle (go1.21.5 -> 1.21.5, veya 1.21)
        go_ver_num = ""
        if go_version:
            m = re.match(r"go?(\d+\.\d+(?:\.\d+)?)", go_version)
            if m:
                go_ver_num = m.group(1)
        if not go_ver_num:
            go_ver_num = "1.21"  # Varsayilan

        lines = [
            f"module {module_path}",
            "",
            f"go {go_ver_num}",
        ]

        if dependencies:
            lines.append("")
            lines.append("require (")
            for dep in dependencies:
                dep_path = dep.get("path", "")
                dep_ver = dep.get("version", "v0.0.0")
                if dep_path:
                    lines.append(f"\t{dep_path} {dep_ver}")
            lines.append(")")

        lines.append("")  # trailing newline

        go_mod_path = output_dir / "go.mod"
        go_mod_path.write_text("\n".join(lines), encoding="utf-8")
        logger.debug("go.mod olusturuldu: %s", go_mod_path)
        return go_mod_path

    # ------------------------------------------------------------------
    # Paket organizasyonu
    # ------------------------------------------------------------------

    def _organize_by_package(
        self,
        functions: list[dict],
        buildinfo: dict[str, Any],
    ) -> dict[str, list[dict]]:
        """Fonksiyonlari paketlere gore grupla.

        Args:
            functions: GOPCLNTAB fonksiyon listesi.
            buildinfo: BUILDINFO verisi (modul yolu icin).

        Returns:
            Paket adi -> fonksiyon listesi eslesmesi.
        """
        packages: dict[str, list[dict]] = {}

        for func in functions:
            name = func.get("name", "")
            pkg = func.get("package", "")

            if not pkg and "." in name:
                # Fonksiyon isminden paket cikar
                # main.handleRequest -> main
                # github.com/user/pkg.Func -> github.com/user/pkg
                # github.com/user/pkg.(*Type).Method -> github.com/user/pkg
                pkg = name.rsplit(".", 1)[0]
                # Method receiver temizligi
                if ".(*" in pkg:
                    pkg = pkg.split(".(")[0]
                elif ".(" in pkg:
                    pkg = pkg.split(".(")[0]

            if not pkg:
                pkg = "main"

            if pkg not in packages:
                packages[pkg] = []
            packages[pkg].append(func)

        return packages

    def _create_package_dir(
        self,
        pkg_name: str,
        module_path: str,
        output_dir: Path,
    ) -> Path | None:
        """Paket dizini olustur.

        Stdlib paketleri icin dizin olusturulmaz (sadece user paketleri).

        Args:
            pkg_name: Go paket adi (orn: "main", "github.com/user/pkg/sub").
            module_path: go.mod'daki modul yolu.
            output_dir: Proje kok dizini.

        Returns:
            Olusturulan dizin yolu veya None (stdlib ise).
        """
        # Stdlib paketlerini atla — bunlari reconstruct etmeye gerek yok
        if self._is_stdlib(pkg_name):
            return None

        # Paket yolunu dizin yapisina cevir
        if pkg_name == "main":
            pkg_dir = output_dir
        elif module_path and pkg_name.startswith(module_path):
            # Modul icindeki alt paket
            relative = pkg_name[len(module_path):].lstrip("/")
            if relative:
                pkg_dir = output_dir / relative.replace("/", "/")
            else:
                pkg_dir = output_dir
        else:
            # Disaridan gelen paket (vendor veya dependency)
            # vendor/ altina koy
            pkg_dir = output_dir / "vendor" / pkg_name.replace("/", "/")

        pkg_dir.mkdir(parents=True, exist_ok=True)
        return pkg_dir

    @staticmethod
    def _is_stdlib(pkg_name: str) -> bool:
        """Go standart kutuphane paketi mi?"""
        stdlib_prefixes = (
            "runtime", "internal", "sync", "syscall", "os", "fmt",
            "io", "net", "encoding", "crypto", "reflect", "math",
            "strings", "bytes", "bufio", "context", "errors", "log",
            "path", "sort", "strconv", "time", "unicode", "regexp",
            "hash", "compress", "archive", "database", "html", "image",
            "mime", "text", "debug", "go/", "testing", "unsafe",
            "plugin", "embed", "iter", "maps", "slices", "cmp",
        )
        first_part = pkg_name.split("/")[0]
        return first_part in stdlib_prefixes or pkg_name in stdlib_prefixes

    # ------------------------------------------------------------------
    # .go dosya olusturma
    # ------------------------------------------------------------------

    def _create_go_file(
        self,
        pkg_name: str,
        pkg_dir: Path,
        functions: list[dict],
        types: dict[str, Any],
    ) -> Path | None:
        """Paket icin .go dosyasi olustur.

        Args:
            pkg_name: Go paket adi.
            pkg_dir: Paket dizini.
            functions: Bu paketteki fonksiyonlar.
            types: Bu paketteki tip tanimlari.

        Returns:
            Olusturulan .go dosya yolu.
        """
        # Paket kisa adini cikar (son / 'dan sonraki kisim)
        short_name = pkg_name.rsplit("/", 1)[-1] if "/" in pkg_name else pkg_name
        # Gecerisiz Go identifier'lari temizle
        short_name = re.sub(r"[^a-zA-Z0-9_]", "_", short_name)
        if not short_name or short_name[0].isdigit():
            short_name = "pkg_" + short_name

        lines: list[str] = []

        # Package declaration
        lines.append(f"package {short_name}")
        lines.append("")

        # Header comment
        lines.append("// Code reconstructed by Karadul Go Binary Analyzer")
        lines.append(f"// Original package: {pkg_name}")
        lines.append(f"// Functions: {len(functions)}")
        lines.append("")

        # Tip tanimlari
        structs = types.get("structs", [])
        interfaces = types.get("interfaces", [])
        methods = types.get("methods", [])

        if structs:
            lines.append("// ---- Type Definitions ----")
            lines.append("")
            for s in structs:
                type_name = s.get("name", "UnknownType")
                lines.append(f"// {s.get('full_name', type_name)}")
                lines.append(f"type {type_name} struct {{")
                lines.append("\t// Fields not recoverable from binary")
                lines.append("}")
                lines.append("")

        if interfaces:
            lines.append("// ---- Interfaces ----")
            lines.append("")
            for iface in interfaces:
                type_name = iface.get("name", "UnknownInterface")
                lines.append(f"// {iface.get('full_name', type_name)}")
                lines.append(f"type {type_name} interface {{")

                # Bu interface'e ait method'lari bul
                iface_methods = [
                    m for m in methods
                    if m.get("receiver_type") == type_name
                ]
                if iface_methods:
                    for m in iface_methods:
                        lines.append(f"\t{m.get('method_name', 'Unknown')}()")
                else:
                    lines.append("\t// Methods not fully recoverable")
                lines.append("}")
                lines.append("")

        # Fonksiyon imzalari
        if functions:
            lines.append("// ---- Functions ----")
            lines.append("")
            for func in functions:
                func_name = func.get("name", "")
                source_file = func.get("source_file", "")
                func_lines = func.get("lines", [])

                # Fonksiyon kisa adini cikar
                short_func = self._extract_func_short_name(func_name)
                if not short_func:
                    continue

                # Yorum
                comment_parts = []
                if source_file:
                    comment_parts.append(f"Source: {source_file}")
                if func_lines:
                    comment_parts.append(f"Lines: {func_lines[0]}-{func_lines[-1]}")

                if comment_parts:
                    lines.append(f"// {short_func} — {', '.join(comment_parts)}")

                # Method mi, fonksiyon mu?
                receiver = func.get("receiver_type", "")
                if receiver or ".(*" in func_name:
                    # Method: receiver tipini cikar
                    if not receiver and ".(*" in func_name:
                        m = re.search(r"\.\(\*(\w+)\)\.", func_name)
                        if m:
                            receiver = m.group(1)

                    if receiver:
                        lines.append(
                            f"func (r *{receiver}) {short_func}() {{"
                        )
                    else:
                        lines.append(f"func {short_func}() {{")
                else:
                    lines.append(f"func {short_func}() {{")

                lines.append("\t// Body not recoverable from binary")
                lines.append("}")
                lines.append("")

        # Dosya adi
        if short_name == "main":
            file_name = "main.go"
        else:
            file_name = f"{short_name}.go"

        go_file = pkg_dir / file_name
        go_file.write_text("\n".join(lines), encoding="utf-8")
        return go_file

    @staticmethod
    def _extract_func_short_name(full_name: str) -> str | None:
        """Tam fonksiyon isminden kisa adi cikar.

        Ornekler:
        - main.handleRequest -> handleRequest
        - github.com/user/pkg.(*Server).Start -> Start
        - runtime.gopanic -> gopanic
        """
        if not full_name:
            return None

        # Method: package.(*Type).Method -> Method
        m = re.search(r"\.\(\*\w+\)\.(\w+)$", full_name)
        if m:
            return m.group(1)

        # Basit fonksiyon: package.Function -> Function
        if "." in full_name:
            short = full_name.rsplit(".", 1)[-1]
            # func1, func2 gibi closure isimleri
            if re.match(r"^func\d+$", short):
                return None  # Anonymous closure'lari atla
            return short

        return full_name

    # ------------------------------------------------------------------
    # Type helper
    # ------------------------------------------------------------------

    def _get_types_for_package(
        self,
        pkg_name: str,
        types_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Belirli bir pakete ait tip tanimlarini filtrele.

        Args:
            pkg_name: Paket adi.
            types_data: Tum type descriptor verisi.

        Returns:
            Bu pakete ait structs, interfaces, methods.
        """
        result: dict[str, Any] = {
            "structs": [],
            "interfaces": [],
            "methods": [],
        }

        if not types_data:
            return result

        for s in types_data.get("structs", []):
            if s.get("package", "") == pkg_name or (
                s.get("full_name", "").startswith(pkg_name + ".")
            ):
                result["structs"].append(s)

        for iface in types_data.get("interfaces", []):
            if iface.get("package", "") == pkg_name or (
                iface.get("full_name", "").startswith(pkg_name + ".")
            ):
                result["interfaces"].append(iface)

        for method in types_data.get("methods", []):
            full_name = method.get("full_name", "")
            if full_name.startswith(pkg_name + "."):
                result["methods"].append(method)

        return result
