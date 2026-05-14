"""CAPA yorum enjeksiyonu — pipeline-local helper.

Bu modul, ``karadul/stages.py`` icindeki ``_inject_capa_comments`` fonksiyonunun
birebir kopyasini barindirir. Amac, ``karadul.pipeline.steps.capa_annotation``
adimini ``karadul.stages`` monolitinden ayirmak ve `pipeline -> stages` yonunde
olusan dairesel bagimliligi (lazy import ile maskelenmis mimari sizinti)
ortadan kaldirmaktir.

Davranis ``stages.py`` icindeki orijinaliyle BIREBIR aynidir; testler hem
``karadul.stages._inject_capa_comments`` hem de bu modulu kullanabilir.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def _inject_capa_comments(
    decompiled_dir: Path,
    capa_capabilities: dict[str, list[dict]],
    func_data: dict | None,
) -> int:
    """CAPA capability bilgisini decompile edilmis C dosyalarina yorum olarak ekle.

    Her fonksiyonun basina /** @capability ... */ blogu ekler.

    Args:
        decompiled_dir: Decompile edilmis (veya comment pass'ten gecmis) C dosyalari.
        capa_capabilities: {addr_hex: [{name, namespace, ...}, ...]}
        func_data: Ghidra functions.json (fonksiyon adresi -> isim mapping icin).

    Returns:
        Yorum eklenen fonksiyon sayisi.
    """
    if not decompiled_dir or not decompiled_dir.exists():
        return 0
    if not capa_capabilities:
        return 0

    # Ghidra functions.json'dan adres -> fonksiyon ismi mapping olustur
    addr_to_name: dict[str, str] = {}
    name_to_caps: dict[str, list[str]] = {}

    if func_data:
        functions_list = func_data.get("functions", [])
        if isinstance(functions_list, list):
            for f in functions_list:
                if isinstance(f, dict):
                    addr = f.get("address", "")
                    name = f.get("name", "")
                    if addr and name:
                        # Adresleri normalize et: "0x100004a00" formatina cevir
                        if isinstance(addr, str):
                            addr_to_name[addr.lower()] = name
                        elif isinstance(addr, int):
                            addr_to_name[f"0x{addr:x}"] = name

    # CAPA sonuclarindan addr -> name -> capability listesi olustur
    for addr_hex, caps in capa_capabilities.items():
        addr_lower = addr_hex.lower()
        func_name = addr_to_name.get(addr_lower)
        if not func_name:
            # Deneme: "0x" prefix'siz
            try:
                addr_int = int(addr_hex, 16)
                func_name = addr_to_name.get(f"0x{addr_int:x}")
            except (ValueError, TypeError):
                continue
        if func_name:
            cap_names = []
            for c in caps:
                if isinstance(c, dict):
                    cap_names.append(c.get("name", "unknown"))
                elif isinstance(c, str):
                    cap_names.append(c)
            if cap_names:
                name_to_caps[func_name] = cap_names

    if not name_to_caps:
        return 0

    # C dosyalarini tara ve fonksiyon tanimlarinin basina @capability yorumu ekle
    total_injected = 0
    c_files = sorted(decompiled_dir.rglob("*.c"))

    # Fonksiyon tanimi regex: "void FUN_xxx(...)" veya "int func_name(...)"
    # Ghidra decompile output'unda fonksiyonlar genellikle
    # "<return_type> <name>(<params>)" formatinda tanimlanir.
    _func_def_pattern = re.compile(
        r"^(\w[\w\s\*]*?)\s+(\w+)\s*\(",
        re.MULTILINE,
    )

    for c_file in c_files:
        try:
            content = c_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            logger.debug("C dosyasi okunamadi, atlaniyor", exc_info=True)
            continue

        modified = False
        new_lines: list[str] = []
        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]
            # Fonksiyon tanimi mi?
            m = _func_def_pattern.match(line)
            if m:
                func_name = m.group(2)
                if func_name in name_to_caps:
                    func_caps: list[str] = name_to_caps[func_name]
                    # Onceki satir zaten /** ... */ ise, mevcut blogun sonuna ekle
                    # Yoksa yeni blok olustur
                    cap_lines = [f" * @capability {cap}" for cap in func_caps]
                    comment_block = "/**\n" + "\n".join(cap_lines) + "\n */"
                    new_lines.append(comment_block)
                    modified = True
                    total_injected += 1

            new_lines.append(line)
            i += 1

        if modified:
            try:
                c_file.write_text("\n".join(new_lines), encoding="utf-8")
            except Exception:
                logger.debug("C dosyasi yazilamadi, atlaniyor", exc_info=True)

    return total_injected
