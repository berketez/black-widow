#!/usr/bin/env python3
"""Karadul Fortran kaynak kodu import araci.

Fortran kaynak dosyalarini (.f, .f90, .F, .F90) parse ederek
Karadul signature DB formatinda JSON dosyalari uretir.

Iki cikti dosyasi olusturur:
  1. Signature JSON (--output): load_external_signatures() ile uyumlu
  2. Param DB JSON (ayni dizinde fortran_params.json): FortranParamDB.register_batch() ile uyumlu

Kullanim:
    python scripts/import_fortran_source.py /tmp/ccx_source/CalculiX/ccx_2.21/src/ \\
        --output sigs/fortran_ccx.json \\
        --project-name CalculiX

    python scripts/import_fortran_source.py /tmp/code_aster/src/ \\
        --output sigs/fortran_aster.json \\
        --project-name Code_Aster \\
        --category fortran-fea

Cikti formati (signature JSON):
    {
      "meta": {
        "generator": "karadul-fortran-import",
        "date": "2026-04-07",
        "project": "CalculiX",
        "source_dir": "/tmp/ccx_source/...",
        "total_subroutines": 500,
        "total_params": 5000
      },
      "signatures": {
        "_results_": {
          "lib": "CalculiX",
          "purpose": "Fortran subroutine: RESULTS(co, nkon, nelem, ...)",
          "category": "fortran-fea",
          "params": ["co", "nkon", "nelem", ...]
        }
      }
    }

Cikti formati (fortran_params.json):
    {
      "_results_": ["co", "nkon", "nelem", ...],
      "_mafillsmas_": ["ad", "au", "adb", ...]
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import date
from pathlib import Path

# Proje kokunu Python path'ine ekle
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from karadul.reconstruction.fortran_param_db import (
    FortranSourceEntry,
    FortranSourceParser,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signature JSON olusturma
# ---------------------------------------------------------------------------


def _build_purpose_string(entry: FortranSourceEntry, max_params: int = 8) -> str:
    """Okunabilir purpose stringi olustur.

    Ornek: "Fortran subroutine: RESULTS(co, nkon, nelem, ne, ipkon, lakon)"
    Parametre sayisi max_params'i asarsa "..." ile kesilir.
    """
    kind = "subroutine"  # Varsayilan; Fortran'da FUNCTION da olabilir
    # FortranSourceEntry'de ayrim yok, ikisi de ayni sekilde saklanir.
    # Purpose string icin hepsine "subroutine" demek yeterli; signature
    # eslesmesi icin onemli olan c_symbol.
    params = entry.param_names
    if len(params) > max_params:
        params_str = ", ".join(params[:max_params]) + ", ..."
    else:
        params_str = ", ".join(params)

    return f"Fortran {kind}: {entry.fortran_name}({params_str})"


def build_signature_json(
    entries: list[FortranSourceEntry],
    project_name: str,
    source_dir: str,
    category: str,
) -> dict:
    """FortranSourceEntry listesinden Karadul signature JSON'u olustur.

    Args:
        entries: Parse edilmis Fortran entry'leri.
        project_name: Proje adi (CalculiX, Code_Aster, vb.).
        source_dir: Kaynak dizin yolu (meta bilgisi icin).
        category: Signature kategorisi (ornek: "fortran-fea").

    Returns:
        Karadul signature DB formatinda dict.
    """
    total_params = sum(len(e.param_names) for e in entries)

    signatures: dict[str, dict] = {}
    duplicates = 0

    for entry in entries:
        if entry.c_symbol in signatures:
            # Ayni isimde birden fazla subroutine/function olabilir
            # (farkli dosyalarda). Daha fazla parametreye sahip olani tut.
            existing_params = signatures[entry.c_symbol].get("params", [])
            if len(entry.param_names) <= len(existing_params):
                duplicates += 1
                continue
            duplicates += 1

        sig_entry: dict = {
            "lib": project_name,
            "purpose": _build_purpose_string(entry),
            "category": category,
        }
        if entry.param_names:
            sig_entry["params"] = entry.param_names

        signatures[entry.c_symbol] = sig_entry

    if duplicates:
        logger.info("Tekrarlanan sembol: %d (en cok parametreli tutuluyor)", duplicates)

    result = {
        "meta": {
            "generator": "karadul-fortran-import",
            "date": date.today().isoformat(),
            "project": project_name,
            "source_dir": source_dir,
            "total_subroutines": len(signatures),
            "total_params": total_params,
        },
        "signatures": signatures,
    }
    return result


def build_param_db_json(entries: list[FortranSourceEntry]) -> dict[str, list[str]]:
    """FortranSourceEntry listesinden param DB dict'i olustur.

    FortranParamDB.register_batch() ile dogrudan yuklenebilir format.
    Tekrarlanan semboller icin en cok parametreye sahip olan tutulur.

    Args:
        entries: Parse edilmis Fortran entry'leri.

    Returns:
        {c_symbol: [param_names]} dict'i.
    """
    db: dict[str, list[str]] = {}
    for entry in entries:
        if entry.c_symbol in db:
            if len(entry.param_names) <= len(db[entry.c_symbol]):
                continue
        if entry.param_names:
            db[entry.c_symbol] = entry.param_names
    return db


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fortran kaynak kodundan Karadul signature DB olustur",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ornekler:\n"
            "  %(prog)s /tmp/ccx_source/CalculiX/ccx_2.21/src/ "
            "--output sigs/fortran_ccx.json --project-name CalculiX\n"
            "  %(prog)s /tmp/code_aster/src/ "
            "--output sigs/fortran_aster.json --project-name Code_Aster"
        ),
    )
    parser.add_argument(
        "source_dir",
        type=Path,
        help="Fortran kaynak dosyalari iceren dizin",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=_PROJECT_ROOT / "sigs" / "fortran_import.json",
        help="Cikti signature JSON dosyasi (varsayilan: sigs/fortran_import.json)",
    )
    parser.add_argument(
        "--project-name", "-p",
        type=str,
        default="FortranProject",
        help="Proje adi (lib alani, varsayilan: FortranProject)",
    )
    parser.add_argument(
        "--category", "-c",
        type=str,
        default="fortran-fea",
        help="Signature kategorisi (varsayilan: fortran-fea)",
    )
    parser.add_argument(
        "--extensions",
        type=str,
        nargs="+",
        default=[".f", ".f90", ".F", ".F90", ".for"],
        help="Aranacak dosya uzantilari (varsayilan: .f .f90 .F .F90 .for)",
    )
    parser.add_argument(
        "--no-param-db",
        action="store_true",
        help="fortran_params.json dosyasini olusturma",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Ayrintili log",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    source_dir: Path = args.source_dir.resolve()
    output_path: Path = args.output.resolve()

    # Girdi dogrulama
    if not source_dir.is_dir():
        logger.error("Kaynak dizin bulunamadi: %s", source_dir)
        sys.exit(1)

    # Cikti dizinini olustur
    output_path.parent.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()

    # --- Adim 1: Parse ---
    logger.info("=== Fortran kaynak parse ediliyor ===")
    logger.info("Dizin: %s", source_dir)
    logger.info("Uzantilar: %s", " ".join(args.extensions))

    fparser = FortranSourceParser()
    entries = fparser.parse_directory(source_dir, tuple(args.extensions))

    if not entries:
        logger.warning("Hicbir subroutine/function bulunamadi!")
        sys.exit(0)

    # Dosya sayisini hesapla
    fortran_files: set[str] = set()
    for entry in entries:
        if entry.source_file:
            fortran_files.add(entry.source_file)

    total_params = sum(len(e.param_names) for e in entries)

    logger.info(
        "Parse sonucu: %d dosya, %d subroutine/function, %d parametre",
        len(fortran_files), len(entries), total_params,
    )

    # --- Adim 2: Signature JSON ---
    logger.info("=== Signature JSON olusturuluyor ===")

    sig_data = build_signature_json(
        entries=entries,
        project_name=args.project_name,
        source_dir=str(source_dir),
        category=args.category,
    )

    output_path.write_text(
        json.dumps(sig_data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info("Signature JSON: %s (%d entry)", output_path, len(sig_data["signatures"]))

    # --- Adim 3: Param DB JSON ---
    if not args.no_param_db:
        logger.info("=== Param DB JSON olusturuluyor ===")

        param_db = build_param_db_json(entries)
        param_db_path = output_path.parent / "fortran_params.json"

        param_db_path.write_text(
            json.dumps(param_db, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        logger.info("Param DB JSON: %s (%d fonksiyon)", param_db_path, len(param_db))

    # --- Ozet ---
    elapsed = time.monotonic() - start
    unique_sigs = len(sig_data["signatures"])

    logger.info("=" * 60)
    logger.info("OZET")
    logger.info("  Proje:              %s", args.project_name)
    logger.info("  Kaynak dizin:       %s", source_dir)
    logger.info("  Fortran dosya:      %d", len(fortran_files))
    logger.info("  Subroutine/func:    %d (toplam), %d (unique)", len(entries), unique_sigs)
    logger.info("  Parametre:          %d", total_params)
    logger.info("  Signature JSON:     %s", output_path)
    if not args.no_param_db:
        logger.info("  Param DB JSON:      %s", param_db_path)
    logger.info("  Sure:               %.1fs", elapsed)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
