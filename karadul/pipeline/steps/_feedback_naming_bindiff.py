"""Feedback loop — BinDiff alt-fazi.

stages.py L2396-2564'un birebir kopyasi. BinDiff iki kaynaktan eslestirir:
(a) reference_binary config (geriye uyum), (b) ref_db cache auto-scan.
Per-match confidence map iter'lar arasi persistent tutulur.

PK-1 (yöntem kapısı; KARARLAR A-2, A-13, A-30): eşleşmeler yöntemine göre ikiye ayrılır.
Ölçülmüş kesinliğinin Wilson alt sınırı ``AD_ESIGI``'ni geçen yöntem (``yontem_kapisi.ad_verebilir``)
ad yazar; geçmeyen ya da ölçülmemiş yöntemin eşleşmesi ad yazmaz, kanıt satırı olur
(``stats["bindiff_evidence"]``, sayaç ``stats["bindiff_method_gate"]``, köken kaydında
``reference_evidence``; yazıcı ``write_reference_evidence``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from karadul.reconstruction.kimlik import yontem_kapisi as _kapi
from karadul.reconstruction.tarif import baglama as _baglama

logger = logging.getLogger(__name__)

# Köken kaydı (``naming_provenance.json``) bölümü: kapıdan düşen başvuru eşleşmeleri.
REFERENCE_EVIDENCE_SECTION = "reference_evidence"
# c_namer koşmadıysa (köken kaydı yoksa) yazılan ayrı dosya (``reconstructed/`` altında).
REFERENCE_EVIDENCE_FALLBACK_FILE = "reference_evidence.json"
KAYNAK_BINDIFF = "bindiff"
KAYNAK_REFDIFF = "reference_differ"


def gate_counter(stats: dict[str, Any], key: str, method: str | None, outcome: str) -> None:
    """``stats[key]`` sayacı: ``yöntem → {"ad": n, "kanit": m}``."""
    row = stats.setdefault(key, {}).setdefault(str(method), {"ad": 0, "kanit": 0})
    row[outcome] = row.get(outcome, 0) + 1


def split_by_method_gate(
    conf_map: dict[str, tuple[str, float, str]],
    matches: Any,
    *,
    stats: dict[str, Any],
    basvuru: str | None = None,
) -> tuple[dict[str, tuple[str, float, str]], list[dict[str, Any]]]:
    """``transfer_names_with_confidence`` çıktısını yöntem kapısından geçir.

    Dönen: (ad yazabilenler — aynı biçimde, kanıt satırları). Sayaçlar ``bindiff_method_gate``'e.
    ``matches``: eşleşmelerin hedef adresini kanıt satırına yazmak için (``DiffMatch.target_address``).
    """
    addr_of: dict[str, str] = {}
    for m in matches or ():
        t = getattr(m, "target_name", None)
        if t and t not in addr_of:
            addr_of[t] = getattr(m, "target_address", None)
    names: dict[str, tuple[str, float, str]] = {}
    evidence: list[dict[str, Any]] = []
    for t_name, (ref_name, conf, method) in conf_map.items():
        if _kapi.ad_verebilir(method):
            names[t_name] = (ref_name, conf, method)
            gate_counter(stats, "bindiff_method_gate", method, "ad")
            continue
        gate_counter(stats, "bindiff_method_gate", method, "kanit")
        evidence.append(_kapi.kanit_satiri(
            kaynak=KAYNAK_BINDIFF, anahtar=t_name, ad=ref_name, yontem=method,
            adres=addr_of.get(t_name), eslesme_guveni=conf, basvuru=basvuru,
        ))
    return names, evidence


def write_reference_evidence(
    *, pc: Any, kaynak: str, rows: list[dict[str, Any]], stats: dict[str, Any],
) -> None:
    """Kanıt satırlarını köken kaydına yaz (``naming_provenance.json`` → ``reference_evidence``).

    Hedef: Faz 2'nin ilk yinelemesinde c_namer'ın köken kaydı (``reconstructed/src``; birleştirici
    ``name_merger`` bölümünü aynı dosyaya, öbür bölümleri koruyarak yazar). Kayıt yoksa (c_namer
    koşmadı) ``reconstructed/reference_evidence.json``. Bölüm bir satır listesidir (P-ÜV6a'nın
    ``ust_veri_kanit`` biçimi); bu ``kaynak``'ın eski satırları değiştirilir, öbür kaynağınkiler kalır.
    Satır yoksa dosyaya dokunulmaz. Yazılamazsa yalnız istatistiğe not düşülür.
    """
    if not rows:
        return
    from karadul.core.naming_labels import NAMING_PROVENANCE_FILE

    try:
        reconstructed = Path(pc.workspace.get_stage_dir("reconstructed"))
        target = reconstructed / "src" / NAMING_PROVENANCE_FILE
        if not target.is_file():
            target = reconstructed / REFERENCE_EVIDENCE_FALLBACK_FILE
        data: Any = {}
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("köken kaydı sözlük değil")
        old = data.get(REFERENCE_EVIDENCE_SECTION)
        kept = [r for r in old if isinstance(r, dict) and r.get("kaynak") != kaynak] \
            if isinstance(old, list) else []
        data[REFERENCE_EVIDENCE_SECTION] = sorted(
            kept + list(rows),
            key=lambda r: (str(r.get("kaynak")), str(r.get("anahtar")), str(r.get("ozgun_ad"))))
        target.parent.mkdir(parents=True, exist_ok=True)
        # c_namer'ın yazım biçimiyle aynı (indent=1, ensure_ascii, sort_keys)
        target.write_text(json.dumps(data, indent=1, ensure_ascii=True, sort_keys=True),
                          encoding="utf-8")
        stats["reference_evidence_provenance"] = f"yazildi:{target.name}"
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        stats["reference_evidence_provenance"] = f"yazilamadi:{type(exc).__name__}"

# P13a / AD-11 + B-C6: BinDiff / ReferenceDiffer'ın ezemediği ön ad türleri: elle (analist),
# ``main`` girişi (yükleyicinin bulduğu), KS-1 kesin çapası. Öncelik ``tarif.baglama``'da
# (elle > main > KS-1 > Faz 1 > gnulib > ELF önyükü); eşleşme adları bu sırada yok, ölçülmemiş.
DIFF_PROTECTED_KINDS = frozenset(_baglama.PROTECTED_KINDS | {_baglama.KIND_KS1})


def pre_name_meta_of(ctx: Any) -> dict[str, Any] | None:
    """Faz 2 tohumundaki ön ad künyesi (``pre_name_meta``); yoksa None."""
    artifacts = getattr(ctx, "artifacts", None)
    try:
        meta = artifacts.get("pre_name_meta") if artifacts is not None else None
    except Exception:
        return None
    return meta if isinstance(meta, dict) else None


def update_unprotected(
    extracted_names: dict[str, str],
    new_names: dict[str, str],
    meta: dict[str, Any] | None,
) -> list[str]:
    """``new_names``'i ön ad sözlüğüne yaz; korunan türdeki (elle, main, KS-1) künyeli adı EZME.

    Künye ancak sözlükteki adı anlatıyorsa geçerlidir (``baglama.meta_for``). Dönen: yazılmayan
    (korunan) anahtarlar, sıralı.
    """
    kept: list[str] = []
    for key, name in new_names.items():
        entry = _baglama.meta_for(meta, key, extracted_names.get(key, ""))
        if entry is not None and entry.get("kind") in DIFF_PROTECTED_KINDS:
            if extracted_names.get(key) != name:
                kept.append(key)
            continue
        extracted_names[key] = name
    return sorted(kept)


def run_bindiff(
    *,
    ctx: Any,
    func_data: Any,
    string_data: Any,
    functions_json: Path,
    strings_json: Path,
    call_graph_json: Path,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    extracted_names: dict[str, str],
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """BinDiff (config + ref_db) eslestirme; yalnizca iter==0 cagrilir."""
    pc = ctx.pipeline_context
    try:
        from karadul.analyzers.bindiff import BinaryDiffer
        differ = BinaryDiffer()

        target_func_data = func_data if isinstance(func_data, dict) else (
            json.loads(functions_json.read_text(encoding="utf-8", errors="replace"))
            if functions_json.exists() else None
        )
        target_str_data = string_data if string_data is not None else (
            json.loads(strings_json.read_text(encoding="utf-8", errors="replace"))
            if strings_json.exists() else None
        )

        _config_source(
            pc=pc, differ=differ,
            target_func_data=target_func_data,
            target_str_data=target_str_data,
            bindiff_confidence_map=bindiff_confidence_map,
            bindiff_names=bindiff_names,
            stats=stats,
        )

        if target_func_data:
            _refdb_source(
                pc=pc, differ=differ,
                target_func_data=target_func_data,
                target_str_data=target_str_data,
                call_graph_json=call_graph_json,
                bindiff_confidence_map=bindiff_confidence_map,
                bindiff_names=bindiff_names,
                stats=stats,
            )

        # PK-1: kapıdan düşen eşleşmeler kanıt satırı olarak köken kaydına
        write_reference_evidence(
            pc=pc, kaynak=KAYNAK_BINDIFF,
            rows=stats.get("bindiff_evidence") or [], stats=stats,
        )

        if bindiff_names:
            stats["bindiff_matches"] = len(bindiff_names)
            # Yalnız yöntem kapısından geçen adlar (``split_by_method_gate``)
            protected = update_unprotected(
                extracted_names, bindiff_names, pre_name_meta_of(ctx))
            if protected:
                stats["bindiff_protected_pre_names"] = len(protected)
            logger.info(
                "BinDiff toplam: %d fonksiyon eslesti", len(bindiff_names),
            )
    except ImportError:
        logger.debug("BinDiff modulu bulunamadi, atlaniyor")
    except Exception as exc:
        logger.warning("BinDiff hatasi (atlaniyor): %s", exc)
        errors.append(f"BinDiff hatasi: {exc}")


def _config_source(
    *,
    pc: Any, differ: Any,
    target_func_data: Any,
    target_str_data: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    stats: dict[str, Any],
) -> None:
    """Kaynak (a): reference_binary config."""
    ref_binary = getattr(
        pc.config.binary_reconstruction, "reference_binary", "",
    )
    if not (ref_binary and Path(ref_binary).exists()):
        return
    try:
        ref_functions_json = Path(ref_binary).parent / "ghidra_functions.json"
        ref_strings_json = Path(ref_binary).parent / "ghidra_strings.json"
        if not (ref_functions_json.exists() and target_func_data):
            logger.debug(
                "BinDiff(config): referans Ghidra ciktilari bulunamadi (%s)",
                ref_functions_json if ref_binary else "N/A",
            )
            return

        ref_data = json.loads(
            ref_functions_json.read_text(encoding="utf-8", errors="replace"),
        )
        ref_str_data = None
        if ref_strings_json.exists():
            ref_str_data = json.loads(
                ref_strings_json.read_text(encoding="utf-8", errors="replace"),
            )
        diff_result = differ.compare(
            reference=ref_data, target=target_func_data,
            ref_strings=ref_str_data, target_strings=target_str_data,
        )
        conf_map = differ.transfer_names_with_confidence(diff_result)
        if conf_map:
            # PK-1: yalnız kapıdan geçen yöntemin eşleşmesi ad yazar; kalan kanıt satırı
            named, evidence = split_by_method_gate(
                conf_map, getattr(diff_result, "matches", None),
                stats=stats, basvuru=Path(ref_binary).name,
            )
            bindiff_confidence_map.update(named)
            bindiff_names.update({t: v[0] for t, v in named.items()})
            stats.setdefault("bindiff_evidence", []).extend(evidence)
            stats["bindiff_config_matches"] = len(conf_map)
            stats["bindiff_config_match_rate"] = diff_result.match_rate
            logger.info(
                "BinDiff(config): %d fonksiyon eslesti (match_rate=%.2f)",
                len(conf_map), diff_result.match_rate,
            )
    except Exception as exc:
        logger.warning("BinDiff(config) hatasi (atlaniyor): %s", exc)


def _refdb_source(
    *,
    pc: Any, differ: Any,
    target_func_data: Any,
    target_str_data: Any,
    call_graph_json: Path,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    bindiff_names: dict[str, str],
    stats: dict[str, Any],
) -> None:
    """Kaynak (b): ref_db auto-scan (reference_binary gerektirmez)."""
    try:
        ref_db_path = getattr(
            pc.config.binary_reconstruction, "reference_db_path", "",
        )
        ref_db_dir = Path(ref_db_path) if ref_db_path else (
            Path.home() / ".cache" / "karadul" / "ref_db"
        )
        if not ref_db_dir.exists():
            return

        from karadul.reconstruction.reference_differ import ReferenceDB
        ref_db = ReferenceDB(ref_db_dir)
        ref_db_entries = ref_db.all_entries()

        target_cg_data = None
        if call_graph_json.exists():
            try:
                target_cg_data = json.loads(
                    call_graph_json.read_text(encoding="utf-8", errors="replace"),
                )
            except Exception:
                logger.debug(
                    "Call graph JSON parse basarisiz (refdb)", exc_info=True,
                )

        refdb_total = 0
        for rdb_entry in ref_db_entries:
            if not rdb_entry.functions_json.exists():
                continue
            try:
                rdb_funcs = json.loads(
                    rdb_entry.functions_json.read_text(
                        encoding="utf-8", errors="replace",
                    ),
                )
                rdb_strings = None
                if rdb_entry.strings_json and rdb_entry.strings_json.exists():
                    rdb_strings = json.loads(
                        rdb_entry.strings_json.read_text(
                            encoding="utf-8", errors="replace",
                        ),
                    )
                rdb_call_graph = None
                if (
                    rdb_entry.call_graph_json
                    and rdb_entry.call_graph_json.exists()
                ):
                    rdb_call_graph = json.loads(
                        rdb_entry.call_graph_json.read_text(
                            encoding="utf-8", errors="replace",
                        ),
                    )

                rdb_diff = differ.compare(
                    reference=rdb_funcs,
                    target=target_func_data,
                    ref_strings=rdb_strings,
                    target_strings=target_str_data,
                    ref_call_graph=rdb_call_graph,
                    target_call_graph=target_cg_data,
                )
                rdb_conf = differ.transfer_names_with_confidence(rdb_diff)
                if rdb_conf:
                    # PK-1: yöntem kapısı (kalan eşleşme kanıt satırı)
                    named, evidence = split_by_method_gate(
                        rdb_conf, getattr(rdb_diff, "matches", None), stats=stats,
                        basvuru=f"{rdb_entry.library}/{rdb_entry.version}",
                    )
                    stats.setdefault("bindiff_evidence", []).extend(evidence)
                    for t_name, (ref_name, conf, method) in named.items():
                        existing = bindiff_confidence_map.get(t_name)
                        if existing is None or conf > existing[1]:
                            bindiff_confidence_map[t_name] = (
                                ref_name, conf, method,
                            )
                            bindiff_names[t_name] = ref_name
                    refdb_total += len(rdb_conf)
                    logger.debug(
                        "BinDiff(ref_db): %s/%s -- %d eslesti",
                        rdb_entry.library, rdb_entry.version, len(rdb_conf),
                    )
            except Exception as rdb_exc:
                logger.debug(
                    "BinDiff(ref_db): %s/%s hatasi: %s",
                    rdb_entry.library, rdb_entry.version, rdb_exc,
                )
                continue

        if refdb_total > 0:
            stats["bindiff_refdb_matches"] = refdb_total
            logger.info(
                "BinDiff(ref_db): toplam %d fonksiyon eslesti (%d kutuphane)",
                refdb_total, len(ref_db_entries),
            )
    except ImportError:
        logger.debug("BinDiff(ref_db): ReferenceDB import edilemedi")
    except Exception as exc:
        logger.warning("BinDiff(ref_db) hatasi (atlaniyor): %s", exc)
