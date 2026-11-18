"""Feedback loop — NameMerger alt-fazi.

stages.py L2656-2929. Candidate toplama icin
`_feedback_naming_candidates.collect_candidates`'e delege eder; merge +
Aho-Corasick replacement bu dosyada.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES
from karadul.pipeline.steps._feedback_naming_candidates import (
    K4_CHANNEL_FLAGS,
    UNMEASURED_SOURCES,
    collect_candidates,
    load_ghidra_index,
)
from karadul.pipeline.steps._feedback_naming_bindiff import pre_name_meta_of
from karadul.reconstruction import name_validity as _name_validity
from karadul.reconstruction.tarif import baglama as _baglama

try:
    from karadul.reconstruction.name_merger import NameMerger
except ImportError:
    NameMerger = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


def config_flag(br_cfg: Any, name: str) -> bool:
    """Adlandırma bayrağı açık mı. Yalnız gerçek ``True`` açık sayılır: eksik öznitelik ya da
    sahte yapılandırma nesnesinin döndürdüğü doğru benzeri değer bayrağı açmaz."""
    return getattr(br_cfg, name, False) is True


def global_naming_threshold(br_cfg: Any) -> float | None:
    """Genel adlara uygulanacak ürün eşiği; uygulanmıyorsa ``None`` (plan v2.2 N1 adım 3, §4.4).

    ``apply_global_naming_threshold`` açıksa ``min_naming_confidence`` (öntanımlı 0,7). Aynı
    değer c_namer'ın seçimine ve NameMerger çıktısına verilir: ürün tek eşik taşır.
    """
    if not config_flag(br_cfg, "apply_global_naming_threshold"):
        return None
    value = getattr(br_cfg, "min_naming_confidence", None)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def drop_below_threshold(
    final_naming_map: dict[str, str], merged_names: Any, threshold: float | None,
) -> tuple[dict[str, str], int]:
    """NameMerger haritasından, birleşik güveni eşiğin altında kalan genel anahtarları çıkar.

    Genel anahtar: içinde ``::`` olmayan (c_namer'daki tanım). Eşik ``None`` ise harita
    olduğu gibi döner. Güveni okunamayan giriş düşürülmez (kanıtsız karar verilmez).
    Dönen: (süzülmüş harita, düşen anahtar sayısı).
    """
    if threshold is None:
        return final_naming_map, 0
    kept: dict[str, str] = {}
    for key, name in final_naming_map.items():
        confidence = getattr(merged_names.get(key), "final_confidence", None)
        if (
            "::" not in key
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and confidence < threshold
        ):
            continue
        kept[key] = name
    return kept, len(final_naming_map) - len(kept)


MERGER_PROVENANCE_SECTION = "name_merger"
MERGER_PROVENANCE_VERSION = 1


def c_namer_decided(naming_result: Any) -> dict[str, str] | None:
    """c_namer koştuysa ad verdiği anahtarlar (anahtar → ad); koşmadıysa ``None``.

    "Koştu": sonuç başarılı ve ``naming_map`` bir sözlük. Bu anahtarların adı kodda zaten
    yazılı (birleştirici c_namer'ın çıktısı üstünde çalışır); karar c_namer'ındır.
    """
    if naming_result is None or getattr(naming_result, "success", False) is not True:
        return None
    naming_map = getattr(naming_result, "naming_map", None)
    if not isinstance(naming_map, dict):
        return None
    return {k: v for k, v in naming_map.items() if isinstance(k, str) and isinstance(v, str)}


def rejected_pre_name_keys(
    extracted_names: dict[str, str] | None,
    decided: dict[str, str] | None,
    bindiff_confidence_map: dict[str, Any] | None,
    refdiff_naming: dict[str, str] | None,
) -> frozenset[str]:
    """c_namer'ın ön ad olarak gördüğü ama ad vermediği anahtarlar (koşmadıysa boş).

    Ön ad sözlüğünde olup c_namer'ın haritasında olmayan anahtar: ad geçerliliği reddetti ya da
    aynı ad daha öncelikli ön adda kullanıldı. BinDiff / ReferenceDiffer'ın bu yinelemede
    eklediği anahtarlar c_namer'dan SONRA geldiği için sayılmaz.
    """
    if decided is None or not extracted_names:
        return frozenset()
    later = set(bindiff_confidence_map or ()) | set(refdiff_naming or ())
    return frozenset(k for k in extracted_names if k not in decided and k not in later)


def _function_index(functions_json: Path | None) -> tuple[dict[str, str], dict[int, str]]:
    """``ghidra_functions.json``'dan var olan fonksiyon adları ve adres → Ghidra adı."""
    if functions_json is None or not Path(functions_json).exists():
        return {}, {}
    try:
        data = json.loads(Path(functions_json).read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}, {}
    funcs = data.get("functions", []) if isinstance(data, dict) else data
    pairs: list[tuple[str, bool]] = []
    by_addr: dict[int, str] = {}
    for f in funcs if isinstance(funcs, list) else []:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str):
            continue
        pairs.append((f["name"], bool(f.get("is_thunk") or f.get("is_external"))))
        try:
            by_addr.setdefault(int(str(f.get("address", "")), 16), f["name"])
        except ValueError:
            continue
    return _name_validity.existing_function_names(pairs), by_addr


def validate_merged_names(
    merged_map: dict[str, str], *, functions_json: Path | None, used: Any,
) -> tuple[dict[str, str], dict[str, str]]:
    """Birleştiricinin haritasını c_namer'ın ad kurallarından geçir (AD-05).

    Genel anahtarda: ``name_validity.reject_reason`` (C tanımlayıcısı, anahtar sözcük, tip adı,
    ikilide başka fonksiyonun adı; anahtarın kendi fonksiyonunun adı çakışma değildir); bu
    koşuda verilmiş adla çakışan ad ``unique_name`` ile ek alır. Yerel anahtarda (``f::ad``)
    yalnız sözcük kuralları. Dönen: (süzülmüş harita, {reddedilen anahtar: neden}).
    """
    existing, by_addr = _function_index(functions_json)
    taken = set(used)
    kept: dict[str, str] = {}
    rejected: dict[str, str] = {}
    for key, name in merged_map.items():
        local = "::" in key
        own = key
        if not local and key.startswith("FUN_"):
            try:
                own = by_addr.get(int(key[4:], 16), key)
            except ValueError:
                own = key
        reason = _name_validity.reject_reason(
            name, local=local, existing_functions=None if local else existing, own_name=own)
        if reason is not None:
            rejected[key] = reason
            continue
        if not local:
            name = _name_validity.unique_name(name, taken, reserved=existing)
            taken.add(name)
        kept[key] = name
    return kept, rejected


def manual_names(meta: dict[str, Any] | None) -> dict[str, str]:
    """Künyede elle (analist) türündeki ön adlar: anahtar → ad (sıralı)."""
    out: dict[str, str] = {}
    for key in sorted(meta or {}):
        entry = (meta or {})[key]
        if (isinstance(entry, dict) and entry.get("kind") == _baglama.KIND_MANUAL
                and isinstance(entry.get("name"), str) and entry["name"]):
            out[key] = entry["name"]
    return out


def force_manual_names(
    final_map: dict[str, str], manual: dict[str, str], functions_json: Path | None,
) -> tuple[int, dict[str, str]]:
    """Elle adları ``final_map``'e zorla (yerinde). Ad geçerliliğinden geçmeyen zorlanmaz.

    Dönen: (haritayı değiştiren zorlama sayısı, {zorlanmayan anahtar: ret nedeni}).
    """
    if not manual:
        return 0, {}
    existing, by_addr = _function_index(functions_json)
    forced = 0
    refused: dict[str, str] = {}
    for key, name in manual.items():
        own = key
        if key.startswith("FUN_"):
            try:
                own = by_addr.get(int(key[4:], 16), key)
            except ValueError:
                own = key
        reason = _name_validity.reject_reason(name, existing_functions=existing, own_name=own)
        if reason is not None:
            refused[key] = reason
            continue
        if final_map.get(key) != name:
            final_map[key] = name
            forced += 1
    return forced, refused


def write_merger_provenance(
    *,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    iter_index: int,
    merge_result: Any,
    final_map: dict[str, str],
    rejected: dict[str, str],
    excluded: frozenset[str],
    decided_count: int,
    threshold: float | None,
    stats: dict[str, Any],
) -> None:
    """Birleştiricinin kararını köken kaydına yaz (``naming_provenance.json`` → ``name_merger``).

    Kayıt c_namer'ın bu yinelemedeki köken kaydına (``decompiled_dir``; c_namer'ın çıktı
    dizini) eklenir; yoksa (c_namer koşmadı) ``reconstructed/name_merger_provenance[_iterN].json``
    yazılır. Her karar: ad, birleşik güven, kaynaklar, yöntem ve koda giden haritada olup olmadığı
    (eşik / ad geçerliliği nedeniyle düşenin nedeni). Yazılamazsa yalnız istatistiğe not düşülür.
    """
    decisions: dict[str, Any] = {}
    for key in sorted(merge_result.merged_names):
        m = merge_result.merged_names[key]
        if key in final_map:
            outcome: Any = None
        elif key in rejected:
            outcome = rejected[key]
        else:
            outcome = "below_global_min"
        sources = sorted(set(m.sources))
        unmeasured = sorted(set(sources) & UNMEASURED_SOURCES)
        decisions[key] = {
            "name": m.final_name,
            "applied_name": final_map.get(key),
            # P13b / P12a kuralı: güveni ölçülmemiş K-4 kanalı (PDB, DWARF, Rust / Go, BN, TRex,
            # RTTI) kararın kaynağındaysa birleşik sayı kalibre değildir → null.
            "confidence": None if unmeasured else round(float(m.final_confidence), 4),
            "sources": sources,
            "method": m.merge_method,
            "dropped": outcome,
        }
        if unmeasured:
            decisions[key]["unmeasured_sources"] = unmeasured
    section = {
        "version": MERGER_PROVENANCE_VERSION,
        "iteration": iter_index,
        "c_namer_decided": decided_count,
        "excluded_rejected_pre_names": sorted(excluded),
        "global_min_confidence": threshold,
        "unk": merge_result.total_unk,
        "decisions": decisions,
    }
    from karadul.core.naming_labels import NAMING_PROVENANCE_FILE

    target = Path(decompiled_dir) / NAMING_PROVENANCE_FILE
    try:
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("köken kaydı sözlük değil")
            data[MERGER_PROVENANCE_SECTION] = section
        else:
            suffix = f"_iter{iter_index}" if iter_index > 0 else ""
            target = Path(reconstructed_dir) / f"name_merger_provenance{suffix}.json"
            data = {MERGER_PROVENANCE_SECTION: section}
        # c_namer'ın yazım biçimiyle aynı (indent=1, ensure_ascii, sort_keys)
        target.write_text(json.dumps(data, indent=1, ensure_ascii=True, sort_keys=True),
                          encoding="utf-8")
        stats["name_merger_provenance"] = f"yazildi:{target.name}"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        stats["name_merger_provenance"] = f"yazilamadi:{type(exc).__name__}"


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def k4_inputs(ctx: Any, functions_json: Path | None) -> dict[str, Any]:
    """P13b / BORU-14 (a): K-4 kanallarının girdileri (bayraklar, Ghidra dizini, üreticiler).

    Bayraklar ``binary_reconstruction.enable_<kanal>_naming`` (yalnız gerçek ``True`` açar;
    öntanımda hepsi kapalı, K-4: ölçülmeden açılmaz). Üretici listeleri Faz 1 adımlarının
    yapıtlarından (``pdb_symbols``, ``bn_functions``, ``trex_structs``; Faz 2'ye tohum olarak
    gelir). Ghidra dizini yalnız en az bir kanal açıkken kurulur.
    """
    pc = ctx.pipeline_context
    br = getattr(pc.config, "binary_reconstruction", None)
    flags = {src: config_flag(br, flag) for src, flag in K4_CHANNEL_FLAGS.items()}
    arts = getattr(ctx, "artifacts", None)
    get = arts.get if arts is not None and hasattr(arts, "get") else (lambda _k: None)
    binary_path = get("binary_for_byte_match")
    if not isinstance(binary_path, Path):
        tp = getattr(getattr(pc, "target", None), "path", None)
        binary_path = Path(tp) if isinstance(tp, (str, Path)) else None
    index = None
    if any(flags.values()):
        image_base = None
        try:
            from karadul.pipeline.steps.byte_pattern import BytePatternStep

            image_base = BytePatternStep._ghidra_load_base(pc=pc, functions_json=functions_json)
        except Exception:  # görüntü tabanı okunamadı: delta 0 (sayaçlar gösterir)
            logger.debug("Ghidra görüntü tabanı okunamadı", exc_info=True)
        index = load_ghidra_index(
            functions_json, binary_path=binary_path, ghidra_image_base=image_base)
    rtti = get("rtti_classes")
    return {
        "flags": flags,
        "index": index,
        "binary_path": binary_path,
        "pdb_symbols": _as_dict_list(get("pdb_symbols")),
        "pdb_status": get("pdb_status"),
        "bn_functions": _as_dict_list(get("bn_functions")),
        "bn_status": get("bn_status"),
        "trex_structs": _as_dict_list(get("trex_structs")),
        "trex_status": get("trex_status"),
        "rtti_classes": _as_dict_list(rtti),
        "rtti_status": get("rtti_status"),
    }


def run_name_merger(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    extracted_names: dict[str, str],
    naming_result: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    refdiff_naming: dict[str, str],
    fid_json: Path,
    computation_result: Any,
    pcode_naming_candidates: list[dict],
    stats: dict[str, Any],
    errors: list[str],
    artifacts: dict[str, Any],
    functions_json: Path | None = None,
) -> tuple[dict[str, str] | None, set[str], Path]:
    """NameMerger ve Aho-Corasick replacement.

    Returns:
        (final_naming_map, current_named_set, updated_decompiled_dir)
    """
    pc = ctx.pipeline_context
    final_naming_map: dict[str, str] | None = None
    current_named_set: set[str] = set()
    logger.info("  Naming merge (iter %d)...", iter_index + 1)

    if NameMerger is None:
        return final_naming_map, current_named_set, decompiled_dir

    try:
        merger = NameMerger(
            min_confidence=pc.config.binary_reconstruction.min_naming_confidence,
            merger_config=pc.config.name_merger,
        )

        # v1.11.0 Hafta 2 kopru: BSim shadow -> fusion evidence.
        # Kural: shadow_mode=True (default) -> BSim fusion'a yazmaz.
        #        shadow_mode=False AND use_bsim_fusion=True -> evidence ekle.
        bsim_shadow_payload = _maybe_load_bsim_shadow_for_fusion(
            ctx=ctx, stats=stats,
        )
        bsim_cfg = getattr(pc.config, "bsim", None)
        bsim_fusion_min_sim = float(
            getattr(bsim_cfg, "fusion_min_similarity", 0.7),
        )
        bsim_fusion_max_n = int(
            getattr(bsim_cfg, "fusion_max_candidates_per_function", 3),
        )

        # P13a / AD-04 + AD-05: c_namer koştuysa ad verdiği anahtarın kararı onundur (kod o adı
        # taşıyor; birleştirici yeniden puanlamaz, 0,70 uydurmaz); ön adlar birleştiriciye ikinci
        # kez (``binary_extractor``) girmez. c_namer'ın gördüğü ama ad vermediği ön ad anahtarı
        # (ad geçerliliği reddi, aynı ad daha öncelikli ön adda) birleştiriciden ad almaz.
        decided = c_namer_decided(naming_result)
        excluded = rejected_pre_name_keys(
            extracted_names, decided, bindiff_confidence_map, refdiff_naming)

        candidates_by_symbol = collect_candidates(
            pre_names_via_c_namer=decided is not None,
            extracted_names=extracted_names,
            naming_result=naming_result,
            bindiff_confidence_map=bindiff_confidence_map,
            refdiff_naming=refdiff_naming,
            fid_json=fid_json,
            computation_result=computation_result,
            pcode_naming_candidates=pcode_naming_candidates,
            iter_index=iter_index,
            stats=stats,
            bsim_shadow=bsim_shadow_payload,
            bsim_fusion_min_similarity=bsim_fusion_min_sim,
            bsim_fusion_max_candidates=bsim_fusion_max_n,
            # v1.21 engineering fusion: decompiled C dizini + functions_json
            # mevcutsa EngineeringAlgorithmAnalyzer + FormulaReconstructor
            # uzerinden constant/api/formula naming kanallari uretilir.
            decompiled_dir=decompiled_dir,
            functions_json=functions_json,
            # P13b / BORU-14 (a): K-4 kanalları gerçek koşuda (bayrağı açık olanlar).
            k4=k4_inputs(ctx, functions_json),
        )
        decided_map = dict(decided or {})
        for key in list(candidates_by_symbol):
            if key in decided_map:
                del candidates_by_symbol[key]
            elif key in excluded:
                # c_namer'ın reddettiği ön ADI başka kaynak önerse de geri gelmez; anahtara
                # başka bir ad öneren bağımsız kanıt (FID, hesaplama …) yarışmayı sürdürür.
                rejected_name = (extracted_names or {}).get(key)
                kept = [c for c in candidates_by_symbol[key]
                        if getattr(c, "name", None) != rejected_name]
                if kept:
                    candidates_by_symbol[key] = kept
                else:
                    del candidates_by_symbol[key]
        if decided is not None:
            stats["name_merger_c_namer_decided"] = len(decided_map)
            stats["name_merger_excluded_rejected_pre_names"] = len(excluded)
        if not candidates_by_symbol and not decided_map:
            return final_naming_map, current_named_set, decompiled_dir

        merge_result = merger.merge(candidates_by_symbol)
        merged_map = merger.to_naming_map(merge_result)
        logger.info(
            "Name merger: %d merged (%d exact_multi, %d conflicts)",
            merge_result.total_merged,
            merge_result.exact_multi_matches,
            merge_result.conflicts_resolved,
        )
        stats["name_merger_total"] = merge_result.total_merged
        stats["name_merger_exact_multi"] = merge_result.exact_multi_matches
        stats["name_merger_conflicts"] = merge_result.conflicts_resolved

        # Ürün eşiği (bayrak açıksa): c_namer'ın seçimindeki eşiğin aynısı, öbür kaynakların
        # 0,30-0,70 arasında ad yazmasını önler. Bayrak kapalıyken harita değişmez.
        threshold = global_naming_threshold(pc.config.binary_reconstruction)
        merged_map, below = drop_below_threshold(
            merged_map, merge_result.merged_names, threshold,
        )
        if threshold is not None:
            stats["name_merger_below_global_min"] = below

        # AD-05: birleştiricinin adı c_namer'ın süzgeçlerinden geçer (ad geçerliliği, var olan
        # fonksiyon adıyla çakışma, bu koşuda verilmiş adla çakışma → ek).
        merged_map, rejected = validate_merged_names(
            merged_map, functions_json=functions_json,
            used=[v for k, v in decided_map.items() if "::" not in k])
        if rejected:
            stats["name_merger_rejected"] = dict(sorted(Counter(rejected.values()).items()))

        # Koda giden harita: c_namer'ın kararları + birleştiricinin süzülmüş kararları.
        final_naming_map = dict(decided_map)
        final_naming_map.update(merged_map)
        # Bos/kisa key'leri cikar (regex \b()\b bos string bozulmasini onle)
        final_naming_map = {
            k: v for k, v in final_naming_map.items()
            if k and len(k) >= 2 and v
        }
        # B-C6 (AD-11): analistin elle verdiği ad birleştirmeden SONRA koda giden haritaya
        # zorlanır (eskiden yalnız silinen monolitte vardı). Ad geçerliliğinden geçmeyen elle ad
        # zorlanmaz; nedeniyle sayılır.
        forced, refused = force_manual_names(
            final_naming_map, manual_names(pre_name_meta_of(ctx)), functions_json)
        if forced:
            stats["name_merger_manual_forced"] = forced
        if refused:
            stats["name_merger_manual_refused"] = dict(sorted(Counter(refused.values()).items()))
        write_merger_provenance(
            decompiled_dir=decompiled_dir, reconstructed_dir=reconstructed_dir,
            iter_index=iter_index, merge_result=merge_result, final_map=merged_map,
            rejected=rejected, excluded=excluded, decided_count=len(decided_map),
            threshold=threshold, stats=stats,
        )
        if not final_naming_map:
            return final_naming_map, current_named_set, decompiled_dir

        current_named_set = _apply_aho_replace(
            iter_index=iter_index,
            decompiled_dir=decompiled_dir,
            reconstructed_dir=reconstructed_dir,
            incremental_files=incremental_files,
            final_naming_map=final_naming_map,
            artifacts=artifacts,
        )
        if current_named_set:
            merge_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
            decompiled_dir = reconstructed_dir / f"merged{merge_suffix}"
    except Exception as exc:
        logger.warning("Name merger hatasi (atlaniyor): %s", exc)
        errors.append(f"Name merger hatasi: {exc}")

    return final_naming_map, current_named_set, decompiled_dir


def _apply_aho_replace(
    *,
    iter_index: int,
    decompiled_dir: Path,
    reconstructed_dir: Path,
    incremental_files: list[Path] | None,
    final_naming_map: dict[str, str],
    artifacts: dict[str, Any],
) -> set[str]:
    """final_naming_map'i Aho-Corasick ile dosyalara paralel uygula."""
    from karadul.reconstruction.aho_replacer import AhoReplacer

    aho = AhoReplacer(final_naming_map)
    merge_suffix = f"_iter{iter_index}" if iter_index > 0 else ""
    merge_dir = reconstructed_dir / f"merged{merge_suffix}"
    merge_dir.mkdir(parents=True, exist_ok=True)

    def _dest_path(c_file: Path) -> Path:
        """v1.10.0 H10: kaynak subdirectory yapisini koru.

        Onceki kod `merge_dir / c_file.name` kullaniyordu — iki farkli
        alt-klasorde ayni `.c` adina sahip dosyalar birbirini eziyordu
        (ornek: `foo/util.c` ve `bar/util.c`).  Simdi dosyayi kaynakli
        goreli yoluyla koruyoruz; `decompiled_dir` disinda kalan nadir
        durumlarda guvenli fallback: sadece dosya adi.
        """
        try:
            rel = c_file.resolve().relative_to(decompiled_dir.resolve())
        except ValueError:
            return merge_dir / c_file.name
        return merge_dir / rel

    def merge_one(c_file: Path) -> int:
        content = c_file.read_text(encoding="utf-8", errors="replace")
        new_content = aho.replace(content)
        dst = _dest_path(c_file)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(new_content, encoding="utf-8")
        return 1 if new_content != content else 0

    all_merge_files = (
        sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
    )
    merge_process, merge_copy_count = _select_merge_files(
        all_merge_files=all_merge_files,
        incremental_files=incremental_files,
        iter_index=iter_index,
        merge_dir=merge_dir,
        decompiled_dir=decompiled_dir,
    )

    renamed_count = 0
    with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
        for result in pool.map(merge_one, merge_process):
            renamed_count += result

    artifacts["merged_names"] = merge_dir
    current_named_set = set(final_naming_map.keys())
    logger.info(
        "Name merger: %d isim dosyalara uygulandi (%d dosya degisti, "
        "%d processed, %d total, %d worker)",
        len(final_naming_map), renamed_count,
        len(merge_process), len(all_merge_files), CPU_PERF_CORES,
    )
    return current_named_set


def _maybe_load_bsim_shadow_for_fusion(
    *,
    ctx: Any,
    stats: dict[str, Any],
) -> dict[str, Any] | None:
    """BSim shadow payload'i fusion kanalina kabul edilebilirse dondur.

    Kopru kurallari:
      - cfg.bsim.enabled False -> None (NO-OP)
      - cfg.bsim.shadow_mode True (default) -> None (shadow davranisi korunur)
      - cfg.bsim.use_bsim_fusion False (default) -> None (opt-in)
      - Hepsi gecerse: once pipeline step cikti dict'i, yoksa artifact disk
        dosyasi okunur. None donusu "veri yok" anlamina gelir, collector
        bu durumda BSim evidence eklemez.
    """
    pc = ctx.pipeline_context
    bsim_cfg = getattr(pc.config, "bsim", None)
    if bsim_cfg is None:
        return None
    if not bool(getattr(bsim_cfg, "enabled", False)):
        stats["bsim_fusion_status"] = "disabled"
        return None
    shadow_mode = bool(getattr(bsim_cfg, "shadow_mode", True))
    use_fusion = bool(getattr(bsim_cfg, "use_bsim_fusion", False))
    if shadow_mode or not use_fusion:
        # Mevcut shadow davranisi -- fusion'a YAZMA
        stats["bsim_fusion_status"] = (
            "shadow" if shadow_mode else "fusion-flag-off"
        )
        return None

    # 1) StepContext.artifacts uzerinden dogrudan al (en hizli yol).
    #    bsim_match step'i "bsim_shadow" anahtari ile produces eder.
    payload: dict[str, Any] | None = None
    try:
        artifacts = getattr(ctx, "artifacts", None)
        if artifacts is not None:
            candidate = artifacts.get("bsim_shadow")
            if isinstance(candidate, dict):
                payload = candidate
    except Exception as exc:  # pragma: no cover - defansif
        logger.debug(
            "ctx.artifacts['bsim_shadow'] erisim hatasi: %s",
            exc, exc_info=True,
        )

    # 2) Fallback: disk artifact'i oku
    if payload is None:
        try:
            recon_dir = pc.workspace.get_stage_dir("reconstructed")
            shadow_path = recon_dir / "bsim_shadow.json"
            if shadow_path.exists():
                payload = json.loads(
                    shadow_path.read_text(
                        encoding="utf-8", errors="replace",
                    ),
                )
        except Exception as exc:  # pragma: no cover - defansif
            logger.debug(
                "bsim_shadow.json disk okuma hatasi: %s",
                exc, exc_info=True,
            )
            payload = None

    if not payload or not isinstance(payload, dict):
        stats["bsim_fusion_status"] = "no-data"
        return None

    stats["bsim_fusion_status"] = "active"
    return payload


def _select_merge_files(
    *,
    all_merge_files: list[Path],
    incremental_files: list[Path] | None,
    iter_index: int,
    merge_dir: Path,
    decompiled_dir: Path,
) -> tuple[list[Path], int]:
    """Incremental modda degismeyenleri hardlink'le, islenecekleri dondur."""
    if incremental_files is None or iter_index == 0:
        return all_merge_files, 0

    incr_names = {f.name for f in incremental_files}
    merge_process = [f for f in all_merge_files if f.name in incr_names]
    merge_copy = [f for f in all_merge_files if f.name not in incr_names]
    for cf in merge_copy:
        # v1.10.0 H10: kaynak subdirectory yapisini koru (hardlink + fallback).
        try:
            rel = cf.resolve().relative_to(decompiled_dir.resolve())
        except ValueError:
            rel = Path(cf.name)
        dst = merge_dir / rel
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(cf, dst)
            except (OSError, NotImplementedError):
                shutil.copy2(cf, dst)
    logger.info(
        "Incremental merge: %d files to process, %d copied unchanged",
        len(merge_process), len(merge_copy),
    )
    return merge_process, len(merge_copy)
