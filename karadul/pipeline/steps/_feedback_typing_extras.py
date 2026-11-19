"""Feedback loop — XTRIDE / Dynamic / N-gram naming alt adimlari.

stages.py L3035-3219. Her biri bagimsiz, ayni arayuz: decompiled_dir'deki
.c dosyalarini tarar, re.compile cache ile in-place rename/edit uygular.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_XTRIDE_UNDEFINED_WIDTH = {"undefined1": 1, "undefined2": 2, "undefined4": 4, "undefined8": 8}


def xtride_replacement_ok(old_type: str, new_type: str) -> bool:
    """XTRIDE tahmini Ghidra bildirimini değiştirebilir mi (TIP-11).

    - ``long``/``ulong`` (Ghidra'nın somut 8 baytlık tamsayısı): yalnız işaretçi tipiyle.
    - ``undefinedN``: yalnız genişliği N olan bilinen tiple (işaretçi = 8).
    - Düz ``undefined`` (1 bayt, belirsiz) ve genişliği bilinmeyen tip (``struct``): hayır.
    """
    from karadul.reconstruction.c_type_recoverer import _same_width

    new = new_type.strip()
    if old_type in ("long", "ulong"):
        return new.endswith("*")
    if old_type not in _XTRIDE_UNDEFINED_WIDTH:
        return False
    return _same_width(old_type, new)


def run_xtride_typing(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """XTRIDE N-gram tip cikarimi — undefined8 -> gercek tip."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_xtride_typing:
        stats[f"timing_xtride_typing_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.xtride_typer import XTrideTyper
        xtride = XTrideTyper()
        xtride_total = 0
        xtride_improved = 0
        xtride_rejected = 0

        xfiles = _target_files(decompiled_dir, incremental_files, iter_index)
        pat_cache: dict[str, re.Pattern[str]] = {}
        for xf in xfiles:
            try:
                xcode = xf.read_text(encoding="utf-8", errors="replace")
                xresult = xtride.infer_types(xcode, xf.stem)
                xtride_total += xresult.total_inferred
                if not xresult.inferences:
                    continue
                new_code = xcode
                changed = False
                for xvar, xinf in xresult.inferences.items():
                    if xinf.confidence < 0.50:
                        continue
                    if xvar not in pat_cache:
                        pat_cache[xvar] = re.compile(
                            r"^(\s*)(?P<old>undefined[1248]?|long|ulong)\s+"
                            + re.escape(xvar)
                            + r"(\s*[;=])",
                            re.MULTILINE,
                        )
                    decl_pat = pat_cache[xvar]
                    m = decl_pat.search(new_code)
                    if m:
                        # TIP-11: Ghidra'nın tipi yalnız aynı genişlikte ve daha
                        # bilgili tiple değişir.  ``long``/``ulong`` Ghidra'nın veri
                        # akışıyla belirlediği somut tamsayıdır: yalnız işaretçi
                        # kanıtıyla (8 bayt) değişir; ``double`` / ``uint32_t``'ye
                        # dönmez.  ``undefinedN`` yalnız N baytlık tiple dolar.
                        if not xtride_replacement_ok(m.group("old"), xinf.inferred_type):
                            xtride_rejected += 1
                            continue
                        new = (
                            f"{m.group(1)}{xinf.inferred_type} {xvar}{m.group(3)}"
                        )
                        # Eşleşmenin kendi konumunda değiştir (ilk metin geçişinde değil).
                        new_code = new_code[:m.start()] + new + new_code[m.end():]
                        changed = True
                        xtride_improved += 1
                if changed:
                    xf.write_text(new_code, encoding="utf-8")
            except Exception:
                logger.debug(
                    "Xtride type inference dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        stats["xtride_total_inferences"] = xtride_total
        stats["xtride_type_improvements"] = xtride_improved
        stats["xtride_rejected_width_or_concrete"] = xtride_rejected
        stats["xtride_pattern_count"] = xtride.pattern_count
        logger.info(
            "  XTRIDE typing (iter %d): %d inferences, %d type improvements "
            "(%d files, %d patterns)",
            iter_index + 1, xtride_total, xtride_improved,
            len(xfiles), xtride.pattern_count,
        )
    except Exception as exc:
        logger.warning("XTRIDE typing hatasi (atlaniyor): %s", exc)
        errors.append(f"XTRIDE typing hatasi: {exc}")
    stats[f"timing_xtride_typing_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


def run_dynamic_naming(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """Frida trace tabanli dynamic naming — var_name -> suggested_name."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_dynamic_naming:
        stats[f"timing_dynamic_naming_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.dynamic_namer import DynamicNamer
        trace_path = (
            pc.workspace.get_stage_dir("dynamic") / "trace_report.json"
        )
        if not trace_path.exists():
            stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return

        dyn_namer = DynamicNamer(trace_report_path=trace_path)
        if not dyn_namer.load_trace():
            stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return

        dyn_total = 0
        dyn_applied = 0
        dyn_threshold = (
            pc.config.binary_reconstruction.ngram_confidence_threshold
        )

        dyn_files = _target_files(
            decompiled_dir, incremental_files, iter_index,
        )
        pat_cache: dict[str, re.Pattern[str]] = {}
        for df in dyn_files:
            try:
                dcode = df.read_text(encoding="utf-8", errors="replace")
                dsuggestions = dyn_namer.infer_names(df.stem, dcode)
                dyn_total += len(dsuggestions)
                if not dsuggestions:
                    continue
                changed = False
                for ds in dsuggestions:
                    if ds.confidence < dyn_threshold:
                        continue
                    if ds.var_name not in pat_cache:
                        pat_cache[ds.var_name] = re.compile(
                            r"\b" + re.escape(ds.var_name) + r"\b",
                        )
                    pat = pat_cache[ds.var_name]
                    new_code, cnt = pat.subn(ds.suggested_name, dcode)
                    if cnt > 0:
                        dcode = new_code
                        changed = True
                        dyn_applied += 1
                if changed:
                    df.write_text(dcode, encoding="utf-8")
            except Exception:
                logger.debug(
                    "Dynamic rename dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        stats["dynamic_total_suggestions"] = dyn_total
        stats["dynamic_names_applied"] = dyn_applied
        logger.info(
            "  Dynamic naming (iter %d): %d suggestions, %d applied",
            iter_index + 1, dyn_total, dyn_applied,
        )
    except Exception as exc:
        logger.warning("Dynamic naming hatasi (atlaniyor): %s", exc)
        errors.append(f"Dynamic naming hatasi: {exc}")
    stats[f"timing_dynamic_naming_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


def run_ngram_naming(
    *,
    ctx: Any,
    iter_index: int,
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    stats: dict[str, Any],
    errors: list[str],
) -> None:
    """N-gram degisken isim tahmini."""
    pc = ctx.pipeline_context
    step_start = time.monotonic()
    if not pc.config.binary_reconstruction.enable_ngram_naming:
        stats[f"timing_ngram_naming_iter{iter_index}"] = 0.0
        return

    try:
        from karadul.reconstruction.ngram_namer import NgramNamer
        # AD-10: veritabanı eskiden yalnız ``project_root/sigs`` altında aranıyordu;
        # ``--output-dir`` verilince project_root çıktı dizini olur ve kanal
        # SESSİZCE hiç çalışmazdı (istatistik yok, uyarı yok).  Artık durum
        # istatistiğe yazılır.  GHIDRA-14 (P15b): yalnız veri kökünde aranır.
        aranan = ngram_db_dirs(pc.config)
        ngram_db_dir = next((d for d in aranan if d.is_dir()), None)
        if ngram_db_dir is None:
            stats["ngram_naming_durum"] = "veri_yok"
            stats["ngram_db_aranan"] = [str(d) for d in aranan]
            logger.warning(
                "N-gram adlandırma çalışmadı: veritabanı bulunamadı (%s)",
                ", ".join(str(d) for d in aranan),
            )
            stats[f"timing_ngram_naming_iter{iter_index}"] = round(
                time.monotonic() - step_start, 1,
            )
            return
        stats["ngram_naming_durum"] = "calisti"
        stats["ngram_db_dizini"] = str(ngram_db_dir)

        ngram_namer = NgramNamer(db_dir=ngram_db_dir)
        ngram_total = 0
        ngram_applied = 0
        ngram_rejected_invalid = 0
        ngram_rejected_collision = 0
        ngram_threshold = (
            pc.config.binary_reconstruction.ngram_confidence_threshold
        )

        ngram_files = _target_files(
            decompiled_dir, incremental_files, iter_index,
        )
        # P05c: koda yazılan her n-gram adı köken kaydına (eskiden yalnız sayaç vardı)
        prov_applied: list[dict[str, Any]] = []
        prov_candidates: list[dict[str, Any]] = []
        ngram_below_threshold = 0
        for nf in ngram_files:
            try:
                ncode = nf.read_text(encoding="utf-8", errors="replace")
                nresult = ngram_namer.predict(ncode, nf.stem)
                ngram_total += nresult.total_predicted
                if not nresult.predictions:
                    continue
                accepted = {
                    nvar: npred.predicted_name
                    for nvar, npred in nresult.predictions.items()
                    if npred.confidence >= ngram_threshold
                }
                ngram_below_threshold += len(nresult.predictions) - len(accepted)
                plan: dict[str, str] = {}
                new_code, applied, bad, clash = apply_local_renames(
                    ncode, accepted, applied_out=plan,
                )
                ngram_rejected_invalid += bad
                ngram_rejected_collision += clash
                for nvar, nname in sorted(plan.items()):
                    npred = nresult.predictions[nvar]
                    record = {
                        "file": nf.name,
                        "var": nvar,
                        "name": nname,
                        "source": NGRAM_PROVENANCE_SOURCE,
                        "confidence": round(float(npred.confidence), 4),
                        "evidence": npred.evidence,
                    }
                    if NGRAM_APPLY_NAMES:
                        prov_applied.append(record)
                    else:
                        record["rejected"] = NGRAM_REJECT_PRECISION
                        prov_candidates.append(record)
                if applied and NGRAM_APPLY_NAMES:
                    ngram_applied += applied
                    nf.write_text(new_code, encoding="utf-8")
            except Exception:
                logger.debug(
                    "N-gram prediction dosya islemi basarisiz, atlaniyor",
                    exc_info=True,
                )

        # P05c: sayaçlar yinelemeler boyunca toplanır. Eskiden her yineleme üstüne yazıyordu:
        # ikinci yineleme (yalnız değişen dosyalar) ilk yinelemenin yüzlerce adını rapordan
        # siliyordu (birleşik koşu dir: rapor 0, ilk yinelemede koda yazılan 138).
        for key, value in (
            ("ngram_total_predictions", ngram_total),
            ("ngram_names_applied", ngram_applied),
            ("ngram_rejected_invalid", ngram_rejected_invalid),
            ("ngram_rejected_collision", ngram_rejected_collision),
            ("ngram_candidates", len(prov_candidates)),
        ):
            stats[key] = stats.get(key, 0) + value
            stats[f"{key}_iter{iter_index}"] = value
        prov_state = write_ngram_provenance(
            decompiled_dir=decompiled_dir, iter_index=iter_index, section={
                "version": NGRAM_PROVENANCE_VERSION,
                "iteration": iter_index,
                "source": NGRAM_PROVENANCE_SOURCE,
                "db_dir": str(ngram_db_dir),
                "min_confidence": ngram_threshold,
                "apply_names": NGRAM_APPLY_NAMES,
                "measured_precision": NGRAM_MEASURED_PRECISION,
                "predictions": ngram_total,
                "applied": prov_applied,
                "candidates": prov_candidates,
                "rejected": {
                    "below_min_confidence": ngram_below_threshold,
                    "invalid_name": ngram_rejected_invalid,
                    "collision": ngram_rejected_collision,
                },
            },
        )
        stats["ngram_provenance"] = prov_state
        stats[f"ngram_provenance_iter{iter_index}"] = prov_state
        logger.info(
            "  N-gram naming (iter %d): %d predictions, %d applied, %d geçersiz, "
            "%d çakışma (%d files)",
            iter_index + 1, ngram_total, ngram_applied, ngram_rejected_invalid,
            ngram_rejected_collision, len(ngram_files),
        )
    except Exception as exc:
        logger.warning("N-gram naming hatasi (atlaniyor): %s", exc)
        errors.append(f"N-gram naming hatasi: {exc}")
    stats[f"timing_ngram_naming_iter{iter_index}"] = round(
        time.monotonic() - step_start, 1,
    )


NGRAM_PROVENANCE_SECTION = "ngram_locals"
NGRAM_PROVENANCE_SOURCE = "ngram"
NGRAM_PROVENANCE_VERSION = 1
# P05c Kalem 5 (ön kayıt P05c_on_kayit.md §4): n-gram adlarının DWARF'lı 22 ikilide ölçülen
# kesinliği kanal eşiğinin (%6) çok altında (gevşek ölçüt, katının üst sınırı; ayrıntı
# docs/arge/2026-11-18_onarim/P05c.md). Daraltılmış kapı (güven ≥ 0,80 ve en az 2 kullanım) da
# eşiği geçmedi. K-2: ad koda yazılmaz; kapıdan geçen her tahmin köken kaydına ADAY olarak girer
# (``candidates``; Ghidra'nın adı kalır). Yeni ölçümle eşik geçilirse True yapılır.
NGRAM_APPLY_NAMES = False
NGRAM_REJECT_PRECISION = "measured_precision_below_threshold"
NGRAM_MEASURED_PRECISION: dict[str, Any] = {
    "metric": "loose_dwarf_name_match",
    "set": "P05c D (22 DWARF ELF, G 9 / K 13)",
    "threshold": 0.06,
    "G": {"dogru": 18, "hukumlu": 3477, "kesinlik": 0.0052},
    "G_dar": {"dogru": 6, "hukumlu": 1599, "kesinlik": 0.0038},
    "K": {"dogru": 42, "hukumlu": 2803, "kesinlik": 0.0150},
    "D": {"dogru": 60, "hukumlu": 6280, "kesinlik": 0.0096, "tam": 11},
}


def write_ngram_provenance(
    *, decompiled_dir: Path, iter_index: int, section: dict[str, Any],
) -> str:
    """N-gram kararını köken kaydına yaz (P05c; ``naming_provenance.json`` → ``ngram_locals``).

    Hedef bu yinelemenin c_namer köken kaydıdır: ``<reconstructed>/src`` (ilk yineleme) ya da
    ``src_iterN``; ``<reconstructed>`` tip kurtarmanın çıktı dizininin (``typed[_iterN]``) üstü.
    Kayıt yoksa (c_namer koşmadı) ``<reconstructed>/ngram_provenance[_iterN].json`` yazılır.
    Dönen değer ``stats["ngram_provenance"]``'a girer: ``yazildi:<dosya yolu (reconstructed'a
    göre)>`` ya da ``yazilamadi:<hata>``.
    """
    import json

    from karadul.core.naming_labels import NAMING_PROVENANCE_FILE

    reconstructed = Path(decompiled_dir).parent
    suffix = f"_iter{iter_index}" if iter_index > 0 else ""
    target = reconstructed / f"src{suffix}" / NAMING_PROVENANCE_FILE
    try:
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("köken kaydı sözlük değil")
        else:
            target = reconstructed / f"ngram_provenance{suffix}.json"
            data = {}
        data[NGRAM_PROVENANCE_SECTION] = section
        # c_namer'ın yazım biçimiyle aynı (indent=1, ensure_ascii, sort_keys)
        target.write_text(json.dumps(data, indent=1, ensure_ascii=True, sort_keys=True),
                          encoding="utf-8")
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("N-gram köken kaydı yazılamadı (%s): %s", target, exc)
        return f"yazilamadi:{type(exc).__name__}"
    return f"yazildi:{target.relative_to(reconstructed).as_posix()}"


def ngram_db_dirs(config: Any) -> list[Path]:
    """N-gram ad veritabanının aranacağı dizin (AD-10, GHIDRA-14).

    Yalnız veri kökü (``config.data_root``; yoksa ``resolve_data_root``). Çıktı kökü
    (``project_root``) ve çalışma dizini ARANMAZ: aynı ikilinin yerel adları
    komutun hangi dizinden / girişten koşulduğuna bağlı olmasın.
    """
    from karadul.analyzers.signature_db import _config_data_root

    data_root = _config_data_root(config)
    return [Path(data_root) / "sigs" / "ngram_name_db"] if data_root is not None else []


_IDENT = re.compile(r"[A-Za-z_]\w*")


def apply_local_renames(
    code: str, renames: dict[str, str], *, applied_out: dict[str, str] | None = None,
) -> tuple[str, int, int, int]:
    """Yerel değişken adlarını yalnız KODDA değiştir (AD-10).

    Eski uygulama ``re.subn(r"\bvar\b", ad, kod)`` ile bütün dosyaya yazıyordu:
    dizgi ve yorum içi de değişiyordu, ``int`` gibi geçersiz ad ya da dosyada
    zaten kullanılan bir ad süzülmüyordu.  Kurallar:
    - ad ``name_validity.lexical_reject_reason(local=True)``'dan geçer;
    - ad dosyanın kodunda zaten geçmez ve aynı dosyada iki değişkene verilmez;
    - değişim dizgi sabiti ve yorum içinde yapılmaz.

    ``applied_out`` verilirse uygulanan değişken → ad eşlemesi ona yazılır (köken kaydı, P05c).

    Returns:
        (yeni kod, uygulanan, geçersiz ad, çakışma)
    """
    from karadul.reconstruction.c_type_recoverer import mask_noncode
    from karadul.reconstruction.name_validity import lexical_reject_reason

    masked = mask_noncode(code)
    used = set(_IDENT.findall(masked))
    taken: set[str] = set()
    plan: dict[str, str] = {}
    bad = clash = 0
    for var, name in sorted(renames.items()):
        if var not in used or name == var:
            continue
        if lexical_reject_reason(name, local=True) is not None:
            bad += 1
            continue
        if name in used or name in taken:
            clash += 1
            continue
        taken.add(name)
        plan[var] = name
    if not plan:
        return code, 0, bad, clash
    if applied_out is not None:
        applied_out.update(plan)
    pattern = re.compile(r"\b(" + "|".join(re.escape(v) for v in plan) + r")\b")
    parts: list[str] = []
    last = 0
    # Örtülü metinde eşleşen konumlar özgün metinde de aynıdır (uzunluk korunur).
    for m in pattern.finditer(masked):
        parts.append(code[last:m.start()])
        parts.append(plan[m.group(1)])
        last = m.end()
    parts.append(code[last:])
    return "".join(parts), len(plan), bad, clash


def _target_files(
    decompiled_dir: Path,
    incremental_files: list[Path] | None,
    iter_index: int,
) -> list[Path]:
    """Iter'e gore islenecek dosyalar (incremental filtresi dahil)."""
    files = (
        sorted(decompiled_dir.rglob("*.c")) if decompiled_dir.exists() else []
    )
    if incremental_files is not None and iter_index > 0:
        incr = {f.name for f in incremental_files}
        files = [f for f in files if f.name in incr]
    return files
