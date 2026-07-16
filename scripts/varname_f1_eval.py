#!/usr/bin/env python3
"""Değişken-adı F1 ölçüm harness'i (DWARF ground truth).

Fonksiyon-adı F1'i vardı (scripts/mac_f1_eval.py, dynsym/nm GT). Bu harness
EKSİK parçayı ekler: DEĞİŞKEN-adı (parametre + lokal) F1'i. Ground truth,
debug binary'nin DWARF bilgisinden (gerçek kaynak değişken adları) gelir;
stripped binary'de bu bilgi HİÇ yoktur, bu yüzden değişken isimlendirme
gerçek bir challenge'dır.

Akış:
  1. DWARF GT çıkar: her fonksiyon için {ad, adres, [param adları], [lokal adları]}
     (karadul.analyzers.dwarf_extractor.DwarfExtractor — Mach-O/dSYM).
  2. karadul'un STRIPPED binary üzerinde ürettiği reconstructed C dosyalarını
     ayrıştır: her fonksiyon için {ad, adres, [param adları], [lokal adları]}.
  3. Fonksiyonları ADRESLE eşleştir (DWARF low_pc ↔ reconstructed "// Address:").
  4. Fonksiyon-adı F1 (leakage uyarısıyla) + DEĞİŞKEN-adı F1 hesapla.

⚠️ LEAKAGE NOTU: Bu fixture (gnulib kripto) karadul'un imza DB'sinde olduğu
için FONKSIYON adları imza-eşleşmesiyle "bedava" kurtarılabilir — fonksiyon F1
YÜKSEK çıkar ama TEMSİLİ DEĞİL (özgün/kapalı kod için geçerli olmaz). Buna
karşılık DEĞİŞKEN adları (lokal/param) imza DB'de YOKTUR (DWARF-only) — değişken
F1 gerçek, sızıntısız ölçümdür. Asıl ilgilendiğimiz metrik odur.

Kullanım:
  python3 scripts/varname_f1_eval.py \
      --debug  <debug_or_dSYM_binary> \
      --recon-src <clean_output>/src   [--examples 15]

  # veya fixture'ı otomatik üret + analiz et + ölç:
  python3 scripts/varname_f1_eval.py --auto
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from karadul.analyzers.dwarf_extractor import DwarfExtractor  # noqa: E402
from tests.benchmark.metrics import AccuracyCalculator  # noqa: E402

# ---------------------------------------------------------------------------
# Ghidra'nın otomatik ürettiği yer-tutucu değişken adları. Bunlar "isim
# kurtarıldı" SAYILMAZ (pozisyona/tipe göre üretilmiş, anlamsız). Bir GT
# değişkeninin karşısında YALNIZCA bunlar varsa, kurtarma başarısız (FN) —
# yanlış (FP) DEĞİL. karadul'un HESAPLADIĞI jenerik adlar (accumulator_N,
# val_N, raw_value_N, result_N, i_N ...) placeholder DEĞİLDİR: onlar karadul'un
# GERÇEK isimlendirme çıktısıdır ve GT ile karşılaştırılır (çoğu "wrong" çıkar —
# bu da baseline'ın düşüklüğünü dürüstçe gösterir).
# ---------------------------------------------------------------------------
_GHIDRA_PLACEHOLDER = re.compile(
    r"^("
    r"param_\d+"
    r"|local_[0-9a-fA-F]+(_\d+)?"
    r"|local_res[0-9a-fA-F]+"
    r"|[a-z]{1,3}Stack_[0-9a-fA-F]+"     # auStack_c8, uStack_18, aiStack_20, acStack
    r"|[a-z]{1,3}Var\d+"                  # uVar1, iVar2, pcVar3, puVar4
    r"|[a-z]Stack[0-9a-fA-F]*"
    r"|unaff_\w+|extraout_\w+|in_\w+|in_stack_\w+"
    r"|unique0x[0-9a-fA-F]+"
    r"|__?stack_chk_guard"
    r")$"
)


def is_ghidra_placeholder(name: str) -> bool:
    return bool(_GHIDRA_PLACEHOLDER.match(name or ""))


# ---------------------------------------------------------------------------
# Veri modelleri
# ---------------------------------------------------------------------------
@dataclass
class FuncVars:
    """Bir fonksiyonun adı + parametre/lokal değişken adları (tek kaynaktan)."""
    name: str
    address: int
    params: list[str] = field(default_factory=list)
    locals: list[str] = field(default_factory=list)


@dataclass
class PRF:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def add(self, other: "PRF") -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn


# ---------------------------------------------------------------------------
# 1) DWARF ground truth
# ---------------------------------------------------------------------------
def extract_dwarf_gt(binary: Path) -> dict[int, FuncVars]:
    """DWARF'tan {adres -> FuncVars} çıkar. Adres 0 olanları atla
    (eşleştirilemez). İsimsiz param/lokalleri DwarfExtractor zaten eler."""
    ext = DwarfExtractor(binary)
    if not ext.has_debug_info():
        raise RuntimeError(f"DWARF debug info yok: {binary}")
    out: dict[int, FuncVars] = {}
    for fn in ext.extract_functions():
        if not fn.address:
            continue
        out[fn.address] = FuncVars(
            name=fn.name,
            address=fn.address,
            params=[p.name for p in fn.params if p.name],
            locals=[lv.name for lv in fn.locals if lv.name],
        )
    return out


# ---------------------------------------------------------------------------
# 2) karadul reconstructed C ayrıştırıcı
# ---------------------------------------------------------------------------
_RE_ADDR = re.compile(r"^//\s*Address:\s*([0-9a-fA-F]+)", re.MULTILINE)
_RE_FUNC_COMMENT = re.compile(r"^//\s*Function:\s*(\S+)", re.MULTILINE)
# Lokal bildirim satırı: "  uint accumulator_24;" / "  uint8_t auStack_c8 [160];"
# "  int *result;" — tip(ler) + isim + (opsiyonel [..]) + ;
_RE_LOCAL_DECL = re.compile(
    r"^\s+[A-Za-z_][\w ]*?[ \*]+([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;\s*$"
)
_C_KEYWORDS = {"return", "goto", "break", "continue", "typedef", "struct",
               "union", "enum", "else", "do", "case", "default", "sizeof"}


def _parse_signature_params(sig: str) -> list[str]:
    """Fonksiyon imzasındaki `(...)` içinden parametre adlarını sırayla çıkar."""
    m = re.search(r"\(([^)]*)\)", sig)
    if not m:
        return []
    inside = m.group(1).strip()
    if not inside or inside == "void":
        return []
    names: list[str] = []
    for part in inside.split(","):
        part = part.strip()
        # son identifier = param adı (tipten sonra); pointer/dizi işaretlerini at
        tok = re.findall(r"[A-Za-z_]\w*", part.replace("*", " "))
        if tok:
            names.append(tok[-1])
    return names


def _parse_one_file(text: str, stem: str) -> FuncVars | None:
    """Tek reconstructed .c metnini FuncVars'a çevir (None = adres yok)."""
    am = _RE_ADDR.search(text)
    if not am:
        return None
    addr = int(am.group(1), 16)
    fm = _RE_FUNC_COMMENT.search(text)
    fname = fm.group(1) if fm else stem
    # İmzayı fonksiyon ADIYLA çıpala: "<tip> <fname>(" satırı. Bu, docstring
    # içindeki "(1 site)" gibi tuzakları ve @param yorumlarını atlar.
    #   ^  başta *, /, //, # OLMAYAN (yani yorum/docstring değil)
    #   <fname> ardından ( ...
    esc = re.escape(fname)
    sig_re = re.compile(
        r"(?m)^(?!\s*[/*#])\s*[A-Za-z_][\w\s\*]*?\b" + esc + r"\s*\(([^;{]*)\)"
    )
    sm = sig_re.search(text)
    params: list[str] = []
    if sm:
        params = _parse_signature_params("(" + sm.group(1) + ")")

    # Lokaller: imzadan sonraki '{' gövdesinin başındaki bildirimler.
    lines = text.splitlines()
    brace_idx = None
    if sm:
        # imza satırının bulunduğu index
        upto = text[: sm.start()].count("\n")
        for j in range(upto, min(upto + 8, len(lines))):
            if "{" in lines[j]:
                brace_idx = j
                break
    locals_: list[str] = []
    if brace_idx is not None:
        for ln in lines[brace_idx + 1:]:
            s = ln.strip()
            if s == "":
                if locals_:
                    break
                continue
            if s.startswith("//") or s.startswith("#") or s.startswith("*") \
                    or s.startswith("/"):
                continue
            dm = _RE_LOCAL_DECL.match(ln)
            if dm:
                ident = dm.group(1)
                if ident in _C_KEYWORDS:
                    continue
                locals_.append(ident)
            else:
                break  # bildirim bloğu bitti
    return FuncVars(name=fname, address=addr, params=params, locals=locals_)


def parse_reconstructed(src_dir: Path) -> dict[int, FuncVars]:
    """reconstructed/src/*.c dosyalarını {adres -> FuncVars} olarak ayrıştır.

    karadul her fonksiyon için İKİ dosya yazabilir: ham Ghidra dökümü
    (`_fname.c`) ve c_namer/yorum-zenginleştirilmiş sürüm (`fname.c`, docstring'li).
    İkisinin KOD imzası aynıdır (aynı değişken adları); zenginleştirilmiş sürümde
    ek `@param`/`@called_by (... site)` docstring satırları vardır. Aynı adrese
    düşen dosyalarda docstring'siz (`_` önekli ham) sürümü tercih ederiz —
    imza çıparlaması daha az tuzak içerir; değişken adları zaten özdeştir.
    """
    by_addr: dict[int, tuple[str, FuncVars]] = {}
    for cfile in sorted(src_dir.glob("*.c")):
        try:
            text = cfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fv = _parse_one_file(text, cfile.stem)
        if fv is None:
            continue
        prev = by_addr.get(fv.address)
        if prev is None:
            by_addr[fv.address] = (cfile.name, fv)
        else:
            # Deterministik tercih: daha zengin (daha fazla isim çıkarılmış) olan;
            # eşitlikte `_` önekli ham sürüm (docstring tuzağı yok).
            prev_name, prev_fv = prev
            score_new = len(fv.params) + len(fv.locals)
            score_old = len(prev_fv.params) + len(prev_fv.locals)
            if score_new > score_old or (
                score_new == score_old and cfile.name.startswith("_")
                and not prev_name.startswith("_")
            ):
                by_addr[fv.address] = (cfile.name, fv)
    return {addr: fv for addr, (_n, fv) in by_addr.items()}


# ---------------------------------------------------------------------------
# 3) Eşleştirme + metrik
# ---------------------------------------------------------------------------
def _norm_func_name(n: str) -> str:
    return (n or "").lstrip("_")


def positional_param_prf(gt: list[str], kd: list[str],
                         calc: AccuracyCalculator) -> tuple[PRF, list]:
    """Parametreleri POZİSYONLA eşleştir (sıra derleyicide korunur). Her
    pozisyonda GT adını karadul adıyla karşılaştır; karadul placeholder ise
    kurtarma yok (FN)."""
    prf = PRF()
    examples = []
    n = max(len(gt), len(kd))
    for i in range(n):
        g = gt[i] if i < len(gt) else None
        k = kd[i] if i < len(kd) else None
        if g is None:
            # GT'de olmayan fazladan param — nadiren; atla (doğrulanamaz)
            continue
        if k is None or is_ghidra_placeholder(k):
            prf.fn += 1
            examples.append((g, k or "-", "missing"))
            continue
        res = calc.compare_name(g, k)
        if res.score > 0:
            prf.tp += 1
            examples.append((g, k, res.match_type))
        else:
            prf.fp += 1  # karadul bir isim üretti ama yanlış
            prf.fn += 1  # GT param'ı da kurtarılamadı
            examples.append((g, k, "wrong"))
    return prf, examples


def setwise_local_prf(gt: list[str], kd_all: list[str],
                      calc: AccuracyCalculator) -> tuple[PRF, list, int]:
    """Lokalleri KÜME bazlı eşleştir (decompiler değişken sayısı ≠ kaynak;
    1:1 hizalama güvenilir değil). GT lokali, fonksiyondaki HERHANGİ bir
    karadul (placeholder-olmayan) lokaliyle eşleşiyorsa TP. Eşleşmeyen GT = FN.
    Hiçbir GT ile eşleşmeyen karadul-adı = FP. Placeholder'lar sayılmaz.

    Döner: (PRF, örnekler, eşleştirilemeyen_placeholder_karadul_sayısı)
    """
    prf = PRF()
    examples = []
    kd_names = [k for k in kd_all if not is_ghidra_placeholder(k)]
    placeholders = len(kd_all) - len(kd_names)
    used = set()
    for g in gt:
        found = None
        for idx, k in enumerate(kd_names):
            if idx in used:
                continue
            res = calc.compare_name(g, k)
            if res.score > 0:
                found = (k, res.match_type)
                used.add(idx)
                break
        if found:
            prf.tp += 1
            examples.append((g, found[0], found[1]))
        else:
            prf.fn += 1
            examples.append((g, "-", "missing"))
    # eşleşmeyen karadul adları = FP (üretildi ama hiçbir GT'ye uymuyor)
    prf.fp += len(kd_names) - len(used)
    return prf, examples, placeholders


def evaluate(dwarf_gt: dict[int, FuncVars],
             recon: dict[int, FuncVars],
             calc: AccuracyCalculator) -> dict:
    """Fonksiyon + parametre + lokal F1'i hesapla, örnekleri topla."""
    func_prf = PRF()
    param_prf = PRF()
    local_prf = PRF()
    matched_funcs = 0
    unmatched_gt_funcs = []
    param_examples = []
    local_examples = []
    per_func = []
    placeholder_total = 0

    for addr, gtf in sorted(dwarf_gt.items()):
        rf = recon.get(addr)
        if rf is None:
            unmatched_gt_funcs.append((gtf.name, hex(addr)))
            # fonksiyon eşleşmedi: adı da değişkenleri de kurtarılamadı
            func_prf.fn += 1
            param_prf.fn += len(gtf.params)
            local_prf.fn += len(gtf.locals)
            continue
        matched_funcs += 1

        # --- fonksiyon adı ---
        if is_ghidra_placeholder(rf.name) or rf.name.startswith("FUN_"):
            func_prf.fn += 1
            fn_match = ("missing", rf.name)
        else:
            res = calc.compare_name(_norm_func_name(gtf.name), _norm_func_name(rf.name))
            if res.score > 0:
                func_prf.tp += 1
                fn_match = (res.match_type, rf.name)
            else:
                func_prf.fp += 1
                func_prf.fn += 1
                fn_match = ("wrong", rf.name)

        # --- parametreler (pozisyonel) ---
        p_prf, p_ex = positional_param_prf(gtf.params, rf.params, calc)
        param_prf.add(p_prf)
        param_examples.extend((gtf.name, *e) for e in p_ex)

        # --- lokaller (küme) ---
        l_prf, l_ex, ph = setwise_local_prf(gtf.locals, rf.locals, calc)
        local_prf.add(l_prf)
        placeholder_total += ph
        local_examples.extend((gtf.name, *e) for e in l_ex)

        per_func.append({
            "addr": hex(addr),
            "gt_name": gtf.name,
            "kd_name": rf.name,
            "func_match": fn_match[0],
            "gt_params": gtf.params,
            "kd_params": rf.params,
            "gt_locals": gtf.locals,
            "kd_locals_named": [k for k in rf.locals if not is_ghidra_placeholder(k)],
            "param_tp": p_prf.tp, "param_fn": p_prf.fn,
            "local_tp": l_prf.tp, "local_fn": l_prf.fn,
        })

    # değişken (param+lokal birleşik)
    var_prf = PRF()
    var_prf.add(param_prf)
    var_prf.add(local_prf)

    return {
        "matched_funcs": matched_funcs,
        "total_gt_funcs": len(dwarf_gt),
        "unmatched_gt_funcs": unmatched_gt_funcs,
        "func_prf": func_prf,
        "param_prf": param_prf,
        "local_prf": local_prf,
        "var_prf": var_prf,
        "placeholder_locals": placeholder_total,
        "param_examples": param_examples,
        "local_examples": local_examples,
        "per_func": per_func,
    }


# ---------------------------------------------------------------------------
# Raporlama
# ---------------------------------------------------------------------------
def _fmt_prf(label: str, prf: PRF) -> str:
    return (f"  {label:14s} P={prf.precision:.3f} R={prf.recall:.3f} "
            f"F1={prf.f1:.3f}  (TP={prf.tp} FP={prf.fp} FN={prf.fn})")


def print_report(res: dict, n_examples: int = 15) -> None:
    print("\n" + "=" * 66)
    print("DEĞİŞKEN-ADI F1 BASELINE (DWARF ground truth)")
    print("=" * 66)
    print(f"Eşleşen fonksiyon: {res['matched_funcs']}/{res['total_gt_funcs']} "
          f"(adresle)")
    print(f"Placeholder lokal (Ghidra auto, isimlendirilmemiş): "
          f"{res['placeholder_locals']}")
    print("\n--- METRİKLER ---")
    print(_fmt_prf("Fonksiyon", res["func_prf"]))
    print("    ⚠️ Fonksiyon F1 SIZINTILI: gnulib imza DB'de → yüksek ama temsili değil")
    print(_fmt_prf("Parametre", res["param_prf"]))
    print(_fmt_prf("Lokal", res["local_prf"]))
    print(_fmt_prf("Değişken(P+L)", res["var_prf"]))

    if res["unmatched_gt_funcs"]:
        print(f"\n--- Adresle eşleşmeyen GT fonksiyon "
              f"({len(res['unmatched_gt_funcs'])}) ---")
        for name, addr in res["unmatched_gt_funcs"][:10]:
            print(f"    {name} @ {addr}")

    print("\n--- DEĞİŞKEN ÖRNEKLERİ (GT vs karadul) ---")
    good = [e for e in res["param_examples"] + res["local_examples"]
            if e[3] in ("exact", "semantic", "partial")]
    bad = [e for e in res["param_examples"] + res["local_examples"]
           if e[3] in ("missing", "wrong")]
    print(f"  # İYİ eşleşme ({len(good)}):")
    for fn, g, k, mt in good[:max(3, n_examples // 2)]:
        print(f"    [{mt:8s}] {fn}: GT '{g}'  ↔  karadul '{k}'")
    print(f"  # KÖTÜ/eksik ({len(bad)}):")
    for fn, g, k, mt in bad[:n_examples]:
        print(f"    [{mt:8s}] {fn}: GT '{g}'  ↔  karadul '{k}'")


def build_gt_and_recon(debug: Path, recon_src: Path):
    dwarf_gt = extract_dwarf_gt(debug)
    recon = parse_reconstructed(recon_src)
    return dwarf_gt, recon


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--debug", type=Path, help="debug/dSYM binary (DWARF GT)")
    ap.add_argument("--recon-src", type=Path,
                    help="karadul çıktısı: <clean>/src dizini")
    ap.add_argument("--examples", type=int, default=15)
    ap.add_argument("--json-out", type=Path, help="metrik özetini JSON yaz")
    args = ap.parse_args()

    if not args.debug or not args.recon_src:
        ap.error("--debug ve --recon-src gerekli (veya --auto).")

    dwarf_gt, recon = build_gt_and_recon(args.debug, args.recon_src)
    print(f"DWARF GT fonksiyon: {len(dwarf_gt)} | reconstructed fonksiyon: {len(recon)}")
    calc = AccuracyCalculator()
    res = evaluate(dwarf_gt, recon, calc)
    print_report(res, args.examples)

    if args.json_out:
        payload = {
            "matched_funcs": res["matched_funcs"],
            "total_gt_funcs": res["total_gt_funcs"],
            "placeholder_locals": res["placeholder_locals"],
            "function": {"precision": res["func_prf"].precision,
                         "recall": res["func_prf"].recall,
                         "f1": res["func_prf"].f1,
                         "note": "gnulib sigdb leakage — inflated"},
            "param": {"precision": res["param_prf"].precision,
                      "recall": res["param_prf"].recall, "f1": res["param_prf"].f1},
            "local": {"precision": res["local_prf"].precision,
                      "recall": res["local_prf"].recall, "f1": res["local_prf"].f1},
            "variable": {"precision": res["var_prf"].precision,
                         "recall": res["var_prf"].recall, "f1": res["var_prf"].f1},
        }
        args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                 encoding="utf-8")
        print(f"\nJSON yazıldı: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
