#!/usr/bin/env python3
"""S8 çıktı eşitliği: iki ``urun_kos.py`` kökünün aynı ikililerdeki Ghidra / ad çıktılarını kıyaslar.

HIZ ve ÖLÇEK paketlerinin "çıktıyı değiştirmez" kabulü (``docs/arge/2026-11-19_mythos/hiz/PLAN.md``
§0 ve §1, ``olcek/PLAN.md`` §1). Her ikili için:

- ``static/ghidra_output/*.json`` ve ``static/ghidra_*.json`` kopyaları (``ghidra_status.json``
  hariç): JSON eşitliği, ``HARIC_ALANLAR`` (zaman ve mutlak yol) dışında;
- ``static/ghidra_output/decompiled/*.c``: dosya kümesi ve bayt eşitliği;
- ``naming_map.json`` (``out/``, ``reconstructed/src/``, ``reconstructed/src_iter1/``): bayt eşitliği;
- ``static/ghidra_status.json``: ``DURUM_HARIC_ALANLAR`` dışında eşitlik; HZ-1'in süre alanları
  (``karadul.ghidra.headless.DURUM_SURE_ALANLARI``) ayrıca sayılır;
- ek satır (kabule girmez): ``static/ghidra_output/pcode.jsonl`` bayt eşitliği.

Fark birimi: JSON'da (dosya, noktalı alan yolu; liste konumu ``[]`` ile genellenir), öbürlerinde
dosya. ``--aa`` verilirse ikinci tablo (önce ↔ A/A: aynı ağaç, aynı komut, ikinci koşu) da
hesaplanır; önce ↔ sonra farklarından A/A'da da görülenler "belirlenimsizlik", görülmeyenler
"sonraya yüklenebilir" diye ayrılır. Hariç alan listesi koşuya göre genişletilmez: A/A'da çıkan
fark adıyla raporlanır.

Süre kaydı denetimi (HZ-1 ön kaydı H3 / H4; sonra kolunda): ``analysis.analyzer_times`` dolu mu;
``adim_sureleri`` anahtarları ``GHIDRA_ADIMLARI``'nda mı, değerler ≥ 0, toplam ≤ ``duration_seconds``
+ 0,01 mi; ``decompile_parcalari.parca_sayisi`` ≥ 1 mi.

``--sira-normal`` (P16e ön kaydı H3; öntanım kapalı, ham kıyas bugünkü gibi): JSON'da adı
``SIRA_NORMAL_LISTELERI``'nde olan her liste iki tarafta da ``caller_sort_key`` ile sıralanır
(başka liste sıralanmaz, başka alan çıkarılmaz); ``.c``'de ``// Callers:`` satırları iki tarafta da
çıkarılıp kalan kıyaslanır, ham hâlde farklı ``// Callers:`` satırı olan dosyalar ayrıca sayılır.

Kullanım (depo kökünden):
    python scripts/arge/hiz/s8_esitlik.py --once <kök> --sonra <kök> [--aa <kök>] \
        [--sira-normal] [--json <çıktı.json>] [--md <çıktı.md>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEPO = Path(__file__).resolve().parents[3]
# Bu ağacın karadul'u yüklensin (editable kurulum ana ağaca işaret eder).
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

from karadul.ghidra.headless import DURUM_SURE_ALANLARI, GHIDRA_ADIMLARI, caller_sort_key  # noqa: E402

# S8 alt kümesi (hiz/PLAN.md §1; ORTAK_D0 §6'daki koşu sırası).
S8_ANAHTARLARI: tuple[str, ...] = (
    "debian/coreutils/cat", "debian/coreutils/sort", "debian/tree/tree",
    "debian/sqlite3/sqlite3", "debian/htop/htop", "debian/tmux/tmux", "debian/zstd/zstd",
    "mac/tmux",
)
# JSON kıyasında yok sayılan alanlar (kökten noktalı yol; dosyadan bağımsız). HZ-1 ön kaydında
# (``hiz/on_kayit_hz1.md``) taban çıktısı taranarak sabitlendi; koşuya göre genişletilmez.
HARIC_ALANLAR: tuple[str, ...] = (
    "duration_seconds",              # decompiled.json — zaman
    "decompiled_dir",                # decompiled.json — mutlak yol
    "jsonl_path",                    # pcode.json — mutlak yol
    "query_duration",                # bsim_matches.json — zaman
    "timestamp",                     # bsim_shadow.json — zaman
    "bsim_detail.lock_wait_s",       # BSim — zaman
    "bsim_detail.ingest_s",
    "bsim_detail.query_s",
)
DURUM_HARIC_ALANLAR: tuple[str, ...] = ("duration_seconds", "project.path")
NAMING_MAP_YERLERI: tuple[str, ...] = (
    "out/naming_map.json", "ws/reconstructed/src/naming_map.json",
    "ws/reconstructed/src_iter1/naming_map.json",
)
# Toplam süre denetiminde yuvarlama payı (her değer üç basamağa yuvarlanır).
TOPLAM_PAYI_SN = 0.01
S8_FARK_ORNEK_SAYISI = 5
# Sıra-normal kıyasta sıralanan listeler (P16e ön kaydı H3; ölçümden önce sabit) ve .c'de
# çıkarılan başlık satırı.
SIRA_NORMAL_LISTELERI: tuple[str, ...] = ("callers", "called_by")
CALLERS_SATIRI_ONEKI = "// Callers:"


def sira_normal(veri: Any) -> Any:
    """``SIRA_NORMAL_LISTELERI`` adlı her sözlük listesini ``caller_sort_key`` ile sıralar."""
    if isinstance(veri, dict):
        return {k: (sorted((sira_normal(x) for x in v), key=caller_sort_key)
                    if k in SIRA_NORMAL_LISTELERI and isinstance(v, list)
                    and all(isinstance(x, dict) for x in v) else sira_normal(v))
                for k, v in veri.items()}
    if isinstance(veri, list):
        return [sira_normal(x) for x in veri]
    return veri


def _callers_satirlari(metin: bytes) -> tuple[list[bytes], list[bytes]]:
    """(``// Callers:`` satırları, kalan satırlar)."""
    onek = CALLERS_SATIRI_ONEKI.encode()
    satirlar = metin.split(b"\n")
    return ([s for s in satirlar if s.startswith(onek)],
            [s for s in satirlar if not s.startswith(onek)])


def _calisma_alani(ikili_koku: Path) -> Path:
    alanlar = sorted((ikili_koku / "ws" / "workspaces").glob("*/*"))
    alanlar = [a for a in alanlar if (a / "static").is_dir()]
    if len(alanlar) != 1:
        raise SystemExit(f"{ikili_koku}: {len(alanlar)} çalışma alanı (tam olarak bir tane olmalı)")
    return alanlar[0]


def _sil(veri: Any, yol: str) -> None:
    parcalar = yol.split(".")
    for p in parcalar[:-1]:
        if not isinstance(veri, dict) or p not in veri:
            return
        veri = veri[p]
    if isinstance(veri, dict):
        veri.pop(parcalar[-1], None)


def _temizle(veri: Any, haric: tuple[str, ...]) -> Any:
    for yol in haric:
        _sil(veri, yol)
    return veri


def json_farklari(a: Any, b: Any, yol: str = "") -> dict[str, int]:
    """İki JSON değerinin farklı yaprakları: {genelleştirilmiş yol: fark sayısı}."""
    if a == b:
        return {}
    out: dict[str, int] = {}

    def ekle(y: str, n: int = 1) -> None:
        out[y or "<kök>"] = out.get(y or "<kök>", 0) + n

    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            alt = f"{yol}.{k}" if yol else str(k)
            if k not in a or k not in b:
                ekle(alt + (" (yalnız sonra)" if k not in a else " (yalnız önce)"))
                continue
            for y, n in json_farklari(a[k], b[k], alt).items():
                ekle(y, n)
    elif isinstance(a, list) and isinstance(b, list):
        alt = yol + "[]"
        if len(a) != len(b):
            ekle(alt + " (uzunluk)")
        for x, y_ in zip(a, b):
            for y, n in json_farklari(x, y_, alt).items():
                ekle(y, n)
    else:
        ekle(yol)
    return out


def _oku(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def _json_dosyalari(static: Path) -> dict[str, Path]:
    dosyalar = {f"ghidra_output/{p.name}": p for p in (static / "ghidra_output").glob("*.json")}
    dosyalar.update({p.name: p for p in static.glob("ghidra_*.json")
                     if p.name != "ghidra_status.json"})
    return dosyalar


def ikili_kiyasla(once: Path, sonra: Path, sira_normal_kiyas: bool = False) -> dict[str, Any]:
    """Bir ikilinin iki koşusunu kıyaslar. Dönüş: birim → fark ayrıntısı ve özet sayılar.

    ``sira_normal_kiyas``: P16e H3 kıyası (modül belgesi); öntanım ham kıyas.
    """
    wa, wb = _calisma_alani(once), _calisma_alani(sonra)
    sa, sb = wa / "static", wb / "static"
    sonuc: dict[str, Any] = {"json": {}, "c": {}, "naming_map": {}, "durum": {}, "ek_pcode_jsonl": None}
    hazirla = sira_normal if sira_normal_kiyas else (lambda v: v)

    ja, jb = _json_dosyalari(sa), _json_dosyalari(sb)
    sonuc["json_dosya_sayisi"] = len(set(ja) | set(jb))
    for ad in sorted(set(ja) | set(jb)):
        if ad not in ja or ad not in jb:
            sonuc["json"][ad] = {"<dosya>": "yalnız " + ("sonra" if ad not in ja else "önce")}
            continue
        f = json_farklari(hazirla(_temizle(_oku(ja[ad]), HARIC_ALANLAR)),
                          hazirla(_temizle(_oku(jb[ad]), HARIC_ALANLAR)))
        if f:
            sonuc["json"][ad] = f

    ca = {p.name: p for p in (sa / "ghidra_output" / "decompiled").glob("*.c")}
    cb = {p.name: p for p in (sb / "ghidra_output" / "decompiled").glob("*.c")}
    sonuc["c_dosya_sayisi"] = {"once": len(ca), "sonra": len(cb)}
    if sira_normal_kiyas:
        sonuc["c_callers_satiri_farkli"] = 0
    for ad in sorted(set(ca) | set(cb)):
        if ad not in ca or ad not in cb:
            sonuc["c"][ad] = "yalnız " + ("sonra" if ad not in ca else "önce")
            continue
        ba, bb = ca[ad].read_bytes(), cb[ad].read_bytes()
        if ba == bb:
            continue
        if not sira_normal_kiyas:
            sonuc["c"][ad] = "bayt farkı"
            continue
        (cs_a, kalan_a), (cs_b, kalan_b) = _callers_satirlari(ba), _callers_satirlari(bb)
        if cs_a != cs_b:
            sonuc["c_callers_satiri_farkli"] += 1
        if kalan_a != kalan_b:
            sonuc["c"][ad] = "bayt farkı (// Callers: dışında)"

    def nm_yolu(kok: Path, w: Path, yer: str) -> Path:
        return w / yer[len("ws/"):] if yer.startswith("ws/") else kok / yer

    sonuc["naming_map_sayisi"] = 0
    for yer in NAMING_MAP_YERLERI:
        pa, pb = nm_yolu(once, wa, yer), nm_yolu(sonra, wb, yer)
        if not pa.exists() and not pb.exists():
            continue
        sonuc["naming_map_sayisi"] += 1
        if not pa.exists() or not pb.exists():
            sonuc["naming_map"][yer] = "yalnız " + ("sonra" if not pa.exists() else "önce")
        elif pa.read_bytes() != pb.read_bytes():
            sonuc["naming_map"][yer] = "bayt farkı"

    da, db = _oku(sa / "ghidra_status.json"), _oku(sb / "ghidra_status.json")
    sonuc["durum_yeni_alanlar"] = {
        "once": [k for k in DURUM_SURE_ALANLARI if k in da],
        "sonra": [k for k in DURUM_SURE_ALANLARI if k in db],
    }
    eski_a = {k: v for k, v in da.items() if k not in DURUM_SURE_ALANLARI}
    eski_b = {k: v for k, v in db.items() if k not in DURUM_SURE_ALANLARI}
    sonuc["durum"] = json_farklari(_temizle(eski_a, DURUM_HARIC_ALANLAR),
                                   _temizle(eski_b, DURUM_HARIC_ALANLAR))

    pja, pjb = sa / "ghidra_output" / "pcode.jsonl", sb / "ghidra_output" / "pcode.jsonl"
    if pja.exists() or pjb.exists():
        sonuc["ek_pcode_jsonl"] = (pja.exists() and pjb.exists()
                                   and pja.read_bytes() == pjb.read_bytes())
    return sonuc


def sure_kaydi_denetle(kosu: Path) -> dict[str, Any]:
    """HZ-1 ön kaydı H3 / H4: ``ghidra_status.json``'daki süre kaydı (sonra kolu)."""
    d = _oku(_calisma_alani(kosu) / "static" / "ghidra_status.json")
    analiz = d.get("analysis")
    adim = d.get("adim_sureleri")
    parca = d.get("decompile_parcalari")
    r: dict[str, Any] = {
        "analysis_var": isinstance(analiz, dict),
        "analiz_durumu": (analiz or {}).get("status") if isinstance(analiz, dict) else None,
        "analyzer_times_sayisi": (len(analiz.get("analyzer_times") or {})
                                  if isinstance(analiz, dict) else None),
        "analyzer_times_error": (analiz or {}).get("analyzer_times_error")
        if isinstance(analiz, dict) else None,
        "adim_sureleri_var": isinstance(adim, dict),
        "decompile_parcalari_var": isinstance(parca, dict),
    }
    r["H3_analyzer_times_dolu"] = bool(r["analyzer_times_sayisi"])
    if isinstance(adim, dict):
        toplam = sum(v for v in adim.values() if isinstance(v, (int, float)))
        r["adim_sayisi"] = len(adim)
        r["bilinmeyen_adim"] = sorted(k for k in adim if k not in GHIDRA_ADIMLARI)
        r["negatif_deger"] = sorted(k for k, v in adim.items()
                                    if not isinstance(v, (int, float)) or v < 0)
        r["adim_toplami_sn"] = round(toplam, 3)
        r["duration_seconds"] = d.get("duration_seconds")
        r["toplam_sureyi_asmiyor"] = (isinstance(d.get("duration_seconds"), (int, float))
                                      and toplam <= d["duration_seconds"] + TOPLAM_PAYI_SN)
        r["adim_sureleri"] = adim
    if isinstance(parca, dict):
        r["parca_sayisi"] = parca.get("parca_sayisi")
        r["parca_sure_sn"] = parca.get("sure_sn")
    r["H4_tutarli"] = bool(
        isinstance(adim, dict) and not r.get("bilinmeyen_adim") and not r.get("negatif_deger")
        and r.get("toplam_sureyi_asmiyor")
        and isinstance(parca, dict) and (parca.get("parca_sayisi") or 0) >= 1)
    return r


def birimler(k: dict[str, Any]) -> set[str]:
    """Bir ikili kıyasının fark birimleri (sınıflama için düz küme)."""
    out = {f"json:{ad}:{yol}" for ad, f in k["json"].items() for yol in f}
    out |= {f"c:{ad}" for ad in k["c"]}
    out |= {f"naming_map:{yer}" for yer in k["naming_map"]}
    out |= {f"ghidra_status:{yol}" for yol in k["durum"]}
    return out


def ozet_satiri(k: dict[str, Any]) -> dict[str, Any]:
    oz = {
        "json_farkli_dosya": len(k["json"]), "json_dosya": k["json_dosya_sayisi"],
        "c_farkli": len(k["c"]), "c_dosya": k["c_dosya_sayisi"],
        "naming_map_farkli": len(k["naming_map"]), "naming_map_dosya": k["naming_map_sayisi"],
        "durum_farkli_alan": len(k["durum"]),
        "durum_yeni_alanlar": k["durum_yeni_alanlar"],
        "ek_pcode_jsonl_esit": k["ek_pcode_jsonl"],
    }
    if "c_callers_satiri_farkli" in k:  # yalnız --sira-normal
        oz["c_callers_satiri_farkli"] = k["c_callers_satiri_farkli"]
    return oz


def _bitti_mi(kok: Path, anahtar: str) -> bool:
    return (kok / anahtar / "BITTI").exists()


def kos(once: Path, sonra: Path, aa: Path | None, sira_normal_kiyas: bool = False) -> dict[str, Any]:
    rapor: dict[str, Any] = {"once": str(once), "sonra": str(sonra), "aa": str(aa) if aa else None,
                             "haric_alanlar": list(HARIC_ALANLAR),
                             "durum_haric_alanlar": list(DURUM_HARIC_ALANLAR),
                             "ikililer": {}}
    if sira_normal_kiyas:
        rapor["sira_normal"] = {"listeler": list(SIRA_NORMAL_LISTELERI),
                                "c_cikarilan_satir": CALLERS_SATIRI_ONEKI}
    for anahtar in S8_ANAHTARLARI:
        satir: dict[str, Any] = {}
        if not (_bitti_mi(once, anahtar) and _bitti_mi(sonra, anahtar)):
            satir["durum"] = "koşu bitmedi (BITTI yok)"
            rapor["ikililer"][anahtar] = satir
            continue
        hz = ikili_kiyasla(once / anahtar, sonra / anahtar, sira_normal_kiyas)
        satir["sonra"] = {"ozet": ozet_satiri(hz), "farklar": {k: hz[k] for k in
                                                              ("json", "c", "naming_map", "durum")}}
        satir["sure_kaydi"] = sure_kaydi_denetle(sonra / anahtar)
        b_hz = birimler(hz)
        if aa is not None and _bitti_mi(aa, anahtar):
            k_aa = ikili_kiyasla(once / anahtar, aa / anahtar, sira_normal_kiyas)
            satir["aa"] = {"ozet": ozet_satiri(k_aa), "farklar": {k: k_aa[k] for k in
                                                                 ("json", "c", "naming_map", "durum")}}
            b_aa = birimler(k_aa)
            satir["belirlenimsizlik"] = sorted(b_hz & b_aa)
            satir["sonraya_yuklenebilir"] = sorted(b_hz - b_aa)
            satir["yalniz_aa"] = sorted(b_aa - b_hz)
        else:
            satir["aa"] = None
            satir["sonraya_yuklenebilir"] = sorted(b_hz)
        satir["cikti_esit"] = not satir["sonraya_yuklenebilir"]
        rapor["ikililer"][anahtar] = satir
    biten = [s for s in rapor["ikililer"].values() if "sonra" in s]
    rapor["ozet"] = {
        "kiyaslanan": len(biten),
        "cikti_esit_sonraya_gore": sum(1 for s in biten if s["cikti_esit"]),
        "H3_analyzer_times_dolu": sum(1 for s in biten if s["sure_kaydi"]["H3_analyzer_times_dolu"]),
        "H4_tutarli": sum(1 for s in biten if s["sure_kaydi"]["H4_tutarli"]),
        "aa_kiyaslanan": sum(1 for s in biten if s.get("aa")),
    }
    return rapor


def _d(v: Any) -> str:
    """Tablo hücresi: alan yoksa "alan yok" (0 ya da boş yazılmaz)."""
    return "alan yok" if v is None else str(v)


def markdown(r: dict[str, Any]) -> str:
    sat = ["| İkili | JSON farklı / dosya | .c farklı / dosya | naming_map farklı / dosya "
           "| ghidra_status eski alan farkı | yeni alanlar (sonra) | pcode.jsonl (ek) |",
           "|---|---|---|---|---|---|---|"]
    aa = ["| İkili | JSON farklı / dosya | .c farklı / dosya | naming_map farklı / dosya "
          "| ghidra_status eski alan farkı | pcode.jsonl (ek) |", "|---|---|---|---|---|---|"]
    sure = ["| İkili | analysis.status | analyzer_times (çözümleyici) | adım sayısı | adım toplamı / "
            "köprü sn | parça sayısı | H3 | H4 |", "|---|---|---|---|---|---|---|---|"]
    ayrinti: list[str] = []
    for anahtar, s in r["ikililer"].items():
        if "sonra" not in s:
            sat.append(f"| {anahtar} | {s['durum']} | | | | | |")
            continue
        o = s["sonra"]["ozet"]
        sat.append(f"| {anahtar} | {o['json_farkli_dosya']} / {o['json_dosya']} | "
                   f"{o['c_farkli']} / {o['c_dosya']['sonra']} | "
                   f"{o['naming_map_farkli']} / {o['naming_map_dosya']} | {o['durum_farkli_alan']} | "
                   f"{', '.join(o['durum_yeni_alanlar']['sonra']) or 'yok'} | "
                   f"{o['ek_pcode_jsonl_esit']} |")
        if s.get("aa"):
            a = s["aa"]["ozet"]
            aa.append(f"| {anahtar} | {a['json_farkli_dosya']} / {a['json_dosya']} | "
                      f"{a['c_farkli']} / {a['c_dosya']['sonra']} | "
                      f"{a['naming_map_farkli']} / {a['naming_map_dosya']} | "
                      f"{a['durum_farkli_alan']} | {a['ek_pcode_jsonl_esit']} |")
        k = s["sure_kaydi"]
        sure.append(f"| {anahtar} | {_d(k['analiz_durumu'])} | {_d(k['analyzer_times_sayisi'])} | "
                    f"{_d(k.get('adim_sayisi'))} | {_d(k.get('adim_toplami_sn'))} / "
                    f"{_d(k.get('duration_seconds'))} | {_d(k.get('parca_sayisi'))} | "
                    f"{'tuttu' if k['H3_analyzer_times_dolu'] else 'TUTMADI'} | "
                    f"{'tuttu' if k['H4_tutarli'] else 'TUTMADI'} |")
        if "c_callers_satiri_farkli" in o:
            ayrinti.append(f"- {anahtar} — sıra-normal: ham `// Callers:` satırı farklı `.c`: "
                           f"{o['c_callers_satiri_farkli']} / {o['c_dosya']['sonra']}")
        for etiket, liste in (("sonraya yüklenebilir", s.get("sonraya_yuklenebilir")),
                              ("belirlenimsizlik (A/A'da da)", s.get("belirlenimsizlik")),
                              ("yalnız A/A", s.get("yalniz_aa"))):
            if liste:
                ornek = ", ".join(f"`{x}`" for x in liste[:S8_FARK_ORNEK_SAYISI])
                fazla = f" … (+{len(liste) - S8_FARK_ORNEK_SAYISI})" if len(liste) > S8_FARK_ORNEK_SAYISI else ""
                ayrinti.append(f"- {anahtar} — {etiket}: {len(liste)} birim: {ornek}{fazla}")
    oz = r["ozet"]
    return "\n".join([
        f"Önce: `{r['once']}`  ",
        f"Sonra: `{r['sonra']}`  ",
        f"A/A: `{r['aa']}`  ",
        ("Kıyas: **sıra-normal** (`" + "`, `".join(SIRA_NORMAL_LISTELERI) + "` listeleri sıralı; `.c`'de `"
         + CALLERS_SATIRI_ONEKI + "` satırı dışarıda)") if r.get("sira_normal") else "Kıyas: ham",
        "",
        "**T-HZ1 (önce ↔ sonra)**", "", *sat, "",
        "**T-AA (önce ↔ A/A)**", "", *(aa if len(aa) > 2 else ["A/A yok ya da bitmedi."]), "",
        "**Süre kaydı (sonra kolu; H3 / H4)**", "", *sure, "",
        "**Fark birimleri**", "", *(ayrinti or ["Fark yok."]), "",
        f"Özet: {oz['kiyaslanan']} ikili kıyaslandı; sonraya yüklenebilir farkı olmayan "
        f"{oz['cikti_esit_sonraya_gore']} / {oz['kiyaslanan']}; H3 {oz['H3_analyzer_times_dolu']} / "
        f"{oz['kiyaslanan']}; H4 {oz['H4_tutarli']} / {oz['kiyaslanan']}; A/A ile ayrılan "
        f"{oz['aa_kiyaslanan']} / {oz['kiyaslanan']}.",
    ]) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--once", type=Path, required=True, help="önce kolunun urun_kos kökü")
    ap.add_argument("--sonra", type=Path, required=True, help="sonra kolunun urun_kos kökü")
    ap.add_argument("--aa", type=Path, default=None, help="önce kolunun A/A tekrarı (isteğe bağlı)")
    ap.add_argument("--json", type=Path, default=None, help="ayrıntılı rapor (JSON)")
    ap.add_argument("--md", type=Path, default=None, help="tablo (Markdown)")
    ap.add_argument("--sira-normal", action="store_true",
                    help="çağıran listeleri sıralı, .c'de // Callers: satırı dışarıda kıyasla (P16e H3)")
    a = ap.parse_args(argv)
    r = kos(a.once.expanduser(), a.sonra.expanduser(), a.aa.expanduser() if a.aa else None,
            a.sira_normal)
    md = markdown(r)
    if a.json:
        a.json.write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(md, encoding="utf-8")
    print(md)
    oz = r["ozet"]
    tam = oz["kiyaslanan"] == len(S8_ANAHTARLARI)
    return 0 if tam and oz["cikti_esit_sonraya_gore"] == oz["kiyaslanan"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
