#!/usr/bin/env python3
"""string_context alt kanalları, adım 2 (plan v2.2 N0b): G4 etiketleriyle alt kanal başına kesinlik.

Ön kayıt ``docs/arge/2026-10-21_g10_n0b/alt_kanal_onkayit.md`` (commit f23f4ea) §4 ve §5 aynen
uygulanır. Tanımlar, alt kanal atamaları ve karar kuralı değişmez: alt kanallar ön kayıtla
depoya konan ``kayitlar_*.jsonl``'dan okunur, karar ``alt_kanal.karar()``'dan gelir.

Koşu başında ön koşullar denetlenir; biri tutmazsa koşu durur:
- ön kayıt commit'i (``ONKAYIT_COMMIT``) HEAD'in atası;
- ``alt_kanal.py``'nin sha256'sı ön kayıttaki değer (içe aktarmadan önce denetlenir);
- ``kayitlar_htop.jsonl`` ve ``kayitlar_tmux.jsonl``'ın sha256'sı ön kayıttaki değer;
- her ``string_context`` kaydı bugünkü sınıflayıcıyla aynı alt kanala düşüyor.

Öğeler ve etiketler (ön kayıt §4)
---------------------------------
- Ana öğeler: L1 ``tmux_385_kor`` ve L3 ``htop_kor``; yemler hariç; L2 kullanılmaz.
- Nihai etiket G4 puanlayıcısından gelir (``etiket_puan.final_label``): ``status == "tp"`` olan
  öğe ``tam``; yakın = ``tam`` + ``dogru_tarif``; yanlış = ``yanlis`` (yanlış fiil dahil).
- Aşama 1 amaç cümlelerinin değişmediği ``etiket_puan.check_amac_unchanged`` ile denetlenir.
- Öğe, anahtardaki adresle kayda bağlanır. Öğenin adayı ile kaydın adı taban adda (çakışma eki
  atılmış) aynı değilse öğe eşlenmemiş sayılır ve adresiyle listelenir.

Çıktı
-----
Alt kanal başına, program başına ve birleşik: n; tam, yakın, yalnız alan, yanlış sayıları; oranlar ve
Wilson %95 aralıkları (``alt_kanal.wilson``); ``alt_kanal.karar()`` (``urunde``, ``guven_etiketi``
dahil). Karar birleşik sayılarla verilir. Ayrıca tek kanal okuması, ``hepsini_kapatir()``,
``string_context`` dışı öğeler, betimsel kırılımlar (kanıt kaynağı, k) ve iki duyarlılık analizi
(``capraz_atif > 0`` öğeler dışarıda; tmux için L3 ``tmux_200_kor``). Çıktıda öğe düzeyinde ad ya
da etiket metni yoktur; adres yalnız eşlenmeyen öğeler için yazılır.

Kullanım
--------
    python scripts/measurement/alt_kanal_olc.py olc \
        --json docs/arge/2026-10-21_g10_n0b/kesinlik_tablosu.json \
        --md docs/arge/2026-10-21_g10_n0b/kesinlik_tablosu.md
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Optional

SEMA = "karadul-alt-kanal-olc/1"
REPO = Path(__file__).resolve().parents[2]
_BURASI = Path(__file__).resolve().parent

# Ön kayıt (alt_kanal_onkayit.md, commit f23f4ea)
ONKAYIT_COMMIT = "f23f4ea"
ALT_KANAL_YOLU = _BURASI / "alt_kanal.py"
ALT_KANAL_SHA256 = "d0e6f54431d77f2663f84afa6d5091e216b04b6bdf3d781005cd0c0a65c273eb"
ONKAYIT_DIZINI = REPO / "docs" / "arge" / "2026-10-21_g10_n0b"
KAYIT_SHA256 = {
    "htop": "8a3bb6eec444926fa40e4d02c413c819af50dcafd23f62bf7fefca4acada488e",
    "tmux": "81c642aae2b84d494e578f6338935ba6f2a5fc45a11dc5297389365ccb96a837",
}
G4_VERI = REPO / "docs" / "arge" / "2026-10-19_g4_etiketleme" / "veri"
ETIKET_PUAN_YOLU = _BURASI / "etiket_puan.py"

# Ön kayıt §4: (program, anahtar paketi, değerlendirici + etiket dosyası eki)
ANA_PAKETLER = (("tmux", "tmux_385_kor", "L1_tmux385"), ("htop", "htop_kor", "L3_htop"))
DUYARLILIK_PAKETI = ("tmux", "tmux_200_kor", "L3_tmux200")
ORAN_ADLARI = ("tam", "yakin", "yalniz_alan", "yanlis")
YAKIN_ETIKETLER = frozenset({"tam", "dogru_tarif"})
ONDALIK = 6


class OnkosulHatasi(RuntimeError):
    """Ön kayıt koşulu tutmuyor: koşu durur."""


# --------------------------------------------------------------------------------------------
# Ön koşullar ve içe aktarma


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def sha256_denetle(yol: Path, beklenen: str) -> str:
    gercek = sha256_dosya(yol)
    if gercek != beklenen:
        raise OnkosulHatasi(f"{yol}: sha256 {gercek}, ön kayıttaki {beklenen}")
    return gercek


def commit_atasi_mi(commit: str, kok: Path = REPO) -> bool:
    """``commit`` HEAD'in atası mı (``git merge-base --is-ancestor``)."""
    try:
        r = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=kok,
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as hata:
        raise OnkosulHatasi(f"git çalıştırılamadı: {hata}") from None
    if r.returncode not in (0, 1):
        raise OnkosulHatasi(f"git merge-base: {r.stderr.strip() or r.returncode}")
    return r.returncode == 0


def _yukle(ad: str, yol: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(ad, yol)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


_ALT_KANAL: Optional[ModuleType] = None
_ETIKET_PUAN: Optional[ModuleType] = None


def alt_kanal() -> ModuleType:
    """Ön kayıtlı ``alt_kanal.py``; sha256 içe aktarmadan önce denetlenir."""
    global _ALT_KANAL
    if _ALT_KANAL is None:
        sha256_denetle(ALT_KANAL_YOLU, ALT_KANAL_SHA256)
        _ALT_KANAL = _yukle("alt_kanal_onkayitli", ALT_KANAL_YOLU)
    return _ALT_KANAL


def etiket_puan() -> ModuleType:
    """G4 puanlayıcısı (nihai etiket, anahtar ve etiket okuma tek kaynaktan)."""
    global _ETIKET_PUAN
    if _ETIKET_PUAN is None:
        _ETIKET_PUAN = _yukle("etiket_puan_g4", ETIKET_PUAN_YOLU)
    return _ETIKET_PUAN


def onkosullari_denetle(kayit_dizini: Path = ONKAYIT_DIZINI) -> dict[str, Any]:
    if not commit_atasi_mi(ONKAYIT_COMMIT):
        raise OnkosulHatasi(f"ön kayıt commit'i {ONKAYIT_COMMIT} HEAD'in atası değil")
    sha256_denetle(ALT_KANAL_YOLU, ALT_KANAL_SHA256)
    kayit_sha = {p: sha256_denetle(kayit_dizini / f"kayitlar_{p}.jsonl", b)
                 for p, b in sorted(KAYIT_SHA256.items())}
    return {"onkayit_commit": ONKAYIT_COMMIT, "onkayit_commit_atasi": True,
            "alt_kanal_sha256": ALT_KANAL_SHA256, "kayitlar_sha256": kayit_sha}


# --------------------------------------------------------------------------------------------
# Girdiler


def kayitlari_oku(kayit_dizini: Path, program: str) -> dict[str, dict[str, Any]]:
    """Ön kayıtla donmuş kayıtlar: adres → satır. Her string_context satırı yeniden sınıflanır."""
    ak = alt_kanal()
    satirlar: dict[str, dict[str, Any]] = {}
    for satir in (kayit_dizini / f"kayitlar_{program}.jsonl").read_text(encoding="utf-8").splitlines():
        if not satir.strip():
            continue
        s = json.loads(satir)
        if s["strateji"] == ak.STRATEJI:
            yeni = ak.sinifla({"strategy": s["strateji"], "new_name": s["ad"],
                               "proposed_name": s["onerilen_ad"], "confidence": s["guven"],
                               "evidence": s["kanit"], "code_path": s["kod_yolu"],
                               "rule": s["kural"], "evidence_origin": s["kanit_kaynagi"]})
            if yeni["alt_kanal"] != s["alt_kanal"]:
                raise OnkosulHatasi(f"{program} {s['anahtar']}: alt kanal {s['alt_kanal']!r} "
                                    f"yeniden sınıflamada {yeni['alt_kanal']!r}")
        if s["adres"] in satirlar:
            raise OnkosulHatasi(f"{program}: adres iki kez: {s['adres']}")
        satirlar[s["adres"]] = s
    return satirlar


def adres_normal(adres: str) -> str:
    a = str(adres).strip().lower()
    return a if a.startswith("0x") else "0x" + a


def ogeleri_yukle(veri: Path, paket: str, etiket_eki: str) -> list[dict[str, Any]]:
    """Bir paketin ana öğeleri: id, adres, aday, nihai etiket, çapraz atıf. Yemler dışarıda."""
    ep = etiket_puan()
    anahtar = ep.load_keys([veri / f"anahtar_{paket}.json"])
    etiketler = ep.load_labels([veri / f"etiket_{etiket_eki}.jsonl"])
    ep.check_ids(etiketler, anahtar)
    amac = veri / f"amac_{etiket_eki}.jsonl"
    if amac.exists():
        ep.check_amac_unchanged(etiketler, ep.load_stage1([amac]))
    ogeler = []
    for iid in sorted(anahtar):
        item = anahtar[iid]
        if item["yem"]:
            continue
        ogeler.append({"id": iid, "adres": adres_normal(item["addr"]), "aday": item["aday"],
                       "nihai": ep.final_label(item, etiketler[iid]["etiket"]),
                       "capraz": ep.has_cross_reference(item)})
    return ogeler


def esle(ogeler: list[dict[str, Any]], kayitlar: dict[str, dict[str, Any]], program: str
         ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Öğeleri adresle kayda bağla; taban ad denetimi. Eşlenmeyenler yalnız adresle listelenir."""
    ak = alt_kanal()
    eslenen: list[dict[str, Any]] = []
    kayit_yok: list[str] = []
    ad_uyusmuyor: list[str] = []
    for o in ogeler:
        k = kayitlar.get(o["adres"])
        if k is None:
            kayit_yok.append(o["adres"])
            continue
        if ak.taban_ad(o["aday"]) != ak.taban_ad(k["ad"]):
            ad_uyusmuyor.append(o["adres"])
            continue
        eslenen.append({**o, "program": program, "strateji": k["strateji"],
                        "alt_kanal": k["alt_kanal"], "kanit_kaynagi": k["kanit_kaynagi"],
                        "k": k["k"]})
    ozet = {"ana_oge": len(ogeler), "eslenen": len(eslenen),
            "oran": round(len(eslenen) / len(ogeler), ONDALIK) if ogeler else None,
            "kayit_yok": sorted(kayit_yok), "taban_ad_uyusmuyor": sorted(ad_uyusmuyor),
            "strateji": dict(sorted(Counter(str(o["strateji"]) for o in eslenen).items()))}
    return eslenen, ozet


# --------------------------------------------------------------------------------------------
# Sayım ve tablolar


def _yuvarla(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(x, ONDALIK)


def oran(k: int, n: int) -> dict[str, Any]:
    if n == 0:
        return {"k": 0, "n": 0, "oran": None, "alt": None, "ust": None}
    alt, ust = alt_kanal().wilson(k, n)
    return {"k": k, "n": n, "oran": _yuvarla(k / n), "alt": _yuvarla(alt), "ust": _yuvarla(ust)}


def sayim(ogeler: Iterable[dict[str, Any]], karar_ver: bool = True) -> dict[str, Any]:
    ogeler = list(ogeler)
    c = Counter(o["nihai"] for o in ogeler)
    n = len(ogeler)
    sayilar = {"tam": c["tam"], "dogru_tarif": c["dogru_tarif"],
               "yakin": sum(c[e] for e in YAKIN_ETIKETLER),
               "yalniz_alan": c["yalniz_alan"], "yanlis": c["yanlis"]}
    sonuc: dict[str, Any] = {
        "n": n, "sayilar": sayilar,
        "oranlar": {ad: oran(sayilar[ad], n) for ad in ORAN_ADLARI},
        "yanlis_olmayan": oran(n - sayilar["yanlis"], n),
    }
    if karar_ver:
        k = alt_kanal().karar(n, sayilar["yanlis"])
        sonuc["karar"] = {a: (_yuvarla(v) if isinstance(v, float) else v) for a, v in k.items()}
    return sonuc


def tablo(ogeler: list[dict[str, Any]]) -> dict[str, Any]:
    """Bir öğe kümesi için alt kanal tablosu, tek kanal okuması ve string_context dışı."""
    ak = alt_kanal()
    sc = [o for o in ogeler if o["strateji"] == ak.STRATEJI]
    kanallar = {kanal: sayim(o for o in sc if o["alt_kanal"] == kanal)
                for kanal in ak.ALT_KANAL_ADLARI}
    disi = sorted({str(o["strateji"]) for o in ogeler if o["strateji"] != ak.STRATEJI})
    return {
        "alt_kanallar": kanallar,
        "tek_kanal": sayim(sc),
        "hepsini_kapatir": ak.hepsini_kapatir({k: v["karar"] for k, v in kanallar.items()}),
        "string_context_disi": {s: sayim((o for o in ogeler if o["strateji"] == s),
                                         karar_ver=False) for s in disi},
    }


def bolum(ogeler: list[dict[str, Any]]) -> dict[str, Any]:
    programlar = sorted({o["program"] for o in ogeler})
    return {"programlar": {p: tablo([o for o in ogeler if o["program"] == p]) for p in programlar},
            "birlesik": tablo(ogeler)}


def kararlar(b: dict[str, Any]) -> dict[str, str]:
    """Birleşik tablodan alt kanal başına karar (ürün kararı birleşik sayılarla verilir)."""
    return {k: v["karar"]["karar"] for k, v in b["birlesik"]["alt_kanallar"].items()}


def karar_farki(ana: dict[str, str], diger: dict[str, str]) -> dict[str, dict[str, str]]:
    return {k: {"ana": ana[k], "duyarlilik": diger[k]} for k in ana if ana[k] != diger.get(k)}


def betimsel(ogeler: list[dict[str, Any]]) -> dict[str, Any]:
    """Birleşik string_context için kanıt kaynağı ve k kırılımı (karar dışı)."""
    sc = [o for o in ogeler if o["strateji"] == alt_kanal().STRATEJI]
    kaynaklar = sorted({str(o["kanit_kaynagi"]) for o in sc})
    kler = sorted({o["k"] for o in sc if o["k"] is not None})
    return {"kanit_kaynagi": {s: sayim((o for o in sc if str(o["kanit_kaynagi"]) == s),
                                       karar_ver=False) for s in kaynaklar},
            "k": {str(k): sayim((o for o in sc if o["k"] == k), karar_ver=False) for k in kler}}


# --------------------------------------------------------------------------------------------
# Ölçüm


def olc(veri: Path = G4_VERI, kayit_dizini: Path = ONKAYIT_DIZINI,
        denetle: bool = True) -> dict[str, Any]:
    onkosul = onkosullari_denetle(kayit_dizini) if denetle else {"denetlenmedi": True}
    ak = alt_kanal()
    kayitlar = {p: kayitlari_oku(kayit_dizini, p) for p in sorted({p for p, _, _ in ANA_PAKETLER})}

    ana_ogeler: list[dict[str, Any]] = []
    esleme: dict[str, Any] = {}
    for program, paket, ek in ANA_PAKETLER:
        eslenen, ozet = esle(ogeleri_yukle(veri, paket, ek), kayitlar[program], program)
        ana_ogeler.extend(eslenen)
        esleme[paket] = ozet
    toplam = sum(e["ana_oge"] for e in esleme.values())
    eslenen_n = sum(e["eslenen"] for e in esleme.values())
    esleme["toplam"] = {"ana_oge": toplam, "eslenen": eslenen_n,
                        "oran": round(eslenen_n / toplam, ONDALIK) if toplam else None}

    ana = bolum(ana_ogeler)
    ana_kararlar = kararlar(ana)

    # Duyarlılık 1: gerçek adı başka bir öğenin gövdesinde geçen öğeler dışarıda
    atifsiz = [o for o in ana_ogeler if not o["capraz"]]
    d1 = bolum(atifsiz)
    # Duyarlılık 2: tmux kısmı L3'ün tmux_200_kor etiketleriyle
    program, paket, ek = DUYARLILIK_PAKETI
    l3_tmux, l3_esleme = esle(ogeleri_yukle(veri, paket, ek), kayitlar[program], program)
    d2 = bolum(l3_tmux + [o for o in ana_ogeler if o["program"] != program])

    girdiler = {}
    for _, paket_adi, ek_adi in ANA_PAKETLER + (DUYARLILIK_PAKETI,):
        for yol in (veri / f"anahtar_{paket_adi}.json", veri / f"etiket_{ek_adi}.jsonl",
                    veri / f"amac_{ek_adi}.jsonl"):
            if yol.exists():
                girdiler[yol.name] = sha256_dosya(yol)
    return {
        "sema": SEMA,
        "arac": {"betik": "scripts/measurement/alt_kanal_olc.py",
                 "betik_sha256": sha256_dosya(Path(__file__).resolve()),
                 "git_head": _git("rev-parse", "HEAD"), "python": platform.python_version()},
        "onkosul": onkosul,
        "girdiler": girdiler,
        "kural": {"yanlis_hedefi": ak.YANLIS_HEDEFI, "wilson_z": ak.WILSON_Z,
                  "urunde_kalan_kararlar": sorted(ak.URUNDE_KALAN_KARARLAR),
                  "guven_etiketleri": ak.GUVEN_ETIKETLERI},
        "esleme": esleme,
        "ana": ana,
        "ana_kararlar": ana_kararlar,
        "hepsini_kapatir": ana["birlesik"]["hepsini_kapatir"],
        "betimsel": betimsel(ana_ogeler),
        "duyarlilik": {
            "capraz_atifsiz": {
                "disarida": dict(sorted(Counter(o["program"] for o in ana_ogeler
                                                if o["capraz"]).items())),
                "tablo": d1, "kararlar": kararlar(d1),
                "ana_karardan_farkli": karar_farki(ana_kararlar, kararlar(d1))},
            "L3_tmux200": {
                "esleme": l3_esleme, "tablo": d2, "kararlar": kararlar(d2),
                "ana_karardan_farkli": karar_farki(ana_kararlar, kararlar(d2))},
        },
    }


def _git(*arglar: str) -> Optional[str]:
    try:
        return subprocess.run(["git", *arglar], cwd=REPO, capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except Exception:
        return None


# --------------------------------------------------------------------------------------------
# Markdown


def yuzde(x: Optional[float]) -> str:
    return "—" if x is None else f"%{x * 100:.1f}".replace(".", ",")


def _aralik(o: dict[str, Any]) -> str:
    return "—" if o["oran"] is None else f"{yuzde(o['alt'])}-{yuzde(o['ust'])}"


def markdown(s: dict[str, Any]) -> str:
    ak = alt_kanal()
    b = s["ana"]["birlesik"]
    satirlar = [
        "# N0b adım 2: alt kanal başına kesinlik (G4 etiketleriyle)",
        "",
        f"- **Ön kayıt:** `alt_kanal_onkayit.md` (commit {s['onkosul'].get('onkayit_commit')}), §4-§5 aynen.",
        f"- **Betikler:** `alt_kanal.py` sha256 `{ALT_KANAL_SHA256[:16]}…` (denetlendi); "
        f"`alt_kanal_olc.py` sha256 `{s['arac']['betik_sha256'][:16]}…`.",
        "- **Öğeler:** L1 `tmux_385_kor` ve L3 `htop_kor`, yemler hariç. `tam` anahtardaki otomatik "
        "eşleşmeden; yakın = `tam` + `dogru_tarif`; yanlış = `yanlis` (yanlış fiil dahil).",
        f"- **Eşlenme:** {s['esleme']['toplam']['eslenen']}/{s['esleme']['toplam']['ana_oge']} "
        f"({yuzde(s['esleme']['toplam']['oran'])}); taban ad denetimiyle.",
        "- **Kural:** yanlış oranının Wilson %95 aralığı [L, U], eşik %10. `dogrulandi` (U ≤ %10) ve "
        "`belirsiz` kalır; `zayif` (L > %10) ve `olculemedi` (n = 0) susar. Karar birleşik sayılarla.",
        "",
        "## Birleşik tablo ve karar",
        "",
        "| Alt kanal | n | yanlış | %95 aralık | yakın | tam | yalnız alan | karar | üründe | etiket |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for kanal in ak.ALT_KANAL_ADLARI:
        t = b["alt_kanallar"][kanal]
        o = t["oranlar"]
        k = t["karar"]
        satirlar.append(
            f"| `{kanal}` | {t['n']} | {yuzde(o['yanlis']['oran'])} | {_aralik(o['yanlis'])} | "
            f"{yuzde(o['yakin']['oran'])} | {yuzde(o['tam']['oran'])} | "
            f"{yuzde(o['yalniz_alan']['oran'])} | `{k['karar']}` | "
            f"{'evet' if k['urunde'] else 'hayır'} | {k['guven_etiketi'] or '—'} |")
    t = b["tek_kanal"]
    satirlar += [
        "",
        f"**Tek kanal okuması** (bütün `string_context`, n = {t['n']}): yanlış "
        f"{yuzde(t['oranlar']['yanlis']['oran'])} ({_aralik(t['oranlar']['yanlis'])}), yakın "
        f"{yuzde(t['oranlar']['yakin']['oran'])}; karar `{t['karar']['karar']}`.",
        "",
        f"**`hepsini_kapatir()`:** {'evet' if s['hepsini_kapatir'] else 'hayır'}.",
        "",
        "## Program başına (yalnız rapor)",
        "",
        "| Alt kanal | tmux n | tmux yanlış | tmux karar | htop n | htop yanlış | htop karar |",
        "|---|---|---|---|---|---|---|",
    ]
    progs = s["ana"]["programlar"]
    for kanal in ak.ALT_KANAL_ADLARI:
        hucre = []
        for p in ("tmux", "htop"):
            tt = progs[p]["alt_kanallar"][kanal]
            hucre += [str(tt["n"]), yuzde(tt["oranlar"]["yanlis"]["oran"]),
                      f"`{tt['karar']['karar']}`"]
        satirlar.append(f"| `{kanal}` | " + " | ".join(hucre) + " |")
    hucre = []
    for p in ("tmux", "htop"):
        tt = progs[p]["tek_kanal"]
        hucre += [str(tt["n"]), yuzde(tt["oranlar"]["yanlis"]["oran"]), f"`{tt['karar']['karar']}`"]
    satirlar.append("| *tek kanal* | " + " | ".join(hucre) + " |")
    disi = b["string_context_disi"]
    satirlar += ["", "**`string_context` dışı öğeler** (karar yok): " + (", ".join(
        f"`{st}` n = {v['n']}, yanlış {v['sayilar']['yanlis']}, yakın {v['sayilar']['yakin']}"
        for st, v in disi.items()) or "yok") + ".", "",
        "## Betimsel kırılımlar (birleşik `string_context`, karar dışı)", "",
        "| Kırılım | n | yanlış | %95 aralık | yakın |", "|---|---|---|---|---|"]
    for grup, adlar in (("kanit_kaynagi", "kaynak"), ("k", "k")):
        for deger, v in s["betimsel"][grup].items():
            o = v["oranlar"]
            satirlar.append(f"| {adlar} = `{deger}` | {v['n']} | {yuzde(o['yanlis']['oran'])} | "
                            f"{_aralik(o['yanlis'])} | {yuzde(o['yakin']['oran'])} |")
    d = s["duyarlilik"]
    satirlar += ["", "## Duyarlılık (karar dışı)", ""]
    for ad, baslik in (("capraz_atifsiz", "`capraz_atif > 0` öğeler dışarıda"),
                       ("L3_tmux200", "tmux için L3 `tmux_200_kor` etiketleri")):
        farkli = d[ad]["ana_karardan_farkli"]
        ek = ""
        if ad == "capraz_atifsiz":
            ek = " Dışarıda kalan: " + ", ".join(f"{p} {n}" for p, n in d[ad]["disarida"].items()) + "."
        else:
            es = d[ad]["esleme"]
            ek = f" Eşlenme {es['eslenen']}/{es['ana_oge']}."
        satirlar.append(f"- **{baslik}.**{ek} Ana karardan farklı alt kanal: " + (", ".join(
            f"`{k}` ({v['ana']} → {v['duyarlilik']})" for k, v in farkli.items()) or "yok") + ".")
        dt = d[ad]["tablo"]["birlesik"]
        satirlar.append("  " + "; ".join(
            f"`{k}` n = {dt['alt_kanallar'][k]['n']}, yanlış "
            f"{yuzde(dt['alt_kanallar'][k]['oranlar']['yanlis']['oran'])}"
            for k in ak.ALT_KANAL_ADLARI if dt["alt_kanallar"][k]["n"]) + ".")
    kalan = [k for k, v in b["alt_kanallar"].items() if v["karar"]["urunde"]]
    susan = [k for k, v in b["alt_kanallar"].items() if not v["karar"]["urunde"]]
    satirlar += ["", "## Özet", "",
                 "- Üründe kalan alt kanallar: " + (", ".join(
                     f"`{k}` ({b['alt_kanallar'][k]['karar']['guven_etiketi']})" for k in kalan)
                     or "yok") + ".",
                 "- N1'de susturulacak alt kanallar: " + (", ".join(
                     f"`{k}` ({b['alt_kanallar'][k]['karar']['karar']})" for k in susan)
                     or "yok") + ".",
                 "- Ayrıntı ve bütün aralıklar: `kesinlik_tablosu.json`.", ""]
    return "\n".join(satirlar)


# --------------------------------------------------------------------------------------------
# CLI


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    o = sub.add_parser("olc", help="G4 etiketleriyle alt kanal başına kesinlik ve karar")
    o.add_argument("--g4-veri", type=Path, default=G4_VERI)
    o.add_argument("--kayit-dizini", type=Path, default=ONKAYIT_DIZINI)
    o.add_argument("--json", type=Path, required=True)
    o.add_argument("--md", type=Path, default=None)
    a = ap.parse_args(argv)
    try:
        sonuc = olc(a.g4_veri, a.kayit_dizini)
    except OnkosulHatasi as hata:
        print(f"DURDU: {hata}", file=sys.stderr)
        return 2
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(markdown(sonuc), encoding="utf-8")
    b = sonuc["ana"]["birlesik"]
    for kanal, t in b["alt_kanallar"].items():
        k = t["karar"]
        print(f"{kanal:<14} n={t['n']:>3} yanlış={t['sayilar']['yanlis']:>3} "
              f"karar={k['karar']:<10} üründe={'evet' if k['urunde'] else 'hayır'}")
    print(f"tek kanal: n={b['tek_kanal']['n']} karar={b['tek_kanal']['karar']['karar']}; "
          f"hepsini_kapatir={sonuc['hepsini_kapatir']}; eşlenme "
          f"{sonuc['esleme']['toplam']['eslenen']}/{sonuc['esleme']['toplam']['ana_oge']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
