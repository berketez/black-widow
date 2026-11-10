#!/usr/bin/env python3
"""N1 adım 3 "aç" kapıları (GT'siz): kolları koşturur ve kapıları sayar.

Tasarım: docs/arge/2026-11-10_n1_adim3/baglama_tasarimi_taslak.md §6.4.

Kollar (yapılandırma bayrakları):
    A0  üçü de kapalı            AT  yalnız ürün eşiği
    A1  yalnız KS-1              A2  susturma + eşik
    A3  hepsi açık (öntanımlı)   A3b hepsi açık, farklı PYTHONHASHSEED

Kapılar:
    K-A  A0 haritası taban koşunun haritasıyla aynı; AT'de FUN_ girişleri A0 ile aynı.
    K-B  A1 ve A3'te ad veren her çapa haritada aynı anahtarla, harfi harfine aynı adla.
    K-C  A2 ve A3'te susan alt kanaldan gelen genel ad 0; ürünün yazdığı sub_channel donuk
         ölçüm sınıflayıcısıyla (scripts/measurement/alt_kanal.py sinifla) her kayıtta aynı.
    K-D  A2 ve A3'te merged/ ile src/ arasında .c farkı 0 (c_namer dışı kaynak ad yazmıyor).
    K-F  A2'de susan ya da eşik altı kalan A0 adlarının akıbeti, A0 köken kaydından donuk
         halef() ile öngörülenle aynı. Yalnız çakışma eki (``_2`` gibi sayısal sonek) farkı
         ayrı sayılır ve kapıyı düşürmez: susan adlar çekilince ek numaraları kayar.
    K-G  A3 ile A3b haritaları bayt bayt aynı.
    K-E  (koşum betiği eşdeğerliği) uygulanmaz: kollar tam hat koşusuyla üretilir.

Çıktıda fonksiyon adı yoktur; yalnız sayılar.

Kullanım:
    python scripts/measurement/adim3_kapilar.py kos     --kok <dizin> [--paralel 3]
    python scripts/measurement/adim3_kapilar.py denetle --kok <dizin> --json <dosya>
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

DEPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEPO / "scripts" / "measurement"))

GHIDRA = Path.home() / "Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC"
DEBIAN = Path.home() / "karadul_olcum/n1_debian13"
MAC = DEPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"

BAYRAKLAR = ("enable_ks1_anchors", "enable_subchannel_silencing", "apply_global_naming_threshold")
# kol → (ks1, susturma, eşik, PYTHONHASHSEED)
KOLLAR = {
    "A0": (False, False, False, "1"),
    "AT": (False, False, True, "1"),
    "A1": (True, False, False, "1"),
    "A2": (False, True, True, "1"),
    "A3": (True, True, True, "1"),
    "A3b": (True, True, True, "2"),
}
ESIK = 0.7
# c_namer'ın ad çakışmasında eklediği sayısal sonek
CAKISMA_EKI_RE = re.compile(r"_\d+$")


def _eksiz(ad):
    return CAKISMA_EKI_RE.sub("", ad) if isinstance(ad, str) else ad


def _tek(desen_kok: Path, desen: str) -> Path:
    bulunan = sorted(desen_kok.glob(desen))
    if len(bulunan) != 1:
        raise SystemExit(f"tek eşleşme bekleniyordu: {desen_kok}/{desen} → {len(bulunan)}")
    return bulunan[0]


def ikililer() -> dict[str, dict[str, Path]]:
    """Ad → {girdi, taban_harita}. Girdi, saklı koşunun raw/ kopyasıdır."""
    out: dict[str, dict[str, Path]] = {}
    for ad, kok in (("debian-tmux", DEBIAN / "tmux/tmux"), ("debian-tree", DEBIAN / "tree/tree"),
                    ("mac-tmux", MAC / "tmux"), ("mac-htop", MAC / "htop")):
        ikili = ad.split("-", 1)[1]
        ws = _tek(kok / "ws/workspaces" / ikili, "*")
        out[ad] = {"girdi": ws / "raw" / ikili,
                   "taban_harita": ws / "reconstructed/src/naming_map.json"}
    return out


def _calisma_alani(kosu: Path) -> Path:
    return _tek(kosu / "ws/workspaces", "*/*")


def kos(kok: Path, paralel: int) -> int:
    kok.mkdir(parents=True, exist_ok=True)
    isler = []
    for kol, (ks1, sus, esik, tohum) in KOLLAR.items():
        yaml = kok / f"{kol}.yaml"
        yaml.write_text("binary_reconstruction:\n" + "".join(
            f"  {b}: {'true' if d else 'false'}\n" for b, d in zip(BAYRAKLAR, (ks1, sus, esik))),
            encoding="utf-8")
        for ad, yollar in ikililer().items():
            hedef = kok / ad / kol
            if (hedef / "BITTI").exists():
                continue
            isler.append((ad, kol, yollar["girdi"], hedef, yaml, tohum))

    def calistir(is_):
        ad, kol, girdi, hedef, yaml, tohum = is_
        hedef.mkdir(parents=True, exist_ok=True)
        ortam = dict(os.environ, GHIDRA_INSTALL_DIR=str(GHIDRA), PYTHONHASHSEED=tohum)
        with open(hedef / "kosu.log", "w", encoding="utf-8") as gunluk:
            r = subprocess.run(
                [sys.executable, "-m", "karadul", "analyze", str(girdi), "--skip-dynamic",
                 "--config", str(yaml), "--output-dir", str(hedef / "ws"),
                 "--output", str(hedef / "out")],
                cwd=DEPO, env=ortam, stdout=gunluk, stderr=subprocess.STDOUT)
        if r.returncode == 0:
            (hedef / "BITTI").write_text("0\n", encoding="utf-8")
        return ad, kol, r.returncode

    hata = 0
    with cf.ThreadPoolExecutor(max_workers=paralel) as havuz:
        for ad, kol, kod in havuz.map(calistir, isler):
            print(f"{ad:12} {kol:4} çıkış={kod}", flush=True)
            hata += kod != 0
    return 1 if hata else 0


def _json(yol: Path):
    return json.loads(yol.read_text(encoding="utf-8"))


def _sha(yol: Path) -> str:
    return hashlib.sha256(yol.read_bytes()).hexdigest()


def _fun(harita: dict) -> dict[str, str]:
    return {k: v for k, v in harita.get("global", {}).items() if k.startswith("FUN_")}


def denetle(kok: Path) -> dict:
    import alt_kanal as olcum_ak  # scripts/measurement/alt_kanal.py (donuk ölçüm sınıflayıcısı)

    from karadul.reconstruction.tarif import alt_kanal as urun_ak

    susan = set(urun_ak.SILENCED_SUBCHANNELS)
    sonuc: dict = {"kollar": {k: dict(zip(BAYRAKLAR, v[:3]), tohum=v[3]) for k, v in KOLLAR.items()},
                   "ikililer": {}, "kapilar": {}}
    toplam = {k: {"tutan": 0, "tutmayan": 0} for k in ("K-A", "K-B", "K-C", "K-D", "K-F", "K-G")}

    for ad, yollar in ikililer().items():
        ws = {}
        eksik = [kol for kol in KOLLAR if not (kok / ad / kol / "BITTI").exists()]
        if eksik:
            sonuc["ikililer"][ad] = {"eksik_kol": eksik}
            for k in toplam:
                toplam[k]["tutmayan"] += 1
            continue
        for kol in KOLLAR:
            ws[kol] = _calisma_alani(kok / ad / kol)
        harita = {kol: ws[kol] / "reconstructed/src/naming_map.json" for kol in KOLLAR}
        koken = {kol: _json(ws[kol] / "reconstructed/src/naming_provenance.json") for kol in KOLLAR}
        h = {kol: _json(harita[kol]) for kol in KOLLAR}
        kayit: dict = {"genel_ad": {kol: len(h[kol].get("global", {})) for kol in KOLLAR},
                       "fun_ad": {kol: len(_fun(h[kol])) for kol in KOLLAR}}

        # K-A
        taban_ayni = _sha(harita["A0"]) == _sha(yollar["taban_harita"])
        taban_fun_ayni = _fun(h["A0"]) == _fun(_json(yollar["taban_harita"]))
        at_fun_ayni = _fun(h["AT"]) == _fun(h["A0"])
        at_fark = {k for k in set(h["A0"]["global"]) ^ set(h["AT"]["global"])}
        at_fark |= {k for k in set(h["A0"]["global"]) & set(h["AT"]["global"])
                    if h["A0"]["global"][k] != h["AT"]["global"][k]}
        kayit["K-A"] = {"a0_taban_bayt_ayni": taban_ayni, "a0_taban_fun_ayni": taban_fun_ayni,
                        "at_fun_a0_ile_ayni": at_fun_ayni, "at_farkli_anahtar": len(at_fark),
                        "at_fark_fun_olmayan": sum(1 for k in at_fark if not k.startswith("FUN_")),
                        "tuttu": taban_fun_ayni and at_fun_ayni}

        # K-B
        kb = {}
        for kol in ("A1", "A3"):
            capa_yol = ws[kol] / "reconstructed/kesin_capalar.json"
            belge = _json(capa_yol) if capa_yol.exists() else {"capalar": []}
            capalar = belge.get("capalar") or belge.get("anchors") or []
            ad_veren = [c for c in capalar if c.get("atlama") is None]
            haritada = sum(1 for c in ad_veren if h[kol]["global"].get(c["anahtar"]) == c["ad"])
            farkli = sum(1 for c in ad_veren
                         if c["anahtar"] in h[kol]["global"] and h[kol]["global"][c["anahtar"]] != c["ad"])
            st = _json(ws[kol] / "reports/report.json")["pipeline"]["stages"]["reconstruct"]["stats"]
            kb[kol] = {"capa": len(capalar), "ad_veren": len(ad_veren), "haritada_ayni_adla": haritada,
                       "haritada_baska_adla": farkli, "haritada_yok": len(ad_veren) - haritada - farkli,
                       "ks1_status": st.get("ks1_status"), "ks1_named": st.get("ks1_named"),
                       "ks1_kesin": st.get("ks1_kesin"), "ks1_skipped": st.get("ks1_skipped"),
                       "etiket_dagilimi": st.get("naming_by_label")}
        kayit["K-B"] = dict(kb, tuttu=all(v["haritada_ayni_adla"] == v["ad_veren"] for v in kb.values()))

        # K-C
        kc = {}
        for kol in ("A2", "A3"):
            susandan = uyusmayan = dizgi = 0
            for r in koken[kol].get("global", {}).values():
                if r.get("strategy") != olcum_ak.STRATEJI:
                    continue
                dizgi += 1
                donuk = olcum_ak.sinifla(r)["alt_kanal"]
                susandan += donuk in susan
                yazilan = r.get("sub_channel")
                uyusmayan += yazilan is not None and yazilan != donuk
            kc[kol] = {"dizgi_kanali_adi": dizgi, "susan_kanaldan": susandan,
                       "sub_channel_uyusmayan": uyusmayan}
        kayit["K-C"] = dict(kc, tuttu=all(v["susan_kanaldan"] == 0 and v["sub_channel_uyusmayan"] == 0
                                          for v in kc.values()))

        # K-D
        kd = {}
        for kol in ("A2", "A3"):
            src = ws[kol] / "reconstructed/src"
            fark = 0
            merged_dizinleri = sorted((ws[kol] / "reconstructed").glob("merged*"))
            for md in merged_dizinleri[:1]:        # ilk yineleme: merged/
                for c in md.glob("*.c"):
                    kaynak = src / c.name
                    fark += (not kaynak.exists()) or kaynak.read_bytes() != c.read_bytes()
            st = _json(ws[kol] / "reports/report.json")["pipeline"]["stages"]["reconstruct"]["stats"]
            kd[kol] = {"merged_var": bool(merged_dizinleri), "src_ile_farkli_dosya": fark,
                       "name_merger_total": st.get("name_merger_total"),
                       "name_merger_below_global_min": st.get("name_merger_below_global_min")}
        kayit["K-D"] = dict(kd, tuttu=all(v["src_ile_farkli_dosya"] == 0 for v in kd.values()))

        # K-F: A0 köken kaydından öngörü ↔ A2 haritası (yalnız FUN_ anahtarları)
        ongoru = {"ad": 0, "silinir": 0, "bilinmiyor": 0, "dokunulmaz": 0}
        tutan = tutmayan = belirsiz = ek_farki = 0
        a2 = h["A2"]["global"]
        for anahtar, r in koken["A0"].get("global", {}).items():
            if not anahtar.startswith("FUN_"):
                continue
            hf = olcum_ak.halef(r, susan, ESIK)
            if hf["sonuc"] == "susturulmadi":
                # kazanan susmuyor: eşik altındaysa silinir, değilse aynı adla kalır
                if float(r.get("confidence", 0.0)) < ESIK and not r.get("pre_name_kind"):
                    beklenen = None
                    ongoru["silinir"] += 1
                else:
                    beklenen = r.get("new_name")
                    ongoru["dokunulmaz"] += 1
            elif hf["sonuc"] == "ad":
                beklenen = hf["ad"]
                ongoru["ad"] += 1
            elif hf["sonuc"] == "bilinmiyor":
                ongoru["bilinmiyor"] += 1
                belirsiz += 1
                continue
            else:
                beklenen = None
                ongoru["silinir"] += 1
            gercek = a2.get(anahtar)
            if gercek == beklenen:
                tutan += 1
            elif beklenen and gercek and _eksiz(gercek) == _eksiz(beklenen):
                ek_farki += 1
            else:
                tutmayan += 1
        yeni_anahtar = sum(1 for k in _fun(h["A2"]) if k not in koken["A0"].get("global", {}))
        kayit["K-F"] = {"ongoru": ongoru, "tutan": tutan, "yalniz_cakisma_eki_farki": ek_farki,
                        "tutmayan": tutmayan,
                        "ongorulemeyen": belirsiz, "a0da_olmayan_yeni_fun": yeni_anahtar,
                        "tuttu": tutmayan == 0 and yeni_anahtar == 0}

        # K-G
        kayit["K-G"] = {"a3_a3b_bayt_ayni": _sha(harita["A3"]) == _sha(harita["A3b"]),
                        "tuttu": _sha(harita["A3"]) == _sha(harita["A3b"])}

        for k in toplam:
            toplam[k]["tutan" if kayit[k]["tuttu"] else "tutmayan"] += 1
        sonuc["ikililer"][ad] = kayit

    sonuc["kapilar"] = {k: dict(v, tuttu=v["tutmayan"] == 0) for k, v in toplam.items()}
    sonuc["kapilar"]["K-E"] = {"uygulanmaz": "kollar tam hat koşusuyla üretildi; koşum betiği yok"}
    return sonuc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    k = alt.add_parser("kos")
    k.add_argument("--kok", type=Path, required=True)
    k.add_argument("--paralel", type=int, default=3)
    d = alt.add_parser("denetle")
    d.add_argument("--kok", type=Path, required=True)
    d.add_argument("--json", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.komut == "kos":
        return kos(a.kok, a.paralel)
    sonuc = denetle(a.kok)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    for kapi, v in sonuc["kapilar"].items():
        print(kapi, v)
    return 0 if all(v.get("tuttu", True) for v in sonuc["kapilar"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
