"""P03 ölçümü: YARA'nın iki arka ucu (yara-python, regex yedeği) aynı hükmü mü veriyor?

Masum kapının sabit setlerindeki (``docs/arge/2026-11-18_onarim/P00/setler.json``)
her ikiliyi iki arka uçla tarar; her kural için (kural adı, eşleşen dizgi
kimlikleri kümesi) karşılaştırılır. Fark varsa ikili ve kural yazılır.

Kullanım (worktree kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/p03_olc.py \
        --setler /Users/apple/Black_Widow/docs/arge/2026-11-18_onarim/P00/setler.json \
        --cikti ~/karadul_olcum/runs/onarim-2026-11-18/P03/arka_uc_esitligi.json

Çıkış kodu: 0 = bütün ikililerde iki arka uç aynı; 1 = fark var ya da yara-python yok.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Betiğin kendi ağacı önce yüklensin (karadul ana ağaca editable kurulu;
# yoksa worktree'de ana ağacın kodu ölçülür).
DEPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(DEPO))


def _imza(sonuc) -> dict[str, list[str]]:
    return {m.rule: sorted({ident for _, ident, _ in m.strings}) for m in sonuc.matches}


def _kural_apileri(kural_dizini: Path) -> dict[str, set[str]]:
    """capa kural adı -> kuralın andığı API adları (dll öneki, A/W soneki atılmış)."""
    import re
    out: dict[str, set[str]] = {}
    for yml in kural_dizini.rglob("*.yml"):
        metin = yml.read_text(encoding="utf-8", errors="replace")
        ad = re.search(r"^\s+name:\s*(.+?)\s*$", metin, re.M)
        if not ad:
            continue
        apiler = {_api_norm(x) for x in re.findall(r"\bapi:\s*([\w.:$@?]+)", metin)}
        out[ad.group(1).strip("'\"")] = {x for x in apiler if x}
    return out


def _api_norm(ad: str) -> str:
    ad = ad.split(".")[-1].split("::")[-1].lstrip("_")
    if len(ad) > 2 and ad[-1] in "AW" and ad[-2].islower():
        ad = ad[:-1]
    return ad.lower()


def capa_dogrula(kapi_json: Path, kural_dizini: Path, cikti: Path) -> int:
    """Masum kapının capa iddialarını içe aktarma tablosuyla karşılaştır.

    Her (ikili, yetenek) için: kuralın andığı API'lerden biri ikilinin içe
    aktarma tablosunda ya da dizgilerinde (çalışma anında çözümleme) var mı?
    - ``api_var``: iddia içe aktarılan/çözümlenen API ile tutarlı (davranış kodda var;
      çağıranın uygulama mı statik CRT mi olduğu bu ölçümle ayrılmaz),
    - ``api_yok``: kural API anıyor ama hiçbiri ikilide yok (şüpheli),
    - ``apisiz``: kural API anmıyor (PE yapısı, komut deseni); bu yolla doğrulanmadı.
    """
    import pefile

    kapi = json.loads(kapi_json.read_text(encoding="utf-8"))
    apiler = _kural_apileri(kural_dizini)
    satirlar = []
    sayac = {"api_var": 0, "api_yok": 0, "apisiz": 0, "kural_yok": 0}
    for set_adi, kayitlar in kapi["kayitlar"].items():
        for r in kayitlar:
            capa = r["katmanlar"].get("capa") or {}
            if capa.get("durum") != "calisti":
                continue
            veri = Path(r["yol"]).read_bytes()
            ithal: set[str] = set()
            try:
                pe = pefile.PE(data=veri, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    for imp in dll.imports:
                        if imp.name:
                            ithal.add(_api_norm(imp.name.decode("latin-1")))
            except Exception:
                pass
            dizgi = veri.lower()
            for idd in capa["iddialar"]:
                ad = idd["etiket"].split(":", 1)[1]
                kural = apiler.get(ad)
                if kural is None:
                    sinif = "kural_yok"
                elif not kural:
                    sinif = "apisiz"
                elif kural & ithal or any(a.encode() in dizgi for a in kural if len(a) >= 8):
                    sinif = "api_var"
                else:
                    sinif = "api_yok"
                sayac[sinif] += 1
                satirlar.append({"set": set_adi, "ikili": r["anahtar"], "yetenek": ad, "sinif": sinif})
    cikti.parent.mkdir(parents=True, exist_ok=True)
    cikti.write_text(json.dumps({"sayac": sayac, "satirlar": satirlar}, ensure_ascii=False,
                                indent=1) + "\n", encoding="utf-8")
    print(json.dumps(sayac, ensure_ascii=False))
    for s in satirlar:
        if s["sinif"] in ("api_yok", "kural_yok"):
            print(s["sinif"], s["ikili"].split("/")[-1], s["yetenek"])
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--setler", type=Path)
    ap.add_argument("--set", default="gelistirme,macos,pe,pozitif")
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--capa-dogrula", type=Path, default=None,
                    help="masum_kapi.json: capa iddialarını içe aktarma tablosuyla karşılaştır")
    ap.add_argument("--capa-kurallari", type=Path,
                    default=Path.home() / ".cache" / "karadul" / "capa-rules")
    a = ap.parse_args(argv)
    if a.capa_dogrula:
        return capa_dogrula(a.capa_dogrula, a.capa_kurallari, a.cikti)
    if a.setler is None:
        ap.error("--setler gerekli")

    import karadul
    from karadul.analyzers.yara_scanner import YaraScanner

    if Path(karadul.__file__).resolve().parents[1] != DEPO:
        print(f"yanlış ağaç yüklendi: {karadul.__file__}", file=sys.stderr)
        return 2

    yerli = YaraScanner()
    if not yerli.yara_available:
        print("yara-python yok: eşitlik ölçülemez", file=sys.stderr)
        return 1
    yerli.load_builtin_rules()
    yedek = YaraScanner()
    yedek._yara_available = False
    yedek._yara = None
    yedek.load_builtin_rules()

    setler = json.loads(a.setler.read_text(encoding="utf-8"))["setler"]
    kayitlar = []
    farkli = 0
    olculemeyen = 0
    t0 = time.time()
    for set_adi in a.set.split(","):
        for e in setler[set_adi]:
            yol = Path(e["gercek_yol"])
            try:
                veri = yol.read_bytes()
            except OSError as exc:
                kayitlar.append({"set": set_adi, "ikili": e["anahtar"], "hata": str(exc)})
                olculemeyen += 1
                continue
            r1 = yerli.scan_bytes(veri)
            r2 = yedek.scan_bytes(veri)
            i1, i2 = _imza(r1), _imza(r2)
            ayni = i1 == i2
            farkli += 0 if ayni else 1
            kayit = {"set": set_adi, "ikili": e["anahtar"], "ayni": ayni,
                     "yara_python": i1, "arka_uc_1": r1.backend, "arka_uc_2": r2.backend}
            if not ayni:
                kayit["regex_yedegi"] = i2
            kayitlar.append(kayit)

    ozet = {
        "agac": str(Path(karadul.__file__).resolve().parents[1]),
        "ikili": len(kayitlar),
        "farkli": farkli,
        "olculemeyen": olculemeyen,
        "sure_sn": round(time.time() - t0, 1),
    }
    a.cikti.parent.mkdir(parents=True, exist_ok=True)
    a.cikti.write_text(json.dumps({"ozet": ozet, "kayitlar": kayitlar},
                                  ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(ozet, ensure_ascii=False))
    for k in kayitlar:
        if k.get("ayni") is False:
            print("FARK", k["set"], k["ikili"], k["yara_python"], k["regex_yedegi"])
    return 0 if farkli == 0 and olculemeyen == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
