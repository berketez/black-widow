"""G8 kaynak taraması: yapı seçimi sayımları, aday fonksiyonlar, gerçek adresler.

Çıktı: workspaces/2026-10-19_g8/veri/kaynak_adaylar.json

Ön kayıt §2 (yapı seçimi) ve §3 (a)-(d) koşulları burada uygulanır. (e)-(f) Ghidra
taban projesine bağlıdır ve taban.py'de uygulanır.
"""

from __future__ import annotations

import collections
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402

YAPI = "window_pane"


def derlenen_dosyalar() -> list[Path]:
    """Ön kayıttaki 144 dosya: kök dizindeki .c dosyaları; darwin dışı osdep-* hariç.
    (compat/ ve fuzz/ alt dizinleri zaten kök değil.)"""
    out = []
    for p in sorted(ortak.TMUX_SRC.glob("*.c")):
        if p.name.startswith("osdep-") and p.name != "osdep-darwin.c":
            continue
        out.append(p)
    return out


def derleme_ile_tutarli(dosyalar: list[Path]) -> dict:
    """Seçilen dosya kümesini gerçek derlemenin (make.log bağlama satırı) nesne listesiyle karşılaştır."""
    log = (ortak.BUILD_G / "make.log").read_text()
    bag = [s for s in log.splitlines() if " -o tmux " in s][-1]
    nesneler = {Path(t).stem for t in bag.split() if t.endswith(".o") and "/" not in t}
    kume = {p.stem for p in dosyalar}
    return {"derlenen_kok_nesne": len(nesneler), "secilen": len(kume),
            "yalniz_secilende": sorted(kume - nesneler), "yalniz_derlemede": sorted(nesneler - kume)}


RE_TANIM = re.compile(r"^([A-Za-z_]\w*)\(", re.M)


def _kapanis(s: str, i: int) -> int:
    d = 0
    for k in range(i, len(s)):
        if s[k] == "(":
            d += 1
        elif s[k] == ")":
            d -= 1
            if d == 0:
                return k
    return -1


def yorum_sil(s: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", s, flags=re.S)


def tanimlar(p: Path) -> list[dict]:
    """BSD biçimli fonksiyon tanımları: dönüş tipi önceki satırda, ad sütun 0'da."""
    s = yorum_sil(p.read_text(encoding="utf-8", errors="replace"))
    out = []
    for m in RE_TANIM.finditer(s):
        ac = m.end() - 1
        kap = _kapanis(s, ac)
        if kap == -1:
            continue
        sonrasi = s[kap + 1:kap + 200].lstrip()
        if not sonrasi.startswith("{"):
            continue  # bildirim ya da makro çağrısı, tanım değil
        bas = s.rfind("\n", 0, m.start() - 1)
        onceki_satir = s[bas + 1:m.start()].strip()
        if not onceki_satir or onceki_satir.endswith((";", "}", "{")) or onceki_satir.startswith("#"):
            continue
        params = " ".join(s[ac + 1:kap].split())
        statik = bool(re.search(r"\bstatic\b", onceki_satir))
        donus = re.sub(r"\b(static|inline|__inline|__dead)\b", " ", onceki_satir)
        donus = " ".join(donus.split())
        satir_no = s.count("\n", 0, m.start()) + 1
        out.append({"ad": m.group(1), "dosya": p.name, "satir": satir_no, "statik": statik,
                    "donus": donus, "parametreler": params})
    return out


def ilk_param_yapi(params: str) -> str | None:
    ilk = params.split(",")[0].strip()
    ilk = re.sub(r"\b__unused\b", " ", ilk).strip()
    m = re.match(r"^(?:const\s+)?struct\s+(\w+)\s*\*\s*\w*$", ilk)
    return m.group(1) if m else None


def nm_sembolleri() -> tuple[dict, dict]:
    r = subprocess.run(["/usr/bin/nm", "-n", "-U", str(ortak.ORIG_TMUX)],
                       capture_output=True, text=True, timeout=120)
    ad2 = collections.defaultdict(list)
    adres2 = collections.defaultdict(list)
    for satir in r.stdout.splitlines():
        parca = satir.split()
        if len(parca) != 3:
            continue
        a, t, ad = parca
        if t not in ("T", "t"):
            continue
        ad2[ad].append((a, t))
        adres2[a].append(ad)
    return ad2, adres2


def main() -> None:
    dosyalar = derlenen_dosyalar()
    tutarlilik = derleme_ile_tutarli(dosyalar)

    # Yapı seçimi sayımları (ön kayıt §2)
    gecis = collections.Counter()
    ilk_param = collections.Counter()
    ilk_param_dosya = collections.defaultdict(set)
    hepsi: list[dict] = []
    for p in dosyalar:
        metin = yorum_sil(p.read_text(encoding="utf-8", errors="replace"))
        for t in re.findall(r"struct\s+(\w+)\s*\*", metin):
            gecis[t] += 1
        for d in tanimlar(p):
            hepsi.append(d)
            y = ilk_param_yapi(d["parametreler"])
            if y:
                ilk_param[y] += 1
                ilk_param_dosya[y].add(p.name)
    secilen_yapi = gecis.most_common(1)[0][0]

    # Adaylar (ön kayıt §3 a-d)
    ad_sayisi = collections.Counter(d["ad"] for d in hepsi)
    ad2, adres2 = nm_sembolleri()
    adaylar, dislanan = [], collections.Counter()
    for d in hepsi:
        if ilk_param_yapi(d["parametreler"]) != secilen_yapi:
            continue
        if ad_sayisi[d["ad"]] != 1:
            dislanan["b_ad_tekil_degil"] += 1
            continue
        semb = ad2.get("_" + d["ad"], [])
        if len(semb) != 1:
            dislanan["c_nm_yok_ya_da_coklu"] += 1
            continue
        a = semb[0][0]
        if len(adres2[a]) != 1:
            dislanan["d_adres_paylasiliyor"] += 1
            continue
        adaylar.append({**d, "adres": "0x" + a.lstrip("0").lower(), "nm_tur": semb[0][1],
                        "prototip_metni": f"{d['donus']} {d['ad']}({d['parametreler']});"})
    adaylar.sort(key=lambda x: int(x["adres"], 16))

    cikti = {
        "kunye": {"kaynak": str(ortak.TMUX_SRC), "orig_sha256": ortak.sha256(ortak.ORIG_TMUX)},
        "dosya_sayisi": len(dosyalar),
        "derleme_tutarliligi": tutarlilik,
        "yapi_secimi": {
            "kural": "derlenen .c dosyalarında 'struct X *' geçişi en çok olan yapı",
            "secilen": secilen_yapi,
            "gecis_ilk10": gecis.most_common(10),
            "ilk_parametre_ilk10": [(k, v, len(ilk_param_dosya[k])) for k, v in ilk_param.most_common(10)],
        },
        "tanim_sayisi": len(hepsi),
        "ilk_parametresi_secilen_yapi": sum(1 for d in hepsi if ilk_param_yapi(d["parametreler"]) == secilen_yapi),
        "dislanan_a_d": dict(dislanan),
        "aday_sayisi_a_d": len(adaylar),
        "adaylar": adaylar,
    }
    ortak.json_yaz(ortak.VERI / "kaynak_adaylar.json", cikti)
    print({k: v for k, v in cikti.items() if k not in ("adaylar",)})


if __name__ == "__main__":
    main()
