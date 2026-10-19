"""G8 ek, K3 ön koşulu: `struct client` yerleşim doğrulaması (onkayit_ek.md §1 K3).

1. Ghidra CParser yerleşimi (tipler.py ile aynı yol) ↔ -g derlemenin DWARF'ı: client ve
   değerle gömdüğü bütün adlı yapılar.
2. İkilide sizeof(struct client): `xcalloc` çağrısından önce w1/x1'e yüklenen sabit.
3. K3 hedeflerinin bellek erişim ofsetleri: şişe ↔ kendi derlememiz.

Çıktı: BELGE/k3_yerlesim_dogrulama.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import tipler  # noqa: E402
import ikili_kanit  # noqa: E402


def sizeof_kaniti(fonk: dict, boyut: int) -> list[dict]:
    out = []
    for ad, komutlar in fonk.items():
        for i, (op, arg) in enumerate(komutlar):
            if op == "bl" and "<_xcalloc>" in arg:
                for op2, arg2 in komutlar[max(0, i - 4):i]:
                    m = re.match(r"(w1|x1), #(0x[0-9a-f]+)", arg2)
                    if op2 == "mov" and m and int(m.group(2), 16) == boyut:
                        out.append({"fonksiyon": ad, "komut": f"{op2} {arg2}"})
    return out


def main() -> None:
    ortak.jvm_baslat()
    dtm, _, rapor = tipler.tipleri_ayristir()
    if rapor["ayristirma"] != "başarılı":
        raise SystemExit("ayrıştırma başarısız")
    dwarf = tipler.dwarf_yapilari(ortak.VERI / "dwarf_debug_info.txt")
    cl = tipler.yapilar(dtm, "client")
    if len(cl) != 1:
        raise SystemExit(f"client sayısı {len(cl)}")
    kapanis = tipler.kapanis_kumesi(cl[0])
    kap = [tipler.karsilastir(t, dwarf) for t in kapanis]
    ozet = {"eşit": 0, "farklı": 0, "dwarf'ta yok": 0, "yalnız ileri bildirim": 0}
    for x in kap:
        ozet[x["durum"]] += 1
    from ghidra.program.model.data import BitFieldDataType  # type: ignore
    bitalan = [str(t.getPathName()) for t in kapanis
               if any(isinstance(c.getDataType(), BitFieldDataType) for c in t.getDefinedComponents())]

    secim = json.loads((ortak.VERI / "k3_secim.json").read_text())
    sise = ikili_kanit.disasm(ortak.ORIG_TMUX)
    bizim = ikili_kanit.disasm(ortak.BUILD_G / "tmux")
    hedefler = []
    for h in secim["hedefler"]:
        a, b = sise.get("_" + h["ad"]), bizim.get("_" + h["ad"])
        if a is None or b is None:
            hedefler.append({"ad": h["ad"], "durum": "bizim derlemede yok" if b is None else "şişede yok"})
            continue
        ka, kb = set(ikili_kanit.ofsetler(a)), set(ikili_kanit.ofsetler(b))
        hedefler.append({"ad": h["ad"], "komut_sise": len(a), "komut_bizim": len(b),
                         "yalniz_sise": sorted(ka - kb), "yalniz_bizim": sorted(kb - ka),
                         "jaccard": round(len(ka & kb) / len(ka | kb), 3) if (ka | kb) else 1.0})
    cikti = {
        "kunye": ortak.kunye(),
        "client": tipler.yerlesim_dok(cl[0]),
        "kapanis": {"yapi_sayisi": len(kapanis), "ozet": ozet, "bit_alanli_yapilar": bitalan, "ayrinti": kap},
        "ikili_sizeof_kaniti": sizeof_kaniti(sise, cl[0].getLength()),
        "hedef_ofset_karsilastirmasi": hedefler,
    }
    ortak.json_yaz(ortak.BELGE / "k3_yerlesim_dogrulama.json", cikti)
    print("client:", cikti["client"]["boyut"], "bayt,", len(cikti["client"]["bilesenler"]), "alan")
    print("kapanış:", len(kapanis), ozet, "bit alanlı:", bitalan)
    for x in kap:
        if x["durum"] != "eşit":
            print("  ", x["ad"], x["durum"], x.get("farklar", ""))
    print("sizeof kanıtı:", cikti["ikili_sizeof_kaniti"])
    for x in hedefler:
        print("  ", x["ad"], x.get("jaccard"), x.get("komut_sise"), x.get("komut_bizim"), x.get("durum", ""))


if __name__ == "__main__":
    main()
