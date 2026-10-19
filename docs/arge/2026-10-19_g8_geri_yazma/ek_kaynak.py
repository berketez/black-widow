"""G8 ek, K3: `struct client` için aday havuzu (ön kayıt §3 (a)-(d), onkayit_ek.md §1 K3).

kaynak.py'nin işlevleri aynen kullanılır; yalnız yapı adı `client`.
Çıktı: workspaces/2026-10-19_g8/veri/k3_kaynak_adaylar.json
"""

from __future__ import annotations

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak  # noqa: E402
import kaynak  # noqa: E402

YAPI = "client"


def main() -> None:
    dosyalar = kaynak.derlenen_dosyalar()
    hepsi = []
    for p in dosyalar:
        hepsi.extend(kaynak.tanimlar(p))
    ad_sayisi = collections.Counter(d["ad"] for d in hepsi)
    ad2, adres2 = kaynak.nm_sembolleri()
    adaylar, dislanan = [], collections.Counter()
    ilk = [d for d in hepsi if kaynak.ilk_param_yapi(d["parametreler"]) == YAPI]
    for d in ilk:
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
    cikti = {"kunye": {"kaynak": str(ortak.TMUX_SRC), "orig_sha256": ortak.sha256(ortak.ORIG_TMUX)},
             "yapi": YAPI, "dosya_sayisi": len(dosyalar), "ilk_parametresi_yapi": len(ilk),
             "dislanan_a_d": dict(dislanan), "aday_sayisi_a_d": len(adaylar), "adaylar": adaylar}
    ortak.json_yaz(ortak.VERI / "k3_kaynak_adaylar.json", cikti)
    print({k: v for k, v in cikti.items() if k != "adaylar"})


if __name__ == "__main__":
    main()
