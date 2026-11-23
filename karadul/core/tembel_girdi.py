"""ÖL-10 seçim girdisinin bağdaştırıcısı: K1 JSON'ları (+ isteğe bağlı görüntü) → ``SecimGirdisi``.

``karadul.core.tembel_secim`` saf kalsın diye dosya ve üst veri okuması burada. Kaynak:
``OL10_TASARIM.md`` §2.1 (girdiler) ve §7.1 adım 3.

- Fonksiyonlar: ``ghidra_functions.json`` (adres, ``size``, ``is_thunk`` / ``is_external``, ad).
- Dizgi başvurusu: ``ghidra_strings.json`` ``strings[].xrefs[].from_func_addr``.
- Çağrılanlar: ``ghidra_call_graph.json`` ``nodes[].callees``. Çağıran listelerine ve
  listelerin sırasına hiç bakılmaz (§2.1).
- Üst veri (görüntü verilirse): Go ``go_pclntab.oku`` → ``GoFonksiyon.sinif``; ObjC ``objc.oku``
  → ``yontemler[].imp``; giriş adresi ``Goruntu.giris_adresi``. İkili adresi Ghidra adresine
  ``delta`` ile çevrilir (Ghidra görüntü tabanı − ikilinin bağlama tabanı; hesap
  ``load_ghidra_index``'te, ``taban_farki`` onu çağırır).
"""
from __future__ import annotations

import bisect
from pathlib import Path
from typing import Any, Mapping

from karadul.core.tembel_secim import OBJC_SINIFI, SECIM_BILINMIYOR, SecimGirdisi, go_sinifi

# Ghidra'nın giriş noktası fonksiyonuna verdiği ad (soyulmuş ikilide).
GHIDRA_GIRIS_ADI = "entry"
# Go programının ana fonksiyonu (üst veride).
GO_ANA_FONKSIYON = "main.main"


def adres_int(adres: str) -> int:
    """Ghidra adres dizgisi (``00101ae8``, ``100081fb0``, ``ram:0010``) → tam sayı ofset."""
    return int(str(adres).rpartition(":")[2], 16)


def _fonksiyonlar(functions_doc: Mapping[str, Any]) -> list[dict]:
    fs = functions_doc.get("functions", []) if isinstance(functions_doc, Mapping) else functions_doc
    return [f for f in fs or [] if isinstance(f, Mapping) and f.get("address") is not None]


def taban_farki(functions_json: Path | str, ikili: Path | str | None) -> int:
    """Ghidra adresi − ikili adresi. ``load_ghidra_index`` ile aynı hesap (kopya değil).

    ``karadul.pipeline`` yalnız bu işlev çağrılınca yüklenir. Taban okunamazsa 0.
    """
    from karadul.pipeline.steps._feedback_naming_candidates import load_ghidra_index
    from karadul.pipeline.steps.byte_pattern import BytePatternStep

    fj = Path(functions_json)
    taban = BytePatternStep._ghidra_load_base(pc=None, functions_json=fj)
    dizin = load_ghidra_index(fj, binary_path=Path(ikili) if ikili else None,
                              ghidra_image_base=taban)
    return int(dizin.delta) if dizin is not None else 0


def _iceren(baslar: list[int], boyut: Mapping[int, int], adres: int) -> int | None:
    """``adres``'i içeren fonksiyon: başlangıcı ≤ adres olan en yakın fonksiyon, gövdesi içindeyse."""
    i = bisect.bisect_right(baslar, adres) - 1
    if i < 0:
        return None
    a = baslar[i]
    if adres == a or adres < a + max(int(boyut.get(a, 0)), 1):
        return a
    return None


def girdiden_kur(
    functions_doc: Mapping[str, Any],
    strings_doc: Mapping[str, Any] | None,
    call_graph_doc: Mapping[str, Any] | None,
    goruntu: Any = None,
    *,
    delta: int = 0,
    go_sonuc: Any = None,
    objc_sonuc: Any = None,
) -> SecimGirdisi:
    """K1 belgelerinden (ayrıştırılmış JSON) seçim girdisi kur.

    ``goruntu`` verilirse Go / ObjC üst verisi ve giriş adresi ondan okunur (``go_sonuc`` /
    ``objc_sonuc`` önceden okunmuşsa yeniden okunmaz). Görüntü yoksa bütün taslak olmayan
    fonksiyonlar ``BILINMIYOR`` ve E yalnız Ghidra'nın ``entry`` adlı fonksiyonudur.
    """
    boyut: dict[int, int] = {}
    taslak: set[int] = set()
    adlar: dict[int, set[str]] = {}
    cakisma = 0
    for f in _fonksiyonlar(functions_doc):
        a = adres_int(f["address"])
        # Aynı tam sayı adrese düşen ikinci kayıt (olağan dökümde yok) sıradan bağımsız birleşir:
        # en büyük boyut, kayıtlardan biri taslaksa taslak, adların hepsi.
        if a in boyut:
            cakisma += 1
        boyut[a] = max(boyut.get(a, 0), int(f.get("size") or 0))
        adlar.setdefault(a, set()).add(str(f.get("name") or ""))
        if f.get("is_thunk") or f.get("is_external"):
            taslak.add(a)

    dizgiler: dict[int, set[int]] = {}
    for s in (strings_doc or {}).get("strings", []) or []:
        if not isinstance(s, Mapping) or s.get("address") is None:
            continue
        sa = adres_int(s["address"])
        for x in s.get("xrefs") or []:
            ff = x.get("from_func_addr") if isinstance(x, Mapping) else None
            if ff:
                dizgiler.setdefault(adres_int(ff), set()).add(sa)

    cagrilan: dict[int, set[int]] = {}
    nodes = (call_graph_doc or {}).get("nodes", {}) or {}
    for k, n in (nodes.items() if isinstance(nodes, Mapping) else []):
        if not isinstance(n, Mapping):
            continue
        a = adres_int(n.get("address") or k)
        hedef = cagrilan.setdefault(a, set())
        for c in n.get("callees") or []:
            if isinstance(c, Mapping) and c.get("address") is not None:
                hedef.add(adres_int(c["address"]))

    sinif: dict[int, str] = {}
    giris: set[int] = {a for a, ad in adlar.items() if GHIDRA_GIRIS_ADI in ad}
    giris_nedeni: dict[str, list[str]] = {}
    if giris:
        giris_nedeni["ghidra_entry"] = [f"{a:x}" for a in sorted(giris)]
    kunye: dict[str, Any] = {"delta": delta, "adres_cakismasi": cakisma,
                             "fonksiyon": len(boyut), "taslak": len(taslak)}
    ana_modul_bilinmiyor = False

    if goruntu is not None or go_sonuc is not None or objc_sonuc is not None:
        from karadul.analyzers.ustveri import go_pclntab, objc

        if go_sonuc is None and goruntu is not None:
            go_sonuc = go_pclntab.oku(goruntu)
        if objc_sonuc is None and goruntu is not None:
            objc_sonuc = objc.oku(goruntu)
        go_eslenen = 0
        go_fonksiyonlari = list(getattr(go_sonuc, "fonksiyonlar", None) or [])
        for gf in go_fonksiyonlari:
            a = int(gf.giris) + delta
            if a not in boyut or a in taslak:
                continue
            sinif[a] = go_sinifi(gf.sinif)
            go_eslenen += 1
            if gf.ad == GO_ANA_FONKSIYON:
                giris.add(a)
                giris_nedeni.setdefault("go_main_main", []).append(f"{a:x}")
        objc_eslenen = 0
        for y in getattr(objc_sonuc, "yontemler", None) or []:
            imp = getattr(y, "imp", 0)
            if not isinstance(imp, int) or isinstance(imp, bool) or not imp:
                continue
            a = imp + delta
            if a not in boyut or a in taslak:
                continue
            # Go sınıfı verilmişse (KENDI / BAGIMLILIK / STANDART) o kalır; yalnız BILINMIYOR üstüne.
            if sinif.get(a, SECIM_BILINMIYOR) == SECIM_BILINMIYOR:
                sinif[a] = OBJC_SINIFI
                objc_eslenen += 1
        if go_eslenen:
            ana = go_pclntab.ana_modul_bul(getattr(go_sonuc, "buildinfo", None))
            ana_modul_bilinmiyor = ana is None
            kunye["go_ana_modul"] = ana
        kunye.update({
            "go_durum": getattr(go_sonuc, "durum", None),
            "go_fonksiyon": len(go_fonksiyonlari),
            "go_eslenen": go_eslenen,
            "objc_durum": getattr(objc_sonuc, "durum", None),
            "objc_eslenen": objc_eslenen,
        })
        giris_adresi = getattr(goruntu, "giris_adresi", None) if goruntu is not None else None
        kunye["giris_adresi"] = f"{giris_adresi:x}" if isinstance(giris_adresi, int) else None
        if isinstance(giris_adresi, int):
            baslar = sorted(boyut)
            a = _iceren(baslar, boyut, giris_adresi + delta)
            if a is not None:
                giris.add(a)
                giris_nedeni.setdefault("giris_adresi", []).append(f"{a:x}")

    kunye["giris"] = giris_nedeni
    return SecimGirdisi(
        boyut=boyut,
        taslak=frozenset(taslak),
        dizgiler={a: frozenset(v) for a, v in dizgiler.items()},
        cagrilan={a: frozenset(v) for a, v in cagrilan.items()},
        giris=frozenset(giris),
        sinif=sinif,
        ana_modul_bilinmiyor=ana_modul_bilinmiyor,
        kunye=kunye,
    )
