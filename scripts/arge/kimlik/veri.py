#!/usr/bin/env python
"""KİMLİK hattı (ARGE 2026-11-19) — veri yükleyici. Araştırma betiği; ürün kodu değil.

Var olan ürün koşularının Ghidra çıktısından (``static/``) fonksiyon başına olgu çıkarır ve GT'yi
``scripts/measurement/ks1_olc.py`` yardımcılarıyla (``gt_elf``, ``gt_mac``) Ghidra adres uzayında bağlar.
Yeni Ghidra koşusu yapmaz; hiçbir yere yazmaz.

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/veri.py debian/htop mac/htop
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[3]
_OLCUM_BETIK = REPO / "scripts" / "measurement"
if str(_OLCUM_BETIK) not in sys.path:
    sys.path.insert(0, str(_OLCUM_BETIK))

import ks1_olc as ks1  # noqa: E402

OLCUM = Path.home() / "karadul_olcum"
TABAN = OLCUM / "runs" / "urun-onarim-a62f15e"
ONARIM18 = OLCUM / "runs" / "onarim-2026-11-18"
DEBIAN_INDIR = OLCUM / "downloads" / "debian13"
MAC_VERI = REPO / "workspaces" / "olcum_mac"
KORPUS = OLCUM / "corpus"
KORPUS_KOSU = OLCUM / "runs" / "aday-f893d72"
CIKTI = OLCUM / "runs" / "arge-2026-11-19" / "kimlik"

# P-code varnode uzay kodları (``pcode.jsonl``): 0 geçici, 1 yazmaç, 2 sabit, 3 bellek adresi
UZAY_SABIT = 2


@dataclass
class Fonk:
    adres: int
    ghidra_adi: str
    bilinen: bool                      # Ghidra'nın soyulmuş ikilide verdiği jenerik olmayan ad
    boyut: int
    dizgiler: set[str] = field(default_factory=set)
    iceaktarim: set[str] = field(default_factory=set)     # çağrılan içe aktarımların HAM adları
    cagrilan: set[int] = field(default_factory=set)       # iç (thunk olmayan) fonksiyon adresleri
    cagiran: set[int] = field(default_factory=set)
    sabitler: set[int] = field(default_factory=set)
    blok: int = 0
    kenar: int = 0
    komutlar: tuple[tuple[str, int], ...] = ()            # (komut adı, adet), sıralı
    cfg_kenarlari: tuple[tuple[int, int], ...] = ()       # blok sıra numaralarıyla kenarlar
    gt: tuple[str, ...] = ()                              # normalleştirilmiş GT adları (boşsa GT yok)
    nufusta: bool = False


@dataclass
class Ikili:
    kimlik: str
    platform: str
    static: Path
    fonk: dict[int, Fonk]
    kunye: dict[str, Any]
    # tablo yuvası komşuları (``yuva_komsulari`` doldurur): fonksiyon → [(yuva farkı, tür, hedef)];
    # tür "d" (hedef = dizgi değeri) ya da "f" (hedef = fonksiyon adresi)
    yuva_komsu: Optional[dict[int, list[tuple[int, str, Any]]]] = None

    @property
    def nufus(self) -> list[int]:
        return sorted(a for a, f in self.fonk.items() if f.nufusta)


def norm_gt(adlar: list[str], platform: str) -> tuple[str, ...]:
    """GT adlarını ölçünün tam eşitlik tanımına indir: Mach-O ``_`` soyulur, derleyici klonu tabana iner.

    Makine dışlayıcısı parçası (``OUTLINED_FUNCTION_N``; taban boş) ad sayılmaz.
    """
    out = []
    for a in adlar:
        a = ks1.platform_adi(a, platform)
        t = ks1.klon_tabani(a)
        if t == "":
            continue
        out.append(t if t is not None else a)
    return tuple(sorted(set(out)))


def _json(yol: Path) -> Any:
    with open(yol, encoding="utf-8") as f:
        return json.load(f)


def _spec(kimlik: str) -> dict[str, Any]:
    """Kimlik → (platform, program, ad, koşu kökü, GT kaynağı)."""
    p = kimlik.split("/")
    if p[0] == "debian" and len(p) == 2:
        return dict(platform="debian", program=p[1], ad=p[1], kok=TABAN / "debian" / p[1] / p[1])
    if p[0] == "debian" and len(p) == 3:
        return dict(platform="debian", program=p[1], ad=p[2], kok=TABAN / "debian" / p[1] / p[2])
    if p[0] == "mac":
        return dict(platform="mac", program=p[1], ad=p[1], kok=TABAN / "mac" / p[1], mac_veri=MAC_VERI)
    if p[0] == "macgnu":
        if p[1] == "gcat":
            return dict(platform="mac", program="gcat", ad="gcat", kok=ONARIM18 / "P-S3" / "A" / "macgnu" / "gcat",
                        mac_veri=ONARIM18 / "P-S3" / "mac_gnulib")
        return dict(platform="mac", program=p[1], ad=p[1], kok=ONARIM18 / "P-S3b" / "A" / "macgnu" / p[1],
                    mac_veri=ONARIM18 / "P-S3b" / "mac_kabul")
    if p[0] == "macgcc":
        # aynı sürümün Homebrew GCC 16 derlemesi (DEFTER.md §5.9; ``derle_gcc.sh``, ``kos_gcc.sh``)
        return dict(platform="mac", program=p[1], ad=p[1], kok=CIKTI / "gcc" / "kosu" / p[1],
                    mac_veri=CIKTI / "gcc")
    if p[0] == "macgnu2":
        # Homebrew coreutils ikililerinin a62f15e ağacıyla yeniden koşusu (aynı kuşak; DEFTER.md §5.10)
        eski = _spec("macgnu/" + p[1])
        return dict(eski, kok=CIKTI / "ek" / "macgnu2" / p[1])
    if p[0] == "macsym":
        # Mac ikilisinin SEMBOLLÜ analizi (başvuru olarak; DEFTER.md §5.10). GT adresleri soyulmuş kopyayla aynı.
        return dict(platform="mac", program=p[1], ad=p[1], kok=CIKTI / "ek" / "macsym" / p[1],
                    mac_veri=MAC_VERI, sembollu=True)
    if p[0] == "korpus":
        return dict(platform="debian", program=p[1], ad=p[2], kok=KORPUS_KOSU / p[1] / p[2], korpus=p[1])
    raise ValueError(f"bilinmeyen kimlik: {kimlik}")


def _gt_korpus(e: ks1.Elf, korpus: str) -> ks1.GtBirimi:
    """``corpus/<korpus>/gt/<ad>.gt.json`` (``function_f1.extract_gt`` çıktısı) → Ghidra adres uzayı.

    ``ks1.gt_elf``'in aynısı; tek fark GT'nin hazır JSON'dan okunması (dbgsym paketi yerine).
    """
    f1 = ks1._f1()
    gt = _json(KORPUS / korpus / "gt" / f"{e.ad}.gt.json")
    soyulmus = KORPUS / korpus / "bin" / e.ad
    if f1.sha256_file(soyulmus) != gt["stripped_sha256"]:
        raise ks1.OnkosulHatasi(f"{e.ad}: korpus ikilisinin sha256'sı GT ile uyuşmuyor")
    gfonk = f1.load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
    giris = int(gt["entry"], 16)
    entry_ofseti, entry_kaynagi = f1.derive_image_offset(gfonk, giris, gt["elf_type"])
    ofset, kaynak = ks1.elf_ofseti(e.ad, Path(e.static), soyulmus, gfonk, giris, entry_ofseti, entry_kaynagi)
    turler = f1.classify_detected(gfonk, gt["exec_sections"], ofset)
    adsiz = {g["addr"] - ofset for g in gfonk if not g["is_thunk"]
             and turler.get(g["addr"] - ofset) == "code"
             and f1.is_generic_name(g["name"], [g["addr"] - ofset, g["addr"]])}
    adlar: dict[int, list[str]] = {}
    nufus: set[int] = set()
    export_gt: set[int] = set()
    for fn in gt["functions"]:
        dosya = int(fn["addr"], 16)
        adlar[dosya + ofset] = list(fn["names"])
        if fn.get("exported"):
            export_gt.add(dosya + ofset)
        elif not fn["crt"] and dosya in adsiz and not ks1.gt_klon_mu(fn["names"], ks1.PLATFORM_DEBIAN):
            nufus.add(dosya + ofset)
    return ks1.GtBirimi(adlar, nufus, export_gt, {"gt": "korpus", "ofset": f"0x{ofset:x}", "ofset_kaynagi": kaynak,
                                                  "gt_fonksiyon": len(gt["functions"])})


def _gt_mac_sembollu(e: ks1.Elf, mac_veri: Path) -> ks1.GtBirimi:
    """Sembollü (soyulmamış) Mach-O koşusu için GT: adresler soyulmuş kopyanın GT'siyle aynıdır (strip
    ``__TEXT``'i taşımaz). Koşulan dosya GT'nin ÖZGÜN ikilisi olmalı (sha256 denetlenir). Nüfus boş: bu
    ikili yalnız başvuru olarak kullanılır (Ghidra adları zaten biliyor)."""
    import macho_measure as mm
    belge = _json(mm.gt_path(Path(mac_veri), e.program))
    hedef = _json(e.kosu / "raw" / "target_info.json")
    if hedef.get("file_hash") != belge.get("orig_sha256"):
        raise ks1.OnkosulHatasi(f"{e.program}: analiz edilen dosya GT'nin özgün (sembollü) ikilisi değil")
    adlar = ks1._mf().gt_from_json(belge)
    return ks1.GtBirimi(adlar, set(), set(), {"gt": "sembollu", "gt_fonksiyon": len(adlar)})


def yukle(kimlik: str, pcode: bool = True) -> Ikili:
    s = _spec(kimlik)
    static = ks1._tek_static(s["kok"])
    e = ks1.Elf(s["platform"], s["program"], s["ad"], static, static.parent)
    if "korpus" in s:
        gt = _gt_korpus(e, s["korpus"])
    elif s.get("sembollu"):
        gt = _gt_mac_sembollu(e, s["mac_veri"])
    elif s["platform"] == ks1.PLATFORM_MAC:
        gt = ks1.gt_mac(e, s["mac_veri"])
    else:
        gt = ks1.gt_elf(e, DEBIAN_INDIR)
    f1 = ks1._f1()

    ham = _json(static / "ghidra_functions.json")["functions"]
    thunk: dict[int, str] = {}
    fonk: dict[int, Fonk] = {}
    for g in ham:
        a = int(g["address"], 16)
        if g["is_thunk"]:
            thunk[a] = g["name"]
            continue
        fonk[a] = Fonk(a, g["name"], not f1.is_generic_name(g["name"], [a]), int(g.get("size") or 0))

    cg = _json(static / "ghidra_call_graph.json")
    kenarlar: dict[int, set[int]] = {}
    for k in cg["edges"]:
        kenarlar.setdefault(int(k["from"], 16), set()).add(int(k["to"], 16))

    def coz(a: int, derinlik: int = 0) -> tuple[Optional[int], Optional[str]]:
        """Çağrı hedefi → (iç fonksiyon adresi, içe aktarım adı). Thunk zinciri izlenir."""
        if a in fonk:
            return a, None
        if a in thunk:
            ad = thunk[a]
            hedefler = kenarlar.get(a, set())
            if hedefler and derinlik < 4:
                # iç fonksiyona atlayan thunk (``thunk_FUN_…``) ya da PLT → dış thunk zinciri
                ic = [coz(h, derinlik + 1) for h in sorted(hedefler)]
                icler = [x for x in ic if x[0] is not None]
                if icler:
                    return icler[0]
                adlar_ = [x[1] for x in ic if x[1]]
                if adlar_ and f1.is_generic_name(ad, [a]):
                    return None, adlar_[0]
            if not f1.is_generic_name(ad, [a]):
                return None, ad
        return None, None

    for a, hedefler in kenarlar.items():
        if a not in fonk:
            continue
        for h in hedefler:
            ic, dis = coz(h)
            if ic is not None and ic != a:
                fonk[a].cagrilan.add(ic)
                fonk[ic].cagiran.add(a)
            elif dis:
                fonk[a].iceaktarim.add(dis)

    for d in _json(static / "ghidra_strings.json")["strings"]:
        deger = d.get("value")
        if not deger:
            continue
        for x in d.get("xrefs") or []:
            fa = x.get("from_func_addr")
            if fa:
                a = int(fa, 16)
                if a in fonk:
                    fonk[a].dizgiler.add(deger)

    # Eski koşu kuşaklarında (P13a GHIDRA-16 öncesi) dizgi → fonksiyon bağı yalnız ``ghidra_xrefs.json``'da
    # (``strings_used``); iki kaynak birleştirilir ki kuşaklar arası kıyas aynı tanımla yapılsın.
    for fa, x in _json(static / "ghidra_xrefs.json").get("function_xrefs", {}).items():
        a = int(fa, 16)
        if a in fonk:
            for d in x.get("strings_used") or []:
                if d.get("value"):
                    fonk[a].dizgiler.add(d["value"])

    for g in _json(static / "ghidra_cfg.json")["functions"]:
        a = int(g["address"], 16)
        if a not in fonk:
            continue
        f = fonk[a]
        f.blok, f.kenar = int(g["block_count"]), int(g["edge_count"])
        say: dict[str, int] = {}
        sira = {}
        for i, b in enumerate(g.get("blocks") or []):
            sira[b["start_address"]] = i
            for m in b.get("mnemonics") or []:
                say[m] = say.get(m, 0) + 1
        f.komutlar = tuple(sorted(say.items()))
        f.cfg_kenarlari = tuple(sorted((sira[k["from_block"]], sira[k["to_block"]]) for k in g.get("edges") or []
                                       if k["from_block"] in sira and k["to_block"] in sira))

    pj = static / "ghidra_output" / "pcode.jsonl"
    if pcode and pj.is_file():
        with open(pj, encoding="utf-8") as fh:
            for satir in fh:
                kay = json.loads(satir)
                a = int(kay["a"], 16)
                if a not in fonk:
                    continue
                sab = fonk[a].sabitler
                for op in kay.get("ops") or []:
                    ad, _cikis, girdiler = op[0], op[1], op[2] or []
                    if ad in ("LOAD", "STORE"):
                        girdiler = girdiler[1:]      # ilk girdi uzay kimliği
                    for v in girdiler:
                        if v and v[0] == UZAY_SABIT:
                            sab.add(int(v[1]))

    for a, adlar in gt.adlar.items():
        if a in fonk:
            fonk[a].gt = norm_gt(adlar, s["platform"])
    for a in gt.nufus:
        if a in fonk:
            fonk[a].nufusta = True
    kunye = dict(gt.kunye)
    kunye.update(static=str(static), gt_adres=len(gt.adlar), nufus=len(gt.nufus),
                 nufus_fonkta=sum(1 for a in gt.nufus if a in fonk), thunk=len(thunk), fonk=len(fonk))
    return Ikili(kimlik, s["platform"], static, fonk, kunye)


YUVA_BOYU = 8          # AArch64 / arm64 işaretçi boyu
YUVA_PENCERE_UST = 16  # komşuluk en çok bu kadar yuva (eşleyici daha dar pencere seçebilir)


def _ikili_yolu(I: Ikili) -> Path:
    yol = Path(_json(I.static.parent / "raw" / "target_info.json")["path"])
    if not yol.is_file():
        # koşu sonrası taşınmış olabilir: çalışma alanındaki kopya
        adaylar = [p for p in (I.static.parent / "raw").iterdir() if p.is_file() and p.name != "target_info.json"]
        if len(adaylar) == 1:
            return adaylar[0]
        raise FileNotFoundError(f"{I.kimlik}: analiz edilen ikili bulunamadı ({yol})")
    return yol


def isaretci_yuvalari(I: Ikili) -> list[tuple[int, int]]:
    """Veri bölümlerindeki işaretçi yuvaları: [(yuva adresi, hedef adres)], Ghidra adres uzayında, sıralı.

    ELF: ``R_AARCH64_RELATIVE`` (yuva = r_offset, hedef = addend). Mach-O: zincirli düzeltmelerin taban
    kaydırmaları (``lief`` ``RelocationFixup``: yuva = address, hedef = target). Ghidra koşusu gerekmez.
    """
    import lief
    ikili = lief.parse(str(_ikili_yolu(I)))
    ofset = int(I.kunye.get("ofset", "0x0"), 16) if I.platform != ks1.PLATFORM_MAC else 0
    out: list[tuple[int, int]] = []
    if isinstance(ikili, lief.ELF.Binary):
        for r in ikili.relocations:
            if r.type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE:
                out.append((int(r.address) + ofset, int(r.addend) + ofset))
    else:
        for r in ikili.relocations:
            hedef = getattr(r, "target", None)
            if hedef:
                out.append((int(r.address), int(hedef)))
    return sorted(set(out))


def yuva_komsulari(I: Ikili) -> dict[int, list[tuple[int, str, Any]]]:
    """Fonksiyon → aynı tabloda (± ``YUVA_PENCERE_UST`` yuva) duran dizgi ve fonksiyon komşuları.

    Yuvalar arası boşluk ``YUVA_PENCERE_UST`` yuvayı geçerse tablo kesilmiş sayılır (komşuluk kurulmaz).
    Sonuç ``I.yuva_komsu``'da saklanır.
    """
    if I.yuva_komsu is not None:
        return I.yuva_komsu
    dizgi_adres = {int(d["address"], 16): d["value"] for d in _json(I.static / "ghidra_strings.json")["strings"]
                   if d.get("value") and ":" not in d["address"]}
    yuvalar = isaretci_yuvalari(I)
    tur: list[tuple[int, str, Any]] = []
    for yuva, hedef in yuvalar:
        if hedef in I.fonk:
            tur.append((yuva, "f", hedef))
        elif hedef in dizgi_adres:
            tur.append((yuva, "d", dizgi_adres[hedef]))
    out: dict[int, list[tuple[int, str, Any]]] = {}
    ust = YUVA_PENCERE_UST * YUVA_BOYU
    for i, (yuva, t, hedef) in enumerate(tur):
        if t != "f":
            continue
        komsu = out.setdefault(hedef, [])
        for yon in (-1, 1):
            j = i + yon
            while 0 <= j < len(tur) and abs(tur[j][0] - yuva) <= ust:
                fark = (tur[j][0] - yuva) // YUVA_BOYU
                komsu.append((fark, tur[j][1], tur[j][2]))
                j += yon
    I.yuva_komsu = out
    I.kunye["yuva"] = len(yuvalar)
    I.kunye["yuva_fonk"] = sum(1 for _, t, _ in tur if t == "f")
    I.kunye["yuva_dizgi"] = sum(1 for _, t, _ in tur if t == "d")
    return out


def main(argv: list[str]) -> int:
    for k in argv:
        ik = yukle(k)
        f = ik.fonk.values()
        print(k, json.dumps({
            "fonk": len(ik.fonk), "gt_li": sum(1 for x in f if x.gt), "nufus": len(ik.nufus),
            "bilinen": sum(1 for x in f if x.bilinen), "dizgili": sum(1 for x in f if x.dizgiler),
            "iceaktarimli": sum(1 for x in f if x.iceaktarim), "sabitli": sum(1 for x in f if x.sabitler),
            "cagiransiz": sum(1 for x in f if not x.cagiran),
            "yuvali_fonk": len(yuva_komsulari(ik)),
            "nufus_cagiransiz_yuvali": sum(1 for a in ik.nufus if not ik.fonk[a].cagiran and a in ik.yuva_komsu),
            "nufus_cagiransiz": sum(1 for a in ik.nufus if not ik.fonk[a].cagiran),
            "kunye": ik.kunye}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
