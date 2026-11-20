"""P-ÜV1 — Go ``pclntab`` okuyucu: sentetik görüntü testleri.

Bütün veriler ``struct.pack`` ile kurulur (PLAN §0 test verisi kuralı): sahte ``pcHeader`` +
``funcnametab`` + ``cutab`` + ``filetab`` + ``pctab`` + ``ftab`` / ``_func`` + ayrı ``moduledata``
+ ``findfunctab`` + ``__go_buildinfo``. Göstericiler görüntünün düzeltme sözlüğünden çözülür
(dosyadaki ham sözcük bilerek bozuk: okuyucu ham sözcüğe güvenirse testler kırılır).
Gerçek ikiliye bağlı test yok.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import pytest

from karadul.analyzers.ustveri import go_pclntab as G
from karadul.analyzers.ustveri.goruntu import Bag, BellekGoruntu, Bolum


# ---------------------------------------------------------------------------
# Sentetik Go modülü kurucusu
# ---------------------------------------------------------------------------

GO_METIN = 0x100001000          # metin tabanı (moduledata.text)
PCLN = 0x100100000           # __gopclntab
MODUL = 0x100200000          # __go_module (moduledata)
FFTAB = 0x100210000          # findfunctab
BINFO = 0x100220000          # __go_buildinfo
BOZUK_HAM = 0x8000_0000_DEAD_BEEF  # göstericilerin dosyadaki (çözülmemiş) ham sözcüğü
ANA_MODUL = "example.com/uyg"


def _zz(v: int) -> int:
    return 2 * v if v >= 0 else -2 * v - 1


def _uv(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _pc_tablo(ciftler: list[tuple[int, int]], min_lc: int) -> bytes:
    """[(değer, bayt uzunluğu)] → pc-değer tablosu (değer -1'den başlar, 0 ile biter)."""
    out = bytearray()
    onceki = -1
    for deger, uzunluk in ciftler:
        out += _uv(_zz(deger - onceki))
        out += _uv(uzunluk // min_lc)
        onceki = deger
    out += b"\0"
    return bytes(out)


@dataclass
class F:
    ad: str | None                  # None → nameOff 0
    boy: int = 0x40
    dosya: int | None = 0           # cutab sırası; None → pcfile 0
    pcsp: list[tuple[int, int]] | None = None   # None → tam kapsayan tek çift
    func_id: int = 0
    flag: int = 0
    giris_ofseti: int | None = None  # None → ardışık


@dataclass
class Modul:
    fonksiyonlar: list[F] = field(default_factory=lambda: [
        F(None, dosya=None),
        F(f"{ANA_MODUL}/vendor/github.com/x/y.Z", dosya=1),
        F("main.main", dosya=0),
        F("github.com/dis/paket.(*T).Yontem", dosya=2),
    ])
    imza: int = G.MAGIC_120
    min_lc: int = 4
    baslik_text: int = 0             # 1.26+: 0
    dosyalar: list[str] = field(default_factory=lambda: ["main.go", "vendor/y.go"])
    cutab_ek: list[int] = field(default_factory=lambda: [G.DOSYA_YOK])  # 3. sıra: dosya yok
    ek_adlar: list[str] = field(default_factory=lambda: ["satir.ici.Fonk"])
    pclntab_bolum_adi: str = "__gopclntab"
    moduledata_var: bool = True
    md_text: int = GO_METIN
    md_maxpc_kaydir: int = 0
    findfunctab_bozuk: bool = False
    ftab_giris_bozuk: int | None = None   # _func.entryOff'u bozulacak sıra
    kesik_func: bool = False
    bl_hedefi: str = "giris"         # "giris" / "govde" / "yok"
    gosterici_boyutu: int = 8
    kod_boyu: int | None = None      # None → bütün gövdeler kod bölümünde
    md_pclntable_uz: int | None = None  # moduledata'daki pclntable uzunluğu (None → doğru değer)
    baglar: dict = field(default_factory=dict)


def kur(m: Modul | None = None) -> tuple[BellekGoruntu, dict]:
    m = m or Modul()
    fs = m.fonksiyonlar
    n = len(fs)
    # Girişler (metin tabanına göre ofset).
    girisler = []
    o = 0
    for f in fs:
        girisler.append(o if f.giris_ofseti is None else f.giris_ofseti)
        o = girisler[-1] + f.boy
    son_ofset = girisler[-1] + fs[-1].boy

    # funcnametab: ofset 0'da hiçbir fonksiyonun adı olmayan dizgi (nameOff 0 = adsız).
    fn = bytearray(b"ilk.dizgi\0")
    name_off = []
    for f in fs:
        if f.ad is None:
            name_off.append(0)
        else:
            name_off.append(len(fn))
            fn += f.ad.encode() + b"\0"
    for a in m.ek_adlar:
        fn += a.encode() + b"\0"
    # filetab
    ft = bytearray(b"\0")
    dosya_off = []
    for d in m.dosyalar:
        dosya_off.append(len(ft))
        ft += d.encode() + b"\0"
    cutab = b"".join(struct.pack("<I", x) for x in dosya_off + m.cutab_ek)
    # pctab (ofset 0 = tablo yok, ilk bayt dolgu)
    pct = bytearray(b"\0")
    pcsp_off, pcfile_off = [], []
    for f in fs:
        pcsp_off.append(len(pct))
        pct += _pc_tablo(f.pcsp if f.pcsp is not None else [(0, f.boy)], m.min_lc)
        if f.dosya is None:
            pcfile_off.append(0)
        else:
            pcfile_off.append(len(pct))
            pct += _pc_tablo([(f.dosya, f.boy)], m.min_lc)

    funcname_off = G.PCHEADER_BOYU
    cu_off = funcname_off + len(fn)
    filetab_off = cu_off + len(cutab)
    pctab_off = filetab_off + len(ft)
    pcln_off = pctab_off + len(pct)
    # pclntable: ftab + _func'lar
    ftab_boy = 8 * (n + 1)
    funcs = bytearray()
    ftab = bytearray()
    for i, f in enumerate(fs):
        funcoff = ftab_boy + len(funcs)
        ftab += struct.pack("<II", girisler[i], funcoff)
        e2 = girisler[i] + 4 if m.ftab_giris_bozuk == i else girisler[i]
        funcs += struct.pack("<IiiIIIIIIiBBBB", e2, name_off[i], 0, 0, pcsp_off[i], pcfile_off[i],
                             0, 0, 0, 10 + i, f.func_id, f.flag, 0, 0)
    ftab += struct.pack("<II", son_ofset, 0)
    pclntable = bytes(ftab + funcs)
    if m.kesik_func:
        pclntable = pclntable[:ftab_boy + 10]
    baslik = struct.pack("<IBBBBQQQQQQQQ", m.imza, 0, 0, m.min_lc, 8, n, len(m.dosyalar),
                         BOZUK_HAM if m.baslik_text else 0, funcname_off, cu_off, filetab_off,
                         pctab_off, pcln_off)
    pclntab = baslik + bytes(fn) + cutab + bytes(ft) + bytes(pct) + pclntable

    rk = {}
    if m.baslik_text:
        rk[PCLN + 24] = m.baslik_text

    # Kod bölümü: fonksiyon gövdeleri (arm64 nop) + main.main içinde bir bl.
    kod = bytearray(struct.pack("<I", 0xD503201F) * ((m.kod_boyu or son_ofset) // 4))
    if m.bl_hedefi != "yok" and n >= 3:
        kaynak = girisler[2] + 8
        hedef = girisler[1] + (0 if m.bl_hedefi == "giris" else 8)
        imm = ((hedef - kaynak) // 4) & 0x03FFFFFF
        struct.pack_into("<I", kod, kaynak, 0x94000000 | imm)

    # findfunctab: kova başına idx + 16 alt kova farkı.
    minpc = GO_METIN + girisler[0]
    maxpc = GO_METIN + son_ofset + m.md_maxpc_kaydir
    gabs = [GO_METIN + g for g in girisler]
    nb = (GO_METIN + son_ofset - minpc + G.FUNC_TAB_KOVA - 1) // G.FUNC_TAB_KOVA
    fft = bytearray()
    for b in range(nb):
        def ind(pc: int) -> int:
            return max(i for i, g in enumerate(gabs) if g <= pc)
        idx = ind(minpc + b * G.FUNC_TAB_KOVA)
        alt = [ind(min(minpc + b * G.FUNC_TAB_KOVA + s * 256, gabs[-1])) - idx for s in range(16)]
        if m.findfunctab_bozuk:
            idx += 2
        fft += struct.pack("<I16B", idx, *alt)

    # moduledata: göstericiler düzeltme sözlüğünde, dosyada bozuk ham sözcük.
    md = bytearray(8 * 48)
    uz = {
        2: len(fn), 3: len(fn), 5: len(cutab) // 4, 6: len(cutab) // 4, 8: len(ft), 9: len(ft),
        11: len(pct), 12: len(pct), 14: len(pclntable), 15: len(pclntable), 17: n + 1, 18: n + 1,
    }
    if m.md_pclntable_uz is not None:
        uz[14] = m.md_pclntable_uz
    gos = {
        0: PCLN, 1: PCLN + funcname_off, 4: PCLN + cu_off, 7: PCLN + filetab_off,
        10: PCLN + pctab_off, 13: PCLN + pcln_off, 16: PCLN + pcln_off, 19: FFTAB,
        20: minpc, 21: maxpc, 22: m.md_text, 23: GO_METIN + son_ofset + 0x100,
    }
    for i, v in uz.items():
        struct.pack_into("<Q", md, 8 * i, v)
    md_adres = MODUL + 0x40   # bölümün ortasında, önünde başka veri var
    for i, v in gos.items():
        if v:  # çözülmemiş ham sözcük bozuk; değer yalnız düzeltme sözlüğünde
            struct.pack_into("<Q", md, 8 * i, BOZUK_HAM)
            rk[md_adres + 8 * i] = v
    modul_bolumu = b"\x11" * 0x40 + bytes(md) + b"\x22" * 0x40
    if not m.moduledata_var:
        modul_bolumu = b"\x11" * len(modul_bolumu)
        rk = {k: v for k, v in rk.items() if not (MODUL <= k < MODUL + 0x1000)}

    bolumler = [
        ("__text", GO_METIN, bytes(kod) + (b"" if m.kod_boyu else b"\0" * 0x100), True),
        (m.pclntab_bolum_adi, PCLN, pclntab, False),
        ("__go_module", MODUL, modul_bolumu, False),
        ("__noptrdata", FFTAB, bytes(fft), False),
        ("__go_buildinfo", BINFO, buildinfo_baytlari(), False),
    ]
    baglar = {md_adres + 8 * k: v for k, v in m.baglar.items()}
    g = BellekGoruntu(bolumler, mimari="arm64", gosterici_boyutu=m.gosterici_boyutu,
                      yeniden_konumlamalar=rk, baglar=baglar,
                      fonksiyon_baslangiclari=gabs)
    bilgi = {"girisler": gabs, "son": GO_METIN + son_ofset, "pcln_off": pcln_off,
             "pctab_off": pctab_off, "pcsp_off": pcsp_off, "md_adres": md_adres}
    return g, bilgi


def buildinfo_baytlari(surum: str = "go1.27.4") -> bytes:
    mod = (f"path\t{ANA_MODUL}/cmd/uyg\nmod\t{ANA_MODUL}\tv1.2.3\th1:abc=\n"
           f"dep\tgithub.com/x/y\tv0.1.0\th1:x=\ndep\tgithub.com/dis/paket\tv2.0.0\th1:y=\n"
           f"build\t-trimpath=true\nbuild\tGOARCH=arm64\n").encode()
    mod = b"\x30" * 16 + mod + b"\x31" * 16
    b = bytearray(G.BUILDINFO_IMZA + bytes([8, 2]) + b"\0" * 16)
    b += _uv(len(surum)) + surum.encode() + _uv(len(mod)) + mod
    return bytes(b)


# ---------------------------------------------------------------------------
# Okuma
# ---------------------------------------------------------------------------


def test_go120_okunur_metin_tabani_moduledata() -> None:
    g, b = kur()
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI, s.neden
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]
    assert [f.bitis for f in s.fonksiyonlar] == b["girisler"][1:] + [b["son"]]
    assert [f.ad for f in s.fonksiyonlar] == [
        "", f"{ANA_MODUL}/vendor/github.com/x/y.Z", "main.main", "github.com/dis/paket.(*T).Yontem"]
    assert s.pclntab["metin_tabani_kaynagi"] == "moduledata.text"
    assert s.pclntab["basliktaki_textStart"] == "0x0"
    assert s.pclntab["bulma"] == "bölüm adı (__gopclntab)"
    assert s.pclntab["moduledata"] == hex(b["md_adres"])


def test_dosya_yolu_cutab_ve_yok() -> None:
    g, _ = kur()
    s = G.oku(g)
    assert [f.dosya for f in s.fonksiyonlar] == [None, "vendor/y.go", "main.go", None]
    assert s.sayim["dosya_yolu_olan"] == 2


def test_nameoff_sifir_adsiz() -> None:
    g, _ = kur()
    s = G.oku(g)
    f0 = s.fonksiyonlar[0]
    assert f0.name_off == 0 and f0.ad == "" and f0.sinif == G.SINIF_ADSIZ
    assert s.sayim["adli"] == 3


def test_go118_baslik_textstart_dolu_ayni() -> None:
    g, b = kur(Modul(imza=G.MAGIC_118, baslik_text=GO_METIN))
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI, s.neden
    assert s.pclntab["imza_adi"] == "go1.18"
    assert s.pclntab["basliktaki_textStart"] == hex(GO_METIN)
    assert s.pclntab["notlar"] == []
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]


def test_baslik_textstart_farkli_ise_moduledata_kazanir() -> None:
    g, b = kur(Modul(imza=G.MAGIC_118, baslik_text=GO_METIN + 0x1000))
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI, s.neden
    assert s.pclntab["metin_tabani_kaynagi"] == "moduledata.text"
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]
    assert any("textStart" in n for n in s.pclntab["notlar"])


def test_moduledata_text_yoksa_baslik_kullanilir() -> None:
    g, b = kur(Modul(imza=G.MAGIC_118, baslik_text=GO_METIN, md_text=0))
    s = G.oku(g)
    assert s.pclntab["metin_tabani_kaynagi"] == "pcHeader.textStart"
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]


def test_imza_taramasi_bolum_adi_yokken() -> None:
    g, b = kur(Modul(pclntab_bolum_adi="__rodata"))
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI, s.neden
    assert s.pclntab["bulma"] == "imza taraması"
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]


def test_buildinfo_ve_paket_sinifi() -> None:
    g, _ = kur()
    s = G.oku(g)
    assert s.buildinfo["surum"] == "go1.27.4"
    assert s.buildinfo["mod"] == ANA_MODUL and s.buildinfo["mod_surum"] == "v1.2.3"
    assert s.buildinfo["path"] == f"{ANA_MODUL}/cmd/uyg"
    assert s.buildinfo["dep"] == 2
    assert s.buildinfo["build"] == {"-trimpath": "true", "GOARCH": "arm64"}
    assert [f.sinif for f in s.fonksiyonlar] == [
        G.SINIF_ADSIZ, G.SINIF_UCUNCU_TARAF, G.SINIF_KENDI, G.SINIF_UCUNCU_TARAF]
    assert [f.paket for f in s.fonksiyonlar] == [
        "", f"{ANA_MODUL}/vendor/github.com/x/y", "main", "github.com/dis/paket"]


def test_paket_sinifi_kurallari() -> None:
    a = ANA_MODUL
    assert G.paket_sinifi(f"{a}/vendor/golang.org/x/net", a) == G.SINIF_UCUNCU_TARAF
    assert G.paket_sinifi(f"{a}/ic/paket", a) == G.SINIF_KENDI
    assert G.paket_sinifi(a, a) == G.SINIF_KENDI
    assert G.paket_sinifi("main", None) == G.SINIF_KENDI
    assert G.paket_sinifi("runtime", a) == G.SINIF_CALISMA_ZAMANI
    assert G.paket_sinifi("internal/runtime/atomic", a) == G.SINIF_CALISMA_ZAMANI
    assert G.paket_sinifi("vendor/golang.org/x/crypto", a) == G.SINIF_STANDART
    assert G.paket_sinifi("net/http", a) == G.SINIF_STANDART
    assert G.paket_sinifi("github.com/x/y", a) == G.SINIF_UCUNCU_TARAF
    assert G.paket_sinifi("type:.eq", a) == G.SINIF_DERLEYICI
    assert G.paket_sinifi("go:buildid", a) == G.SINIF_DERLEYICI
    assert G.paket_sinifi("", a) == G.SINIF_PAKETSIZ


def test_paket_adi() -> None:
    assert G.paket_adi("github.com/a/b.(*T).F") == "github.com/a/b"
    # bağlayıcı son yol öğesindeki noktayı %2e yazar (gopkg.in/yaml.v3 → yaml%2ev3)
    assert G.paket_adi("gopkg.in/yaml%2ev3.Unmarshal") == "gopkg.in/yaml%2ev3"
    assert G.paket_adi("main.f[go.shape.int]") == "main"
    assert G.paket_adi("x/y.F[a/b.T]") == "x/y"
    assert G.paket_adi("adsiz") == ""
    assert G.ana_modul_bul({"mod": None, "path": "github.com/o/r/cmd/x"}) == "github.com/o/r"


def test_pc_tablosu_zikzak_ve_minlc() -> None:
    sp = [(0, 8), (16, 0x30), (0, 8)]
    g, b = kur(Modul(fonksiyonlar=[F("a.A", pcsp=sp), F("a.B")]))
    p = G.GoPclntab(g)
    tb = p.pc_tablosu(b["pcsp_off"][0], GO_METIN)
    assert tb == [(0, GO_METIN, GO_METIN + 8), (16, GO_METIN + 8, GO_METIN + 0x38), (0, GO_METIN + 0x38, GO_METIN + 0x40)]
    assert p.pc_tablosu(0, GO_METIN) == []


def test_satir_ici_ad_sayaci() -> None:
    g, _ = kur(Modul(ek_adlar=["s.A", "s.B", "s.C"]))
    s = G.oku(g)
    # ofset 0'daki dizgi (nameOff 0 = ad yok) + 3 ek ad hiçbir girişe bağlı değil
    assert s.butunluk["satir_ici_ad"] == {"funcnametab_dizgi": 7, "yalniz_satir_ici": 4}


# ---------------------------------------------------------------------------
# Yapı denetimleri ve karar
# ---------------------------------------------------------------------------


def test_temiz_modulde_ihlal_yok() -> None:
    g, _ = kur()
    d = G.oku(g).butunluk
    for k in ("K0_giris_uyumu", "K1_artan", "K2_kod_icinde", "K3_hiza", "K4_pcsp_kapsama",
              "K5_findfunctab", "K6_fonksiyon_baslangici", "K7_bl_hedefi", "K9_minpc_maxpc"):
        assert d[k]["ihlal"] == 0, (k, d[k])
    assert d["K4_pcsp_kapsama"]["tam"] == 4
    assert d["K4_pcsp_kapsama"]["hiza"] == 0x40
    assert d["K5_findfunctab"]["bakilan"] == 1
    assert d["K7_bl_hedefi"]["hedef_giris"] == 1


def test_k1_esit_giris_tutarsiz_ad_listesi_yok() -> None:
    fs = [F("a.A"), F("a.B", giris_ofseti=0x40), F("a.C", giris_ofseti=0x40), F("a.D")]
    g, _ = kur(Modul(fonksiyonlar=fs, bl_hedefi="yok"))
    s = G.oku(g)
    assert s.durum == G.DURUM_TUTARSIZ
    assert s.butunluk["K1_artan"]["ihlal"] == 1
    assert "K1_artan" in s.neden
    assert s.fonksiyonlar == []
    assert s.sayim["fonksiyon_girisi"] == 4   # kanıt satırı kalır


def test_k2_kod_disi_giris_tutarsiz() -> None:
    fs = [F("a.A"), F("a.B"), F("a.C"), F("a.D", giris_ofseti=0x10000)]
    g, _ = kur(Modul(fonksiyonlar=fs, bl_hedefi="yok", kod_boyu=0x100))
    s = G.oku(g)
    assert s.durum == G.DURUM_TUTARSIZ
    assert s.butunluk["K2_kod_icinde"]["bolum_disi"] == 1
    assert s.fonksiyonlar == []


def test_k4_kisa_pcsp_esik_ustu_tutarsiz() -> None:
    fs = [F("a.A"), F("a.B", boy=0x80, pcsp=[(0, 0x10)]), F("main.main"), F("a.D")]
    g, _ = kur(Modul(fonksiyonlar=fs))
    s = G.oku(g)
    k4 = s.butunluk["K4_pcsp_kapsama"]
    assert k4["kisa"] == 1 and k4["ihlal"] == 1 and k4["tam"] == 3
    assert s.durum == G.DURUM_TUTARSIZ and "K4" in s.neden
    assert s.fonksiyonlar == []


def test_k4_asm_bayrakli_kisa_ihlal_degil() -> None:
    fs = [F("a.A"), F("a.B", boy=0x80, pcsp=[(0, 0x10)], flag=G.FUNC_FLAG_ASM), F("main.main"),
          F("a.D")]
    g, _ = kur(Modul(fonksiyonlar=fs))
    s = G.oku(g)
    assert s.butunluk["K4_pcsp_kapsama"]["kisa_asm"] == 1
    assert s.butunluk["K4_pcsp_kapsama"]["ihlal"] == 0
    assert s.durum == G.DURUM_CALISTI


def test_k4_esik_yuzde_bir() -> None:
    assert G.tutarsizlik_nedeni({"K4_pcsp_kapsama": {"ihlal": 1}}, 100) is None
    assert G.tutarsizlik_nedeni({"K4_pcsp_kapsama": {"ihlal": 2}}, 100) is not None


def test_k5_bozuk_findfunctab_tutarsiz() -> None:
    g, _ = kur(Modul(findfunctab_bozuk=True))
    s = G.oku(g)
    assert s.butunluk["K5_findfunctab"]["ihlal"] > 0
    assert s.durum == G.DURUM_TUTARSIZ and s.fonksiyonlar == []


def test_k9_maxpc_uyumsuz_tutarsiz() -> None:
    g, _ = kur(Modul(md_maxpc_kaydir=0x40))
    s = G.oku(g)
    assert s.butunluk["K9_minpc_maxpc"]["ihlal"] == 1
    assert s.durum == G.DURUM_TUTARSIZ


def test_k0_ftab_func_giris_uyusmazligi_tutarsiz() -> None:
    g, _ = kur(Modul(ftab_giris_bozuk=2))
    s = G.oku(g)
    assert s.butunluk["K0_giris_uyumu"]["ihlal"] == 1
    assert s.durum == G.DURUM_TUTARSIZ


def test_k7_govde_ici_bl_sayilir_karar_degil() -> None:
    g, _ = kur(Modul(bl_hedefi="govde"))
    s = G.oku(g)
    assert s.butunluk["K7_bl_hedefi"]["hedef_baska_govde_ici"] == 1
    assert s.durum == G.DURUM_CALISTI


def test_komsu_func_takasi_k4_ihlal_verir() -> None:
    """H5'in sentetik eşi: komşu iki fonksiyonun pcsp tabloları takas edilirse K4 ihlali > 0."""
    fs = [F("a.A", boy=0x40), F("a.B", boy=0x80), F("a.C", boy=0x40), F("a.D", boy=0x40)]
    g, b = kur(Modul(fonksiyonlar=fs, bl_hedefi="yok"))
    p = G.GoPclntab(g)
    liste = p.fonksiyonlar()
    liste[0].pcsp, liste[1].pcsp = liste[1].pcsp, liste[0].pcsp
    k4 = G.butunluk_denetle(p, liste)["K4_pcsp_kapsama"]
    assert k4["ihlal"] == 2


# ---------------------------------------------------------------------------
# Durumlar ve sağlamlık
# ---------------------------------------------------------------------------


def test_go_degil_veri_yok() -> None:
    g = BellekGoruntu([("__text", GO_METIN, b"\x1f\x20\x03\xd5" * 64, True),
                       ("__data", 0x100200000, b"\0" * 256 + struct.pack("<I", G.MAGIC_120) + b"\0" * 64,
                        False)])
    s = G.oku(g)
    assert s.durum == G.DURUM_VERI_YOK
    assert s.fonksiyonlar == []


def test_eski_imza_desteklenmiyor() -> None:
    g, _ = kur(Modul(imza=0xFFFFFFFA))
    s = G.oku(g)
    assert s.durum == G.DURUM_DESTEKLENMIYOR
    assert "go1.16" in s.neden


def test_moduledata_yoksa_desteklenmiyor() -> None:
    g, _ = kur(Modul(moduledata_var=False))
    s = G.oku(g)
    assert s.durum == G.DURUM_DESTEKLENMIYOR
    assert "moduledata" in s.neden


def test_moduledata_bag_ise_desteklenmiyor() -> None:
    g, _ = kur(Modul(baglar={0: Bag("_x")}))
    s = G.oku(g)
    assert s.durum == G.DURUM_DESTEKLENMIYOR


def test_32_bit_desteklenmiyor() -> None:
    g, _ = kur(Modul(gosterici_boyutu=4))
    s = G.oku(g)
    assert s.durum == G.DURUM_DESTEKLENMIYOR


def test_kesik_func_istisna_atmaz() -> None:
    g, _ = kur(Modul(kesik_func=True))
    s = G.oku(g)
    assert s.durum == G.DURUM_TUTARSIZ
    assert s.fonksiyonlar == []


@pytest.mark.parametrize("kes", [0, 40, 72, 200, 400])
def test_kesik_pclntab_istisna_atmaz(kes: int) -> None:
    g, _ = kur()
    bol = [(b.ad, b.adres, g.oku(b.adres, b.boyut), b.kod) for b in g.bolumler]
    bol = [(a, ad, v[:kes] if a == "__gopclntab" else v, k) for a, ad, v, k in bol]
    s = G.oku(BellekGoruntu(bol, yeniden_konumlamalar=g._rk))
    assert s.durum in G.DURUMLAR
    assert s.durum != G.DURUM_CALISTI


def test_beklenmedik_hata_hata_durumu() -> None:
    class Bozuk:
        gosterici_boyutu = 8

        @property
        def bolumler(self):
            raise RuntimeError("bozuk")

    s = G.oku(Bozuk())
    assert s.durum == G.DURUM_HATA and "RuntimeError" in s.neden


def test_moduledata_pclntable_uzunlugu_bozuksa_bolum_boyu() -> None:
    g, b = kur(Modul(md_pclntable_uz=1 << 40))
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI, s.neden
    assert [f.giris for f in s.fonksiyonlar] == b["girisler"]


def test_yuklenmeyen_bolum_atlanir() -> None:
    """``bellekte`` yanlış bölüm (ELF ``SHF_ALLOC`` yok) adres içermez: pclntab orada aranmaz."""
    g, _ = kur()

    class Yuklenmeyen(type(g)):
        @property
        def bolumler(self):
            return [Bolum(b.ad, b.adres, b.boyut, b.kod, b.bolut, b.dosya_ofseti,
                          bellekte=b.ad != "__gopclntab") for b in super().bolumler]

    g.__class__ = Yuklenmeyen
    s = G.oku(g)
    assert s.durum == G.DURUM_VERI_YOK


def test_kayit_bicimi() -> None:
    g, _ = kur()
    k = G.oku(g).fonksiyonlar[2].kayit()
    assert k["giris"] == hex(GO_METIN + 0x80) and k["ad"] == "main.main" and k["dosya"] == "main.go"
    assert k["sinif"] == G.SINIF_KENDI and k["baslangic_satiri"] == 12
