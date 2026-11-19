"""OLGU tablosunun birim testleri (sentetik girdi). Koşum (depo kökünden):

    PYTHONDONTWRITEBYTECODE=1 python -m pytest scripts/arge/olgu/test_olgu_tablosu.py -q -p no:cacheprovider

Ölçüm modülleri (``urun_olc``, ``ks1_olc``, ``dwarf_tip``) bu deponun ``scripts/measurement``'ından
yüklenir; gerçek koşu verisine dokunulmaz.
"""
from __future__ import annotations

import gzip
import json
import os
import struct
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))

import olgu_ikili as oi  # noqa: E402
import olgu_tablosu as ot  # noqa: E402

# Ölçüm modüllerinin ağacı (mutasyon denetiminde test kopyası başka dizinden koşulur)
REPO = Path(os.environ.get("OLGU_TEST_REPO") or Path(__file__).resolve().parents[3])


@pytest.fixture(scope="module")
def m():
    return ot.olcum_yukle(REPO)


# --------------------------------------------------------------------------------------------
# RELATIVE yeniden konumlandırma ve veri yuvaları


def _rela(r_offset: int, tur: int, sym: int, ek: int) -> bytes:
    return struct.pack("<QQq", r_offset, (sym << 32) | tur, ek)


def test_rela_coz_ve_relative_yuva():
    veri = (_rela(0x20000, 1027, 0, 0x1500)          # RELATIVE → ekleme
            + _rela(0x20008, 257, 3, 0x10)           # ABS64, tanımlı sembol 3
            + _rela(0x20010, 1025, 7, 0)             # GLOB_DAT, tanımsız sembol → atlanır
            + _rela(0x20018, 1026, 2, 0))            # JUMP_SLOT → atlanır
    relalar = oi.rela_coz(veri)
    assert relalar[0] == (0x20000, 1027, 0, 0x1500)
    assert relalar[1] == (0x20008, 257, 3, 0x10)
    harita, sayac = oi.yuva_haritasi_rela(relalar, oi.EM_AARCH64, {3: 0x4000})
    assert harita == {0x20000: 0x1500, 0x20008: 0x4010}
    assert sayac == {"relative": 1, "sembollu": 1, "atlanan": 2}


def test_rela_x86_64_turleri_ve_bozuk_boyut():
    harita, _ = oi.yuva_haritasi_rela(oi.rela_coz(_rela(0x10, 8, 0, 0x99)), oi.EM_X86_64, {})
    assert harita == {0x10: 0x99}
    # AArch64 RELATIVE kodu x86-64'te RELATIVE değildir
    harita, sayac = oi.yuva_haritasi_rela(oi.rela_coz(_rela(0x10, 1027, 0, 0x99)), oi.EM_X86_64, {})
    assert harita == {} and sayac["atlanan"] == 1
    with pytest.raises(ValueError):
        oi.rela_coz(b"\x00" * 23)


# --------------------------------------------------------------------------------------------
# Görüntü ve C dizgisi


def _goruntu() -> oi.Goruntu:
    veri = bytearray(0x300)
    veri[0x100:0x10A] = b"bind-key\x00\x00"
    veri[0x110:0x115] = b"bind\x00"
    veri[0x120:0x124] = b"a\x01b\x00"                # basılamaz
    veri[0x130:0x140] = b"x" * 16                    # NUL yok (bölüm sonuna kadar)
    veri[0x200:0x204] = b"abc\x00"                  # kod bölümünde basılabilir baytlar
    bolumler = [oi.Bolum(".rodata", 0x1100, 0x40, 0x100, False, False),
                oi.Bolum(".text", 0x1200, 0x10, 0x200, True, False),
                oi.Bolum(".bss", 0x3000, 0x100, None, False, True)]
    return oi.Goruntu("elf", bolumler, bytes(veri))


def test_cstr_oku():
    g = _goruntu()
    assert oi.cstr_oku(g, 0x1100) == "bind-key"
    assert oi.cstr_oku(g, 0x1104) == "-key"           # dizginin ortası (kuyruk birleştirme)
    assert oi.cstr_oku(g, 0x1110) == "bind"
    assert oi.cstr_oku(g, 0x1120) is None             # denetim karakteri
    assert oi.cstr_oku(g, 0x1130) is None             # NUL yok
    assert oi.cstr_oku(g, 0x1200) is None             # yürütülebilir bölüm
    assert oi.cstr_oku(g, 0x3000) is None             # NOBITS
    assert oi.cstr_oku(g, 0x9999) is None             # bölüm yok
    assert oi.cstr_oku(g, 0x1108) is None             # boş dizgi


def test_kirp():
    assert oi.kirp("abc") == ("abc", False)
    m_, k = oi.kirp("a" * (oi.KIRPMA_SINIRI + 5))
    assert len(m_) == oi.KIRPMA_SINIRI and k


# --------------------------------------------------------------------------------------------
# Kayıt çiftleri


def test_kayit_ciftleri_komsu_ve_yalniz_tam_fonksiyon_basi():
    w = 8
    yer = 0x8000
    yuva = {yer - 2 * w: 0x1100,           # dizgi
            yer - w: 0x1110,               # dizgi
            yer: 0x5000,                   # F'nin adresi
            yer + w: 0x6000,               # başka fonksiyon (dizgi değil)
            yer + 4 * w: 0x1100,           # sınırda (±4) dizgi
            yer + 5 * w: 0x1110,           # sınır dışı
            0x9000: 0x5004}                # fonksiyon başı değil → sayılmaz
    # yuvanın kendisi (o = 0) komşu sayılmaz: hedefi dizgi gibi görünse de
    dizgiler = {0x1100: "attach-session", 0x1110: "attach", 0x5000: "kendisi"}
    out = oi.kayit_ciftleri({0x5000, 0x6000}, yuva, dizgiler.get, lambda a: ".data.rel.ro", w=w)
    assert set(out) == {0x5000, 0x6000}
    (y,) = out[0x5000]
    assert y["y"] == yer and y["b"] == ".data.rel.ro"
    assert [(d["o"], d["m"]) for d in y["d"]] == [(-2, "attach-session"), (-1, "attach"), (4, "attach-session")]
    # 0x6000'ün yeri yer+w: komşuları -3 (yer-2w), -2 (yer-w), -1 (yer: 0x5000), +3 (yer+4w), +4 (yer+5w)
    assert [d["o"] for d in out[0x6000][0]["d"]] == [-3, -2, -1, 3, 4]


def test_kayit_cifti_iki_yer():
    out = oi.kayit_ciftleri({0x5000}, {0x100: 0x5000, 0x200: 0x5000}, {}.get, lambda a: None)
    assert [y["y"] for y in out[0x5000]] == [0x100, 0x200]
    assert all(y["d"] == [] for y in out[0x5000])


def test_ham_yuvalar_yeniden_konumlanmayan():
    veri = bytearray(0x40)
    veri[0x00:0x08] = (0x1100).to_bytes(8, "little")    # .rodata'ya işaretçi
    veri[0x08:0x10] = (0x7777).to_bytes(8, "little")    # hiçbir bölüme düşmüyor
    bolumler = [oi.Bolum(".data", 0x2000, 0x10, 0x0, False, True),
                oi.Bolum(".rodata", 0x1100, 0x10, 0x20, False, False)]
    assert oi.ham_yuvalar(oi.Goruntu("elf", bolumler, bytes(veri))) == {0x2000: 0x1100}


# --------------------------------------------------------------------------------------------
# Mach-O bölümleri


def test_macho_bolumleri():
    sect = (b"__cstring".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
            + struct.pack("<QQIIIIIIII", 0x100000500, 0x20, 0x500, 0, 0, 0, 0x2, 0, 0, 0))
    seg = struct.pack("<II", 0x19, 72 + 80) + b"__TEXT".ljust(16, b"\x00") + struct.pack(
        "<QQQQiiII", 0x100000000, 0x1000, 0, 0x1000, 5, 5, 1, 0) + sect
    baslik = struct.pack("<IiiIIIII", oi.MH_MAGIC_64, 0x100000C, 0, 2, 1, len(seg), 0, 0)
    (b,) = oi.macho_bolumleri(baslik + seg)
    assert (b.ad, b.adres, b.boyut, b.dosya_ofseti, b.yurutulebilir, b.yazilabilir) == \
        ("__TEXT,__cstring", 0x100000500, 0x20, 0x500, False, False)
    with pytest.raises(ValueError):
        oi.macho_bolumleri(b"\xce\xfa\xed\xfe" + b"\x00" * 28)


# --------------------------------------------------------------------------------------------
# P-code çağrı dizgileri


def test_cagri_dizgileri():
    U = oi.UZAY_UNIQUE
    ops = [
        ["COPY", [U, 0x100, 8], [[2, 0x1100, 8]]],              # u100 = "bind-key"
        ["COPY", [U, 0x200, 8], [[2, 0x1110, 8]]],              # u200 iki kez tanımlı → çözülmez
        ["COPY", [U, 0x200, 8], [[2, 0x1100, 8]]],
        ["CALL", None, [[3, 0x5000, 8], [1, 0x4000, 8], [U, 0x100, 8], [U, 0x200, 8], [2, 0x1110, 8]]],
        ["CALL", None, [[3, 0x6000, 8], [2, 0x42, 8]]],          # dizgi olmayan sabit
        ["CALLIND", None, [[U, 0x300, 8]]],
    ]
    dizgiler = {0x1100: "bind-key", 0x1110: "bind"}
    out, callind = oi.cagri_dizgileri(ops, dizgiler.get)
    assert callind is True
    assert [(x["c"], x["i"], x["m"]) for x in out] == [(0x5000, 2, "bind-key"), (0x5000, 4, "bind")]
    assert oi.cagri_dizgileri([["RETURN", None, [[2, 0, 8]]]], dizgiler.get) == ([], False)


# --------------------------------------------------------------------------------------------
# Kaynak yolu ve sınıf


def test_kaynak_yolu():
    assert oi.kaynak_yolu("adlist.c", "./src") == "src/adlist.c"
    assert oi.kaynak_yolu("../apps/lib/opt.c", "./build_shared") == "apps/lib/opt.c"
    assert oi.kaynak_yolu("./lib//compress/x.c", "./programs") == "programs/lib/compress/x.c"
    assert oi.kaynak_yolu("/build/reproducible-path/redis-8.0.2/src/x.c", None) == "src/x.c"
    assert oi.kaynak_yolu("/usr/include/aarch64-linux-gnu/bits/error.h", None) == \
        "/usr/include/aarch64-linux-gnu/bits/error.h"
    assert oi.kaynak_yolu("../../programs/util.c", "./lib") == "programs/util.c"
    assert oi.kaynak_yolu(None, ".") is None


@pytest.mark.parametrize("yol,gnulib,beklenen", [
    ("lib/quotearg.c", ["lib"], ("gnulib", "lib")),
    ("lib/malloc/dynarray.c", ["lib"], ("gnulib", "lib/malloc")),
    ("src/ls.c", ["lib"], ("program", "src")),
    ("deps/lua/src/lapi.c", [], ("ucuncu_taraf", "deps/lua")),
    ("contrib/pzstd/Pzstd.cpp", [], ("ucuncu_taraf", "contrib/pzstd")),
    ("compat/imsg.c", [], ("uyumluluk", "compat")),
    ("lib/compress/zstd_compress.c", [], ("proje_kitapligi", "lib/compress")),
    ("programs/lib/legacy/zstd_v05.c", [], ("proje_kitapligi", "programs/lib/legacy")),
    ("apps/lib/opt.c", [], ("program", "apps/lib")),
    ("tree.c", [], ("program", ".")),
    ("/usr/include/aarch64-linux-gnu/bits/error.h", [], ("sistem", None)),
    ("csu/start.c", [], ("derleyici", None)),
    (None, [], ("bilinmiyor", None)),
])
def test_kaynak_sinifla(m, yol, gnulib, beklenen):
    assert ot.kaynak_sinifla(yol, gnulib, m.dt) == beklenen


# --------------------------------------------------------------------------------------------
# Şema ve hüküm (urun_olc'un kendi fonksiyonuyla)


def _sentetik_ikili(m):
    ks1 = m.ks1
    e = ks1.Elf("debian", "prog", "ikili", Path("/yok/static"), Path("/yok"))
    fonk_ham = [
        {"name": "FUN_00101000", "address": "00101000", "size": 100, "is_thunk": False, "is_external": False,
         "source": "DEFAULT"},
        {"name": "FUN_00101100", "address": "00101100", "size": 40, "is_thunk": False, "is_external": False,
         "source": "DEFAULT"},
        {"name": "FUN_00101200", "address": "00101200", "size": 300, "is_thunk": False, "is_external": False,
         "source": "DEFAULT"},
        {"name": "known", "address": "00101300", "size": 20, "is_thunk": False, "is_external": False,
         "source": "IMPORTED"},
        {"name": "memcpy", "address": "00100500", "size": 16, "is_thunk": True, "is_external": False,
         "source": "IMPORTED"},
        {"name": "FUN_00101400", "address": "00101400", "size": 50, "is_thunk": False, "is_external": False,
         "source": "DEFAULT"},
    ]
    gt = ks1.GtBirimi(adlar={0x101000: ["parse_args"], 0x101100: ["helper"], 0x101200: ["do_work"],
                             0x101300: ["known"], 0x101400: ["_start"]},
                      nufus={0x101000, 0x101100, 0x101200}, export_gt=set(), kunye={})
    genel = {"FUN_00101000": "parse_args",          # doğru
             "FUN_00101100": "wrong_name",          # yanlış
             "FUN_00101300": "renamed",             # Ghidra zaten adlandırmış → ölçü dışı
             "FUN_00101400": "_start"}              # doğru ama nüfus dışı (CRT)
    koken = {"FUN_00101000": {"strategy": "binary_extract", "pre_name_kind": "gnulib", "label": "doğrulanmadı",
                              "confidence": 0.9},
             "FUN_00101100": {"strategy": "string_context", "sub_channel": "oz_ad", "confidence": 0.8}}
    gfonk = [{"addr": int(f["address"], 16), "name": f["name"], "is_thunk": f["is_thunk"], "size": f["size"]}
             for f in fonk_ham]
    kayitlar, sayac = m.uo.degerlendir_elf(genel, koken, gfonk, gt, "debian")
    satirlar = ot.satirlari_kur(m, e, fonk_ham, False, gt, {}, 0x100000, genel, koken, kayitlar, None, None, {})
    return {s["adres"]: s for s in satirlar}, kayitlar, sayac


def test_sema_ve_hukum(m):
    satirlar, kayitlar, sayac = _sentetik_ikili(m)
    for s in satirlar.values():
        assert set(s) == set(ot.CEKIRDEK_ALANLARI)
    s1, s2, s3, s4, s5, s6 = (satirlar[a] for a in (0x101000, 0x101100, 0x101200, 0x101300, 0x100500, 0x101400))
    assert (s1["urun_olcude"], s1["hukum"], s1["nufusta"], s1["satir"]) == (True, m.uo.DOGRU, True, "ana")
    assert s1["kanal"] == "on_ad:gnulib" and s1["kanal_grubu"] == "kalan" and s1["dosya_adresi"] == 0x1000
    assert (s2["urun_olcude"], s2["hukum"]) == (True, m.uo.YANLIS)
    assert s2["kanal_ana"] == "string_context" and s2["alt_kanal"] == "oz_ad"
    assert (s3["urun_olcude"], s3["hukum"], s3["urun_adi"], s3["urun_atlama"]) == (False, None, None, None)
    assert (s4["urun_olcude"], s4["urun_atlama"], s4["nufusta"]) == (False, m.uo.ATLAMA_GHIDRA_ADLI, False)
    assert s5["kaynak_sinifi"] == ot.SINIF_ICE_AKTARIM and s5["gt_adlari"] is None
    assert (s6["urun_olcude"], s6["hukum"], s6["nufusta"]) == (True, m.uo.DOGRU, False)
    # ölçüye giren adlar urun_olc'un kayıtlarıyla bire bir
    assert {s["adres"] for s in satirlar.values() if s["urun_olcude"]} == {k["adres"] for k in kayitlar}
    assert sayac[m.uo.ATLAMA_GHIDRA_ADLI] == 1


def test_mac_ve_cpp_alanlari(m):
    ks1 = m.ks1
    e = ks1.Elf("mac", "p", "p", Path("/yok/static"), Path("/yok"))
    fonk_ham = [{"name": "FUN_100001000", "address": "100001000", "size": 70, "is_thunk": False,
                 "is_external": False, "source": "DEFAULT"}]
    gt = ks1.GtBirimi(adlar={0x100001000: ["_f"]}, nufus={0x100001000}, export_gt=set(), kunye={})
    (s,) = ot.satirlari_kur(m, e, fonk_ham, True, gt, {}, 0, {}, {}, [], None, None, {})
    assert s["kaynak_sinifi"] == ot.SINIF_BILINMIYOR and s["kaynak_kaniti"] == ot.KANIT_MAC
    assert s["nufusta"] is False and s["cpp_disarida"] is True       # C++ ikili nüfusa girmez
    assert s["boyut_dilimi"] == "64-255"


# --------------------------------------------------------------------------------------------
# Tutarlılık kapısı


def _tablo_yaz(yol: Path, satirlar: list[dict]) -> None:
    with gzip.open(yol, "wt", encoding="utf-8") as f:
        for s in satirlar:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")


def test_dogrula_tutar_ve_bozulunca_tutmaz(m, tmp_path):
    satirlar, _, _ = _sentetik_ikili(m)
    liste = [satirlar[a] for a in sorted(satirlar)]
    ogeler = {s["adres_hex"]: m.uo.oge_yaz({"durum": s["hukum"], "satir": s["satir"], "nufusta": s["nufusta"],
                                             "etiket": s["etiket"], "kanal": s["kanal"]})
              for s in liste if s["urun_olcude"]}
    olcum = {"birimler": {"debian/prog": {"nufus": 3, "elfler": {"ikili": {"nufus": 3, "ad_verilen": 3,
                                                                         "dogru": 2}}}},
             "ogeler": {"debian/prog": {"ikili": ogeler}}}
    oj = tmp_path / "olcum.json"
    oj.write_text(json.dumps(olcum), encoding="utf-8")
    tablo = tmp_path / "olgu.jsonl.gz"
    _tablo_yaz(tablo, liste)
    beklenen = dict(havuz={"nufus": 3, "ad_verilen": 3, "dogru": 2, "yanlis": 1, "nufusta_dogru": 1,
                           "nufusta_ad": 2},
                    birim_beklenen={"debian/prog": (3, 2, 1)}, ikili_sayisi=1, satir_sayisi=6)
    sonuc = ot.dogrula(tablo, oj, m.uo.oge_yaz, m.uo.DOGRU, **beklenen)
    assert sonuc["tuttu"], [d for d in sonuc["denetimler"] if not d["tuttu"]]
    # bir hüküm bozulursa: havuz, birim ve öğe denetimleri düşer
    bozuk = [dict(s) for s in liste]
    for s in bozuk:
        if s["hukum"] == m.uo.YANLIS:
            s["hukum"] = m.uo.DOGRU
    _tablo_yaz(tablo, bozuk)
    sonuc = ot.dogrula(tablo, oj, m.uo.oge_yaz, m.uo.DOGRU, **beklenen)
    dusen = {d["denetim"] for d in sonuc["denetimler"] if not d["tuttu"]}
    assert not sonuc["tuttu"]
    assert {"havuz.dogru", "havuz.yanlis", "oge_farki"} <= dusen


def test_butce_sayimi(m):
    import olgu_butce as ob
    satirlar, _, _ = _sentetik_ikili(m)
    c = ob.say_(satirlar.values(), lambda s: "t", m.uo.DOGRU)["t"]
    assert (c["satir"], c["ic"], c["nufus"], c["nufus_ad"], c["nufus_dogru"], c["nufus_yanlis"],
            c["nufus_adsiz"], c["ad"], c["dogru"], c["yanlis"]) == (6, 5, 3, 2, 1, 1, 1, 3, 2, 1)
    assert Counter(ob.DILIM_SIRASI) and ob.DILIM_SIRASI[-1] == ot.BOYUT_EN_BUYUK
