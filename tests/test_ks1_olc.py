"""scripts/measurement/ks1_olc.py — KS-1 ölçüm betiğinin testleri (plan v2.2 N1).

Bütün testler sentetik verilerle koşar: sentetik GT sözlükleri, sentetik ``static/`` dizinleri ve
geçici git depoları. Gerçek GT, dbgsym ya da dSYM okunmaz.
Kilitlenen davranışlar:
  (a) ad karşılaştırması: tam eşitlik; Mach-O'da baştaki tek ``_``; klon ekli GT ayrı satırda;
      proje normalleştirmesi yalnız duyarlılık satırı,
  (b) birim içi tekilleştirme (aynı ad bir öğe; bütün örnekleri doğruysa doğru),
  (c) tür kararı: n ≥ N_MIN birimlerin makro ortalaması, en az EN_AZ_BIRIM birim,
  (d) kapsam ve ayrı satırlar (parça, klon, eşlenemeyen),
  (e) ön koşullar: ön kayıt commit'i atası, sha256 denetimi,
  (f) program sınıfı eş değişkeni ve GT'siz sayım (çıktıda ad yok).

Mutasyon koruması: ``scripts/measurement/mutation_specs_ks1.json``.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "ks1_olc.py"
_spec = importlib.util.spec_from_file_location("ks1_olc_under_test", _PATH)
ko = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ko
_spec.loader.exec_module(ko)

sys.path.insert(0, str(_KOK / "tests"))
from test_tarif_kesin import ASSERT_RTN, DZ, LOG, MACHO, adr, bl, darwin_log, temel  # noqa: E402


# --------------------------------------------------------------------------------------------
# (a) ad karşılaştırması


def test_platform_adi():
    assert ko.platform_adi("_kume_kur", "mac") == "kume_kur"
    assert ko.platform_adi("__assert_rtn", "mac") == "_assert_rtn"   # yalnız tek _
    assert ko.platform_adi("_kume_kur", "debian") == "_kume_kur"


@pytest.mark.parametrize("ad, taban", [
    ("foo.isra.0", "foo"), ("foo.constprop.0.isra.0", "foo"), ("foo.cold", "foo"),
    ("foo.cold.1", "foo"), ("foo.part.0", "foo"), ("foo.lto_priv.0", "foo"), ("foo.llvm.123", "foo"),
    ("OUTLINED_FUNCTION_3", ""), ("_OUTLINED_FUNCTION_12", ""), ("foo", None), ("foo.bar", None),
])
def test_klon_tabani(ad, taban):
    assert ko.klon_tabani(ad) == taban


def test_capa_degerlendir_tam_esitlik():
    d = ko.capa_degerlendir
    assert d("kume_kur", ["kume_kur"], "debian")["durum"] == "dogru"
    assert d("Kume_Kur", ["kume_kur"], "debian")["durum"] == "yanlis"     # harf duyarlı
    assert d("kume_kur_2", ["kume_kur"], "debian")["durum"] == "yanlis"   # ek yok sayılmaz
    assert d("kume_kur", ["_kume_kur"], "mac")["durum"] == "dogru"
    assert d("kume_kur", ["_kume_kur"], "debian")["durum"] == "yanlis"
    assert d("agac_sonraki", ["agac_SONRAKI", "agac_sonraki"], "debian")["durum"] == "dogru"   # takma ad
    k = d("satir_birak", ["_satir_birak.cold.1"], "mac")
    assert (k["satir"], k["durum"]) == ("klon", "dogru")
    k = d("kayit_yaz", ["kayit_yaz.constprop.0", "kayit_yaz.isra.0"], "debian")
    assert (k["satir"], k["durum"]) == ("klon", "dogru")
    k = d("kayit_yaz", ["kayit_yaz.isra.0", "kayit_yaz"], "debian")      # eksiz takma ad var → ana satır
    assert (k["satir"], k["durum"]) == ("ana", "dogru")
    k = d("kume_kur", ["OUTLINED_FUNCTION_4"], "mac")
    assert (k["satir"], k["durum"]) == ("klon", "yanlis")
    # proje normalleştirmesi daha gevşek: yalnız duyarlılık satırı
    k = d("kume_kur_2", ["kume_kur"], "debian")
    assert (k["durum"], k["proje"]) == ("yanlis", True)


# --------------------------------------------------------------------------------------------
# (b) tekilleştirme, (d) ayrı satırlar ve kapsam


def kayit(ad, durum="dogru", satir="ana", rol="kendi", turler=("func_kalibi",), nufusta=True):
    return {"adres": 0, "ad": ad, "turler": list(turler), "rol": rol, "dizgi": True,
            "nufusta": nufusta, "export_gt": False, "satir": satir, "durum": durum,
            "proje": durum == "dogru"}


def test_tekillestirme_butun_ornekler_dogru_olmali():
    ks = [kayit("xmalloc"), kayit("xmalloc", "yanlis"), kayit("quote"), kayit("quote")]
    tekil = ko.kesinlik_ozeti(ks, tekil=True)
    assert tekil["n"] == 2 and tekil["kesinlik"]["k"] == 1
    ornek = ko.kesinlik_ozeti(ks, tekil=False)
    assert ornek["n"] == 4 and ornek["kesinlik"]["k"] == 3


def test_parca_klon_eslenemeyen_kesinlige_girmez():
    ks = [kayit("a_b"), kayit("a_b", "yanlis", rol="parca"), kayit("c_d", satir="klon"),
          kayit("e_f", satir="eslenemedi", durum=None)]
    o = ko.kesinlik_ozeti(ks)
    assert o["n"] == 1 and o["kesinlik"]["k"] == 1
    ayri = ko.ayri_satirlar(ks)
    assert ayri == {"klon": {"n": 1, "dogru": 1}, "parca": {"n": 1, "dogru": 0},
                    "eslenemedi": {"n": 1}}


def test_kapsam_dogrulugundan_bagimsiz_parca_haric():
    ks = [kayit("a_b"), kayit("c_d", "yanlis"), kayit("e_f", nufusta=False),
          kayit("g_h", rol="parca")]
    k = ko.kapsam_ozeti(ks, nufus=10)
    assert k["kapsam"]["k"] == 2 and k["dogru_kapsam"]["k"] == 1 and k["nufus"] == 10


def test_gorunum_satirlari():
    ks = [kayit("a_b", turler=("assert", "func_kalibi")), kayit("c_d", turler=("func_aktarma",)),
          kayit("e_f", turler=("assert",), rol="ust"), kayit("e_f", turler=("assert",), rol="parca")]
    assert len(ko.gorunum(ks, ko.DIZGI_TURLERI)) == 4
    assert len(ko.gorunum(ks, "func_kalibi")) == 1
    assert [k["ad"] for k in ko.gorunum(ks, "assert")] == ["a_b"]          # yalnız kendi gövdesinde
    assert [k["rol"] for k in ko.gorunum(ks, "assert_ust")] == ["ust", "parca"]
    assert ko.kesinlik_ozeti(ko.gorunum(ks, "assert_ust"))["n"] == 1       # parça kesinliğe girmez


# --------------------------------------------------------------------------------------------
# (c) tür kararı


def ozet(n, k):
    return {"n": n, "kesinlik": ko.oran(k, n)}


def test_makro_karar():
    m = ko.makro({"mac/tmux": ozet(100, 97), "debian/tmux": ozet(50, 48), "mac/htop": ozet(3, 0)})
    assert m["giren_birimler"] == ["debian/tmux", "mac/tmux"]
    assert m["kucuk_birimler"] == ["mac/htop"]
    assert m["makro_kesinlik"] == pytest.approx((0.97 + 0.96) / 2)
    assert m["karar"] == "kesin"
    assert m["havuz"]["n"] == 153 and m["havuz"]["k"] == 145
    m = ko.makro({"mac/tmux": ozet(100, 97), "debian/tmux": ozet(50, 45)})
    assert m["karar"] == "kesin_degil"
    m = ko.makro({"mac/tmux": ozet(100, 100), "debian/tree": ozet(5, 5)})
    assert m["karar"] == "yetersiz" and m["makro_kesinlik"] == 1.0
    m = ko.makro({})
    assert m["karar"] == "yetersiz" and m["makro_kesinlik"] is None


# --------------------------------------------------------------------------------------------
# GT birimiyle değerlendirme (sentetik GT)


class _Capa:
    def __init__(self, ad, turler=("func_kalibi",), rol="kendi"):
        self.name, self.types, self.role = ad, tuple(turler), rol


def test_degerlendir_elf():
    gt = ko.GtBirimi(adlar={0x1000: ["_komut_bul"], 0x2000: ["_satir_birak.cold.1"],
                            0x3000: ["_other"]}, nufus={0x1000, 0x3000}, export_gt=set(), kunye={})
    capalar = {"1000": _Capa("komut_bul"), "2000": _Capa("satir_birak", ("assert",), "parca"),
               "3000": _Capa("yanlis_ad"), "4000": _Capa("bilinmeyen")}
    ks = ko.degerlendir_elf(capalar, gt, "mac", ("assert", "func_kalibi", "func_aktarma"))
    durum = {k["ad"]: (k["satir"], k["durum"]) for k in ks}
    assert durum == {"komut_bul": ("ana", "dogru"), "satir_birak": ("klon", "dogru"),
                     "yanlis_ad": ("ana", "yanlis"), "bilinmeyen": ("eslenemedi", None)}
    o = ko.birim_ozeti(ks, nufus=2, export_gt=0)
    assert set(o) == set(ko.KARAR_SATIRLARI)
    assert o["func_kalibi"]["tekil"]["n"] == 2 and o["func_kalibi"]["tekil"]["kesinlik"]["k"] == 1
    assert o["assert"]["tekil"]["n"] == 0 and o["assert"]["ayri"]["parca"] == {"n": 0, "dogru": 0}
    assert o["assert_ust"]["tekil"]["n"] == 0 and o["assert_ust"]["ayri"]["parca"] == {"n": 1, "dogru": 1}
    assert o["func_kalibi"]["kapsam"]["kapsam"]["k"] == 2


def test_olc_ciktisinda_ad_yok(tmp_path, monkeypatch):
    """olc: GT yükleyici sentetik GtBirimi döndürür; çıktı JSON'unda çapa ya da GT adı geçmez."""
    ik = temel(MACHO, program="tmux")
    fmt = ik.dizgi(DZ, "%s: x")
    adlar = ["ozel_ad_bir", "ozel_ad_iki"]
    for i, ad in enumerate(adlar):
        a = ik.dizgi(DZ + 0x40 + 0x20 * i, ad)
        ik.fonksiyon(0x100001000 + 0x100 * i, darwin_log(fmt, a) + ["ret"])
    kosu = tmp_path / "kosu"
    st = ik.yaz(kosu / "tmux" / "ws" / "workspaces" / "tmux" / "20261021_000000")
    gt = ko.GtBirimi(adlar={0x100001000: ["_ozel_ad_bir"], 0x100001100: ["_gercek_gizli"]},
                     nufus={0x100001000, 0x100001100}, export_gt=set(), kunye={"gt": "sentetik"})
    monkeypatch.setattr(ko, "gt_mac", lambda e, veri: gt)
    sonuc = ko.olc(ko.mac_elfleri(kosu), tmp_path, None, denetle=False, beklenen={"mac": 1})
    metin = json.dumps(sonuc, ensure_ascii=False, default=str)
    for ad in adlar + ["gercek_gizli"]:
        assert ad not in metin
    b = sonuc["birimler"]["mac/tmux"]["turler"]["func_kalibi"]["tekil"]
    assert (b["n"], b["kesinlik"]["k"]) == (2, 1)
    assert sonuc["kararlar"]["func_kalibi"]["karar"] == "yetersiz"
    assert st.is_dir()


def test_nufus_eksikse_olcum_durur(tmp_path):
    tamam = ko.Elf("debian", "tree", "tree", tmp_path, tmp_path)
    bitmemis = ko.Elf("debian", "coreutils", "ls", None, tmp_path)
    assert ko.nufus_denetle([tamam], {"debian": 1})["sorunlar"] == []
    with pytest.raises(ko.OnkosulHatasi, match="beklenen 117"):
        ko.nufus_denetle([tamam])                          # varsayılan beklenen: 117 Debian ELF
    with pytest.raises(ko.OnkosulHatasi, match="bitmemiş"):
        ko.nufus_denetle([tamam, bitmemis], {"debian": 2})
    k = ko.nufus_denetle([tamam, bitmemis], {"debian": 2}, eksik_izinli=True)
    assert k["eksik_izinli"] is True and len(k["sorunlar"]) == 1
    assert ko.BEKLENEN_ELF == {"mac": 2, "debian": 117}


def _static(kok, fonksiyonlar):
    st = kok / "static"
    st.mkdir(parents=True)
    (st / "ghidra_functions.json").write_text(json.dumps({"functions": fonksiyonlar}))
    return st


def _fonk(adres, ad=None, thunk=False):
    return {"name": ad or f"FUN_{adres:08x}", "address": f"{adres:08x}", "is_thunk": thunk,
            "is_external": False, "size": 4}


def test_gt_elf_ofset_nufus_export_klon(tmp_path, monkeypatch):
    """ELF GT yapıştırıcısı: ofset entry'den, nüfus = CRT/export/klon dışı ve Ghidra'da adsız."""
    import types
    gercek = ko._f1()
    soyulmus = tmp_path / "bin" / "prog"
    soyulmus.parent.mkdir()
    soyulmus.write_bytes(b"elf")
    indir = tmp_path / "indir"
    dbg = indir / "x_prog-dbgsym_1_arm64" / "usr" / "lib" / "debug" / ".build-id" / "ab" / "cdef.debug"
    dbg.parent.mkdir(parents=True)
    dbg.write_bytes(b"dbg")
    fonk = [_fonk(0x100500, "entry"), _fonk(0x101000), _fonk(0x102000), _fonk(0x103000, "disari"),
            _fonk(0x104000, "puts", thunk=True)]
    st = _static(tmp_path / "ws", fonk)
    (tmp_path / "ws" / "raw").mkdir()
    (tmp_path / "ws" / "raw" / "target_info.json").write_text(json.dumps(
        {"path": str(soyulmus), "file_hash": gercek.sha256_file(soyulmus)}))
    gt = {"entry": "0x500", "elf_type": "ET_DYN",
          "exec_sections": [{"name": ".text", "start": "0x0", "end": "0x10000"}],
          "functions": [{"addr": "0x500", "names": ["_start"], "crt": True, "exported": False},
                        {"addr": "0x1000", "names": ["foo"], "crt": False, "exported": False},
                        {"addr": "0x2000", "names": ["bar.isra.0"], "crt": False, "exported": False},
                        {"addr": "0x3000", "names": ["disari"], "crt": False, "exported": True}]}
    sahte = types.SimpleNamespace(**{k: getattr(gercek, k) for k in dir(gercek) if not k.startswith("__")})
    sahte.read_elf_info = lambda yol: {"build_id": "abcdef"}
    sahte.extract_gt = lambda d, s_, corpus="", binary="": gt if d == dbg else None
    monkeypatch.setattr(ko, "_f1", lambda: sahte)
    e = ko.Elf("debian", "prog", "prog", st, tmp_path / "ws")
    g = ko.gt_elf(e, indir)
    assert g.kunye["ofset"] == "0x100000" and g.kunye["ofset_kaynagi"] == "ghidra_entry"
    assert sorted(g.adlar) == [0x100500, 0x101000, 0x102000, 0x103000]
    assert g.nufus == {0x101000} and g.export_gt == {0x103000}
    soyulmus.write_bytes(b"degisti")
    with pytest.raises(ko.OnkosulHatasi, match="sha256"):
        ko.gt_elf(e, indir)


def test_gt_mac_nufus_ve_hedef_denetimi(tmp_path, monkeypatch):
    import types
    gt_yolu = tmp_path / "tmux.gt.json"
    gt_yolu.write_text(json.dumps({"stripped_sha256": "abc", "functions": [
        {"addr": "0x100001000", "names": ["_foo"]}, {"addr": "0x100002000", "names": ["_foo.cold.1"]},
        {"addr": "0x100003000", "names": ["_bar"]}, {"addr": "0x100004000", "names": ["_baz"]}]}))
    monkeypatch.setitem(sys.modules, "macho_measure",
                        types.SimpleNamespace(gt_path=lambda veri, ad: gt_yolu))
    fonk = [_fonk(0x100001000), _fonk(0x100002000), _fonk(0x100003000, "bilinen"),
            _fonk(0x100004000, thunk=True)]
    st = _static(tmp_path / "ws", fonk)
    (tmp_path / "ws" / "raw").mkdir()
    hedef = tmp_path / "ws" / "raw" / "target_info.json"
    hedef.write_text(json.dumps({"file_hash": "abc"}))
    e = ko.Elf("mac", "tmux", "tmux", st, tmp_path / "ws")
    g = ko.gt_mac(e, tmp_path)
    assert g.nufus == {0x100001000}      # cold parça, Ghidra'nın bildiği ve thunk dışarıda
    assert g.adlar[0x100002000] == ["_foo.cold.1"]
    hedef.write_text(json.dumps({"file_hash": "baska"}))
    with pytest.raises(ko.OnkosulHatasi, match="strip'li kopyası değil"):
        ko.gt_mac(e, tmp_path)


def test_olc_markdown_ad_icermez(tmp_path, monkeypatch):
    ik = temel(MACHO, program="tmux")
    fmt = ik.dizgi(DZ, "%s: x")
    a = ik.dizgi(DZ + 0x40, "gizli_ad_md")
    ik.fonksiyon(0x100001000, darwin_log(fmt, a) + ["ret"])
    kosu = tmp_path / "kosu"
    ik.yaz(kosu / "tmux" / "ws" / "workspaces" / "tmux" / "20261021_000000")
    gt = ko.GtBirimi(adlar={0x100001000: ["_gizli_ad_md"]}, nufus={0x100001000}, export_gt=set(),
                     kunye={})
    monkeypatch.setattr(ko, "gt_mac", lambda e, veri: gt)
    sonuc = ko.olc(ko.mac_elfleri(kosu), tmp_path, None, denetle=False, beklenen={"mac": 1})
    md = ko.olc_markdown(sonuc)
    assert "gizli_ad_md" not in md
    assert "| mac/tmux | `func_kalibi` | 1 | %100,0 |" in md
    assert "`yetersiz`" in md


# --------------------------------------------------------------------------------------------
# (e) ön koşullar


def test_sha256_denetimi(tmp_path):
    p = tmp_path / "x.py"
    p.write_text("a = 1\n")
    dogru = ko.sha256_dosya(p)
    assert ko.sha256_denetle(p, dogru) == dogru
    with pytest.raises(ko.OnkosulHatasi):
        ko.sha256_denetle(p, "0" * 64)


def _git(kok, *a):
    subprocess.run(["git", *a], cwd=kok, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
                        "HOME": str(kok)})


def _depo(tmp_path):
    kok = tmp_path / "depo"
    (kok / "karadul" / "reconstruction" / "tarif").mkdir(parents=True)
    (kok / "scripts" / "measurement").mkdir(parents=True)
    (kok / "karadul" / "reconstruction" / "tarif" / "kesin.py").write_text("KS1_VERSION = 1\n")
    (kok / "scripts" / "measurement" / "ks1_olc.py").write_text("# olc\n")
    d = kok / "docs" / "arge" / "2026-10-21_g11_n1"
    d.mkdir(parents=True)
    _git(kok, "init", "-q")
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "kod")
    return kok, d


def _sabitle(kok, d):
    belge = {"sema": ko.SABITLER_SEMA, "dosyalar": {
        rel: ko.sha256_dosya(kok / rel)
        for rel in ("karadul/reconstruction/tarif/kesin.py", "scripts/measurement/ks1_olc.py")}}
    (d / "ks1_sabitler.json").write_text(json.dumps(belge))
    (d / "ks1_onkayit.md").write_text("# ön kayıt\n")


def test_onkosul_commitlenmemis_onkayit(tmp_path):
    kok, d = _depo(tmp_path)
    _sabitle(kok, d)   # yazıldı ama commit'lenmedi
    with pytest.raises(ko.OnkosulHatasi, match="commit'lenmemiş"):
        ko.onkosullari_denetle(kok, d / "ks1_onkayit.md", d / "ks1_sabitler.json")


def test_onkosul_gecer_ve_kod_degisince_durur(tmp_path):
    kok, d = _depo(tmp_path)
    _sabitle(kok, d)
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "ön kayıt")
    o = ko.onkosullari_denetle(kok, d / "ks1_onkayit.md", d / "ks1_sabitler.json")
    assert o["onkayit_commit_atasi"] is True and len(o["onkayit_commit"]) == 40
    (kok / "karadul" / "reconstruction" / "tarif" / "kesin.py").write_text("KS1_VERSION = 2\n")
    with pytest.raises(ko.OnkosulHatasi, match="sha256"):
        ko.onkosullari_denetle(kok, d / "ks1_onkayit.md", d / "ks1_sabitler.json")


def test_onkosul_sonradan_degisen_sabitler_sayilmaz(tmp_path):
    """Sabitler ön kayıt commit'indeki hâliyle okunur; sonradan güncellemek kodu aklamaz."""
    kok, d = _depo(tmp_path)
    _sabitle(kok, d)
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "ön kayıt")
    (kok / "karadul" / "reconstruction" / "tarif" / "kesin.py").write_text("KS1_VERSION = 3\n")
    _sabitle(kok, d)
    _git(kok, "add", "-A")
    _git(kok, "commit", "-q", "-m", "sonradan")
    with pytest.raises(ko.OnkosulHatasi, match="sha256"):
        ko.onkosullari_denetle(kok, d / "ks1_onkayit.md", d / "ks1_sabitler.json")


# --------------------------------------------------------------------------------------------
# (f) program sınıfı ve GT'siz sayım


@pytest.mark.parametrize("deger, gecer", [
    ("komut_bul", True), ("a_b_c", True), ("x86_64", True), ("komut", False), ("Komut_bul", False),
    ("_komut", False), ("komut_", False), ("komut-bul", False), ("komut__bul", False),
])
def test_snake_re(deger, gecer):
    assert bool(ko.SNAKE_RE.match(deger)) is gecer


def test_boyut_tabakasi():
    assert [ko.boyut_tabakasi(n) for n in (0, 499, 500, 1999, 2000)] == \
        ["kucuk", "kucuk", "orta", "orta", "buyuk"]


def test_birim_sinifi_ve_zenginlik_esigi(tmp_path):
    def static_yaz(kok, ic, snake, duz, thunk=0):
        st = kok / "static"
        st.mkdir(parents=True)
        fonk = [{"name": f"FUN_{i:x}", "address": f"{i:x}", "is_thunk": False, "is_external": False}
                for i in range(ic)]
        fonk += [{"name": "printf", "address": f"{9000 + i:x}", "is_thunk": True, "is_external": False}
                 for i in range(thunk)]
        dz = [{"address": f"{i:x}", "value": f"ad_{i}"} for i in range(snake)]
        dz += [{"address": f"{500 + i:x}", "value": f"Metin {i}"} for i in range(duz)]
        (st / "ghidra_functions.json").write_text(json.dumps({"functions": fonk}))
        (st / "ghidra_strings.json").write_text(json.dumps({"strings": dz}))
        return st
    e1 = ko.Elf("debian", "coreutils", "ls", static_yaz(tmp_path / "ls", 100, 10, 5, thunk=7), tmp_path)
    e2 = ko.Elf("debian", "coreutils", "cp", static_yaz(tmp_path / "cp", 300, 30, 1), tmp_path)
    e3 = ko.Elf("debian", "tree", "tree", static_yaz(tmp_path / "tree", 50, 0, 9), tmp_path)
    e4 = ko.Elf("debian", "tmux", "tmux", None, tmp_path)
    s = ko.sinif([e1, e2, e3, e4])
    c = s["birimler"]["debian/coreutils"]
    assert (c["elf"], c["ic_fonksiyon"], c["snake_dizgi"]) == (2, 400, 40)
    assert c["dizgi_zenginligi"] == pytest.approx(0.1)
    assert c["ic_fonksiyon_ortanca"] == 200 and c["boyut_tabakasi"] == "kucuk"
    assert s["birimler"]["debian/tree"]["dizgi_zenginligi"] == 0.0
    assert c["zenginlik_esigi"] == pytest.approx(0.05)
    assert c["zenginlik_sinifi"] == "zengin" and s["birimler"]["debian/tree"]["zenginlik_sinifi"] == "yoksul"
    assert s["bekleyen"] == ["debian/tmux/tmux"]


def test_say_ad_yazmaz_ve_bekleyeni_sayar(tmp_path):
    ik = temel(MACHO, program="tmux")
    fmt = ik.dizgi(DZ, "%s: x")
    a = ik.dizgi(DZ + 0x40, "gizli_fonksiyon_adi")
    ik.fonksiyon(0x100001000, darwin_log(fmt, a) + ["ret"])
    fa = ik.dizgi(DZ + 0x80, "parca_adi_gizli")
    s = ik.fonksiyon(0x100008000, adr(0, fa) + [bl(ASSERT_RTN)])
    ik.fonksiyon(0x100002000, [bl(s), "ret"])
    kosu = tmp_path / "kosu"
    ik.yaz(kosu / "tmux" / "ws" / "workspaces" / "tmux" / "20261021_000000")
    deb = tmp_path / "deb" / "coreutils" / "ls"
    deb.mkdir(parents=True)   # BITTI yok: bekliyor
    sonuc = ko.say(ko.elfleri_topla(kosu, tmp_path / "deb"))
    metin = json.dumps(sonuc, ensure_ascii=False, default=str)
    assert "gizli_fonksiyon_adi" not in metin and "parca_adi_gizli" not in metin
    b = sonuc["birimler"]["mac/tmux"]
    assert b["sayac"]["9_capa:func_kalibi"] == 1 and b["sayac"]["9_capa:assert"] == 1
    assert b["rol_tur"] == {"kendi:func_kalibi": 1, "parca:assert": 1, "ust:assert": 1}
    assert sonuc["bekleyen"] == ["debian/coreutils/ls"]
    assert LOG  # temel() günlük fonksiyonunu kurar


def test_calisma_alani_adi_elf_adindan_farkli(tmp_path):
    """coreutils'in ``[`` ikilisi: Karadul çalışma alanını ``_`` adıyla açar; ad varsayılmaz."""
    ik = temel(MACHO, program="[")
    d = tmp_path / "deb" / "coreutils" / "["
    ik.yaz(d / "ws" / "workspaces" / "_" / "20261021_000000")
    (d / "BITTI").write_text("ok 1\n")
    elfler = ko.debian_elfleri(tmp_path / "deb")
    assert [(e.program, e.ad, e.static is not None) for e in elfler] == [("coreutils", "[", True)]
    # iki çalışma alanı belirsizdir: durur
    ik.yaz(d / "ws" / "workspaces" / "_" / "20261021_000001")
    with pytest.raises(ValueError, match="tam olarak bir"):
        ko.debian_elfleri(tmp_path / "deb")


def test_cpp_ikili_mi():
    assert ko.cpp_ikili_mi([{"name": "_ZdlPv", "is_thunk": True}])
    assert ko.cpp_ikili_mi([{"name": "__gxx_personality_v0", "is_external": True}])
    assert not ko.cpp_ikili_mi([{"name": "_ZdlPv", "is_thunk": False}])   # iç ad sayılmaz
    assert not ko.cpp_ikili_mi([{"name": "printf", "is_thunk": True}])
    # glibc C çalışma zamanı: her PIE'de var, C++ işareti değil
    assert not ko.cpp_ikili_mi([{"name": "__cxa_finalize", "is_thunk": True},
                                {"name": "__cxa_atexit", "is_thunk": True}])


def test_sabit_dosyalar_listesi():
    assert ko.SABIT_DOSYALAR[0] == "karadul/reconstruction/tarif/kesin.py"
    assert "scripts/measurement/ks1_olc.py" in ko.SABIT_DOSYALAR
