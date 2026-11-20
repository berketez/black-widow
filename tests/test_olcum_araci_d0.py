"""Dalga 0, OLCUM paketi: ölçüm aracı kusurlarının onarım testleri (kalem 2–7).

Kaynak: ``docs/arge/2026-11-20_dalga0/gonderim/OLCUM.md``; ilerleme ``docs/arge/2026-11-20_dalga0/OLCUM.md``.
Her sınama sentetik veriyle koşar (gerçek koşu kökü, GT, Ghidra yok).

  - kalem 2: ``ks1_olc`` ``BITTI``'nin içeriğini okur; yalnız başarı işareti bitmiş sayılır, kısmi /
    hatalı / bekleyen ayrı sayılır ve özete girer; Mac birimi de ``BITTI``'ye bakılarak sınanır.

Mutasyon koruması: ``scripts/measurement/mutation_specs_olcum_araci.json``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_OLCUM = _KOK / "scripts" / "measurement"


def _yukle(ad: str, dosya: str):
    spec = importlib.util.spec_from_file_location(ad, _OLCUM / dosya)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


uo = _yukle("urun_olc_d0_under_test", "urun_olc.py")
ks1 = uo.ks1

ZAMAN = "20261110_000000"   # öbür ölçüm testlerinin sentetik çalışma alanı zamanıyla aynı


# --------------------------------------------------------------------------------------------
# Kalem 2 — ks1_olc BITTI


def _ikili(d: Path, bitti=None, gunluk=False, run_json=None, ad=None):
    """Bir ikili dizini (urun_kos ya da eski düzen): ``ws/workspaces/<ad>/<zaman>/static``."""
    ws = d / "ws" / "workspaces" / (ad or d.name) / ZAMAN
    st = ws / "static"
    st.mkdir(parents=True)
    (st / "ghidra_functions.json").write_text(json.dumps({"functions": []}))
    (st / "ghidra_strings.json").write_text(json.dumps({"strings": []}))
    (ws / "raw").mkdir()
    (ws / "raw" / "target_info.json").write_text(json.dumps({"file_hash": f"sha-{d.name}"}))
    (ws / "reports").mkdir()
    (ws / "reports" / "report.json").write_text(json.dumps(
        {"environment": {"ghidra": {"version": "12.1.2", "matches_pinned": True}}}))
    src = ws / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps({"global": {}, "per_function": {}}))
    if bitti is not None:
        (d / "BITTI").write_text(bitti)
    if gunluk:
        (d / "kosu.log").write_text("…\n")
    if run_json is not None:
        (d / "run.json").write_text(json.dumps(run_json))
    return st


@pytest.mark.parametrize("icerik, beklenen", [
    ("0\n", ("tamam", "0")),
    ("ok 61\n", ("tamam", "ok")),
    ("3\n", ("kismi", "3")),
    ("1\n", ("hatali", "icerik:1")),
    ("zaman_asimi\n", ("hatali", "icerik:zaman_asimi")),
    ("", ("tamam", "bos")),
])
def test_bitti_durumu_icerik(tmp_path, icerik, beklenen):
    (tmp_path / "BITTI").write_text(icerik)
    assert ks1.bitti_durumu(tmp_path, "debian") == beklenen
    assert ks1.bitti_durumu(tmp_path, "mac") == beklenen


def test_bitti_durumu_dosyasiz(tmp_path):
    assert ks1.bitti_durumu(tmp_path, "debian") == ("bekliyor", "yok")
    # Mac: urun_kos düzeni (kosu.log var) ve BITTI yok → koşu bitmemiş
    (tmp_path / "kosu.log").write_text("")
    assert ks1.bitti_durumu(tmp_path, "mac") == ("bekliyor", "yok")
    # eski ol7 düzeni: run.json'dan
    eski = tmp_path / "eski"
    eski.mkdir()
    (eski / "run.json").write_text(json.dumps({"status": "ok", "exit_code": 0}))
    assert ks1.bitti_durumu(eski, "mac") == ("tamam", "run.json")
    (eski / "run.json").write_text(json.dumps({"status": "fail", "exit_code": 1}))
    assert ks1.bitti_durumu(eski, "mac") == ("hatali", "run.json")
    # hiçbir işaret yok (yalnız sentetik kök): bitmiş ama işareti ayrı
    yalin = tmp_path / "yalin"
    yalin.mkdir()
    assert ks1.bitti_durumu(yalin, "mac") == ("tamam", "isaretsiz")


def test_kismi_ve_hatali_bitmis_sayilmaz_ozete_girer(tmp_path):
    deb, mac = tmp_path / "debian", tmp_path / "mac"
    _ikili(deb / "zstd" / "zstd", bitti="0\n")
    _ikili(deb / "zstd" / "pzstd", bitti="3\n")              # kısmi: eskiden bitmiş sayılıyordu
    _ikili(deb / "tree" / "tree", bitti="zaman_asimi\n")     # hatalı içerik
    _ikili(deb / "htop" / "htop")                            # BITTI yok: bekliyor
    _ikili(mac / "tmux", bitti="3\n", gunluk=True)           # Mac kısmi: eskiden BITTI okunmuyordu
    _ikili(mac / "htop", gunluk=True)                        # Mac, urun_kos düzeni, BITTI yok
    elfler = ks1.elfleri_topla(mac, deb)
    durum = {f"{e.platform}/{e.ad}": (e.durum, e.static is not None) for e in elfler}
    assert durum == {"debian/zstd": ("tamam", True), "debian/pzstd": ("kismi", False),
                     "debian/tree": ("hatali", False), "debian/htop": ("bekliyor", False),
                     "mac/tmux": ("kismi", False), "mac/htop": ("bekliyor", False)}
    with pytest.raises(ks1.OnkosulHatasi, match=r"5 ELF bitmemiş ya da hatalı \(kısmi 2, hatalı 1, bekliyor 2\)"):
        ks1.nufus_denetle(elfler, None)
    k = ks1.nufus_denetle(elfler, None, eksik_izinli=True)
    assert k["durumlar"] == {"tamam": 1, "kismi": 2, "hatali": 1, "bekliyor": 2, "ciktisiz": 0}
    assert k["bitti_isareti"] == {"0": 1}
    assert k["biten"] == {"debian/zstd": 1}


def test_urun_olc_bitmislik_ozeti(tmp_path, monkeypatch):
    """``urun_olc olc`` kısmi ve hatalı ikiliyi ölçmez; JSON ve Markdown özetine sayıyla yazar."""
    deb = tmp_path / "debian"
    _ikili(deb / "zstd" / "zstd", bitti="0\n")
    _ikili(deb / "zstd" / "pzstd", bitti="3\n")
    _ikili(deb / "tree" / "tree", bitti="1\n")
    bos = ks1.GtBirimi(adlar={}, nufus=set(), export_gt=set(), kunye={"gt": "sentetik"})
    monkeypatch.setattr(ks1, "gt_elf", lambda e, indir: bos)
    beklenen = {"debian/zstd": 2, "debian/tree": 1}
    with pytest.raises(ks1.OnkosulHatasi, match="kısmi 1, hatalı 1"):
        uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen)
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen, eksik_izinli=True)
    assert s["nufus"]["durumlar"]["kismi"] == 1 and s["nufus"]["durumlar"]["hatali"] == 1
    assert list(s["birimler"]) == ["debian/zstd"] and list(s["birimler"]["debian/zstd"]["elfler"]) == ["zstd"]
    md = uo.olc_markdown(s)
    assert "tamam 1, kısmi 1, hatalı 1, bekliyor 0, çıktısız 0 (işaret: `0` × 1)" in md
    # ad haritası olmayan "bitmiş" ikili çıktısız sayılır (haritasizlari_isaretle)
    (next((deb / "zstd" / "zstd" / "ws").rglob("naming_map.json"))).unlink()
    s = uo.olc(ks1.elfleri_topla(None, deb), None, None, beklenen=beklenen, eksik_izinli=True)
    assert s["nufus"]["durumlar"]["ciktisiz"] == 1 and s["nufus"]["durumlar"]["tamam"] == 0
    assert "veri yok" in uo.bitmislik_cumlesi({})


# --------------------------------------------------------------------------------------------
# Kalem 3 — masum_kapi sarif katmanı: bilgi düzeyi YARA isabeti yara'nın doğru iddia kuralıyla

mk = _yukle("masum_kapi_d0_under_test", "masum_kapi.py")


def _yara_sonucu(kural_id, yara_kurali, duzey="note"):
    return {"ruleId": kural_id, "level": duzey, "message": {"text": f"YARA rule {yara_kurali} matched"},
            "properties": {"yara_rule": yara_kurali, "source": "yara"}}


def _sarif_kayit(tmp_path, anahtar, sonuclar):
    ws = tmp_path / anahtar.replace("/", "_") / "ws"
    (ws / "reports").mkdir(parents=True)
    (ws / "reports/report.sarif.json").write_text(json.dumps({"runs": [{"results": sonuclar}]}))
    return {"anahtar": anahtar, "katmanlar": {"sarif": mk.cikti_sarif(ws, ws.parent / "out", set())}}


def _hukumler(kayit):
    return {i["etiket"]: i["hukum"] for i in kayit["katmanlar"]["sarif"]["iddialar"]}


def test_sarif_bilgi_duzeyi_yara_dogru_bilinen(tmp_path):
    """a62f15e'nin 12 iddiasının deseni: KRDL001 / KRDL007 YARA isabeti, ikili ``yara`` katmanının doğru
    iddia kuralındaysa doğru bilinir; şüpheli kategorideki (KRDL003) aynı isabet ve kuralın ikili
    listesinde olmayan ikilideki isabet yanlış kalır. Kural dosyası gerçek ``masum_kapi_esik.json``."""
    esik = mk.esik_yukle(mk.ESIK_DOSYASI)
    kayitlar = {"gelistirme": [
        _sarif_kayit(tmp_path, "debian/openssl/openssl", [_yara_sonucu("KRDL001", "OpenSSL_Library")]),
        _sarif_kayit(tmp_path, "debian/zstd/zstd", [
            _yara_sonucu("KRDL007", "GCC_Compiler"), _yara_sonucu("KRDL007", "Zstd_Library"),
            _yara_sonucu("KRDL007", "LZ4_Library")]),
        _sarif_kayit(tmp_path, "debian/tree/tree", [
            _yara_sonucu("KRDL003", "GCC_Compiler", "warning"),      # 1.22.1 deseni: şüpheli diye
            _yara_sonucu("KRDL007", "Zlib_Library")]),                # tree'de zlib bağlı değil
        _sarif_kayit(tmp_path, "debian/sqlite3/sqlite3", [_yara_sonucu("KRDL001", "AES_SBox")]),
    ]}
    mk.hukumle(kayitlar, esik)
    l = kayitlar["gelistirme"]
    assert _hukumler(l[0]) == {"KRDL001:OpenSSL_Library": "dogru_bilinen"}
    assert _hukumler(l[1]) == {"KRDL007:GCC_Compiler": "dogru_bilinen", "KRDL007:Zstd_Library": "dogru_bilinen",
                               "KRDL007:LZ4_Library": "dogru_bilinen"}
    assert _hukumler(l[2]) == {"KRDL003:GCC_Compiler": "yanlis", "KRDL007:Zlib_Library": "yanlis"}
    assert _hukumler(l[3]) == {"KRDL001:AES_SBox": "yanlis"}
    o = mk.ozetle(kayitlar)["sarif"]["gelistirme"]
    assert (o["iddia"], o["yanlis"], o["dogru_bilinen"]) == (7, 3, 4)


def test_sarif_yara_kurali_alani(tmp_path):
    """YARA kuralı iddiaya yazılır (P07 sonrası ``yara_rule``; öncesi ``technology_name``); aynı etikette
    YARA dışı bir sonuç da varsa yazılmaz (hüküm yalnız etiketle verilir)."""
    k = _sarif_kayit(tmp_path, "debian/zstd/zstd", [
        _yara_sonucu("KRDL007", "Zstd_Library"),
        {"ruleId": "KRDL003", "level": "warning", "message": {"text": "t"},
         "properties": {"technology_name": "MPRESS_Packed (packer,mpress)"}},
        _yara_sonucu("KRDL004", "UPX"),
        {"ruleId": "KRDL004", "level": "error", "message": {"text": "p"}, "properties": {"packer_name": "UPX"}}])
    alan = {i["etiket"]: i.get("yara_kurali") for i in k["katmanlar"]["sarif"]["iddialar"]}
    assert alan == {"KRDL007:Zstd_Library": "Zstd_Library", "KRDL003:MPRESS_Packed": "MPRESS_Packed",
                    "KRDL004:UPX": None}
    # pozitif sette hüküm değişmez
    kayitlar = {"pozitif": [k]}
    mk.hukumle(kayitlar, mk.esik_yukle(mk.ESIK_DOSYASI))
    assert {i["hukum"] for i in k["katmanlar"]["sarif"]["iddialar"]} == {"pozitif_set"}


# --------------------------------------------------------------------------------------------
# Kalem 5 — function_f1.read_elf_info: BuildID yalnız sahibi "GNU" olan nottan

f1 = _yukle("function_f1_d0_under_test", "function_f1.py")


def _not(ad: bytes, tur: int, govde: bytes) -> bytes:
    import struct

    def hiza(b):
        return b + b"\0" * (-len(b) % 4)
    return struct.pack("<III", len(ad), len(govde), tur) + hiza(ad) + hiza(govde)


def _iki_notlu_elf(yol: Path, notlar: list) -> Path:
    """En küçük ELF64 (AArch64, ET_DYN): her not ayrı SHT_NOTE bölümünde, sonra .shstrtab."""
    import struct
    adlar = b"\0" + b"".join(ad + b"\0" for ad, _ in notlar) + b".shstrtab\0"
    govde, bolumler, ofset, ad_ofs = b"", [], 64, 1
    for ad, veri in notlar:
        bolumler.append((ad_ofs, 7, 2, ofset, len(veri), 4))          # SHT_NOTE, SHF_ALLOC
        govde += veri
        ofset += len(veri)
        ad_ofs += len(ad) + 1
    bolumler.append((ad_ofs, 3, 0, ofset, len(adlar), 1))             # SHT_STRTAB
    govde += adlar
    ofset += len(adlar)
    pad = -ofset % 8
    govde += b"\0" * pad
    shoff = ofset + pad
    shnum = len(bolumler) + 1
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    baslik = ident + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0x1000, 0, shoff, 0, 64, 56, 0, 64,
                                 shnum, shnum - 1)
    sh = b"\0" * 64 + b"".join(struct.pack("<IIQQQQIIQQ", n, t, fl, 0, o, s, 0, 0, a, 0)
                               for n, t, fl, o, s, a in bolumler)
    yol.write_bytes(baslik + govde + sh)
    return yol


GNU_BUILD_ID = bytes(range(0xA0, 0xB4))                    # 20 bayt
STAPSDT = (b"\x10\x20\x30\x40\0\0\0\0" + b"\0" * 16 + b"saglayici\0sonda\0-4@x0\0")


def test_read_elf_info_stapsdt_notu_build_id_sanilmaz(tmp_path):
    """SystemTap notu (sahibi ``stapsdt``, tür 3) GNU BuildID notundan SONRA gelirse eski kod onun
    baytlarını BuildID diye alıyordu (postgresql-17, python3.13-minimal)."""
    yol = _iki_notlu_elf(tmp_path / "iki_not.elf", [
        (b".note.gnu.build-id", _not(b"GNU\0", 3, GNU_BUILD_ID)),
        (b".note.stapsdt", _not(b"stapsdt\0", 3, STAPSDT))])
    bilgi = f1.read_elf_info(yol)
    assert bilgi["build_id"] == GNU_BUILD_ID.hex()
    assert (bilgi["machine"], bilgi["elf_type"]) == ("EM_AARCH64", "ET_DYN")
    # sıra ters (önce stapsdt) olduğunda da GNU notu
    ters = _iki_notlu_elf(tmp_path / "ters.elf", [
        (b".note.stapsdt", _not(b"stapsdt\0", 3, STAPSDT)),
        (b".note.gnu.build-id", _not(b"GNU\0", 3, GNU_BUILD_ID))])
    assert f1.read_elf_info(ters)["build_id"] == GNU_BUILD_ID.hex()
    # yalnız stapsdt notu varsa BuildID yok (uydurulmaz)
    tek = _iki_notlu_elf(tmp_path / "tek.elf", [(b".note.stapsdt", _not(b"stapsdt\0", 3, STAPSDT))])
    assert f1.read_elf_info(tek)["build_id"] is None


# --------------------------------------------------------------------------------------------
# Kalem 6 — urun_kos künyesi: KARADUL_CACHE_DIR ve imza veritabanının şeması

uk = _yukle("urun_kos_d0_under_test", "urun_kos.py")

_SAHTE_CONFIG = '''
import os
from pathlib import Path
def resolve_data_root():
    return Path(__file__).resolve().parent.parent, "package"
def resolve_sig_lmdb_path(config_path=None, data_root=None):
    return Path(data_root) / "signatures.lmdb", "data_root:signatures.lmdb"
'''


def _sahte_agac(kok: Path, meta: dict | None, config: str = _SAHTE_CONFIG) -> Path:
    """Ürün yerine geçen en küçük ağaç: ``karadul`` paketi (sürüm + çözücü) ve gerçek bir LMDB."""
    import lmdb
    (kok / "karadul").mkdir(parents=True)
    (kok / "karadul" / "__init__.py").write_text('__version__ = "9.9.9"\n')
    (kok / "karadul" / "config.py").write_text(config)
    if meta is not None:
        env = lmdb.open(str(kok / "signatures.lmdb"), max_dbs=8, subdir=True, map_size=1 << 20)
        db = env.open_db(b"meta")
        with env.begin(db=db, write=True) as txn:
            for k, v in meta.items():
                txn.put(k.encode(), v.encode())
        env.close()
    return kok


def test_imza_vt_kunyesi_urun_cozucusuyle(tmp_path):
    agac = _sahte_agac(tmp_path / "agac", {"schema_version": "2", "build_id": "s2-deneme"})
    k = uk.imza_vt_kunyesi(agac)
    assert k == {"yol": str((agac / "signatures.lmdb").resolve()), "kaynak": "data_root:signatures.lmdb",
                 "schema_version": "2", "build_id": "s2-deneme", "source_hash": None, "build_time": None,
                 "hata": None}
    # şema 1 (künyesiz) veritabanı: alan yok → None, uydurulmaz
    eski = _sahte_agac(tmp_path / "eski", {"build_id": "eski"})
    assert uk.imza_vt_kunyesi(eski)["schema_version"] is None
    # çözücüsü olmayan eski ürün: hata yazılır, alanlar None
    cozucusuz = _sahte_agac(tmp_path / "cozucusuz", None, config="X = 1\n")
    k = uk.imza_vt_kunyesi(cozucusuz)
    assert k["yol"] is None and k["schema_version"] is None and "ImportError" in k["hata"]


def test_agac_kunyesi_imzasi_ve_alanlari(tmp_path):
    """``agac_kunyesi(agac)`` imzası ve var olan alanlar aynı; yalnız ``imza_vt`` eklendi."""
    import inspect
    import subprocess
    assert list(inspect.signature(uk.agac_kunyesi).parameters) == ["agac"]
    agac = _sahte_agac(tmp_path / "agac", {"schema_version": "2"})
    for ad in uk.CALISMA_VERISI:
        if not (agac / ad).exists():
            (agac / ad).write_text("")
    git = ["git", "-C", str(agac), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(git[:3] + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "karadul"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "t"], check=True)
    k = uk.agac_kunyesi(agac)
    assert set(k) == {"agac", "commit", "kirli", "karadul_dosyasi", "karadul_surumu", "imza_vt"}
    assert k["karadul_surumu"] == "9.9.9" and k["kirli"] == [] and k["imza_vt"]["schema_version"] == "2"


def test_kosu_kunyesi_onbellek_ve_imza_vt_degisimi(tmp_path, monkeypatch):
    cagri = []

    def sahte_kunye(agac):
        cagri.append(agac)
        return {"agac": str(agac), "commit": "c", "kirli": [], "karadul_dosyasi": "k", "karadul_surumu": "s",
                "imza_vt": {"schema_version": "2" if len(cagri) == 1 else "1"}}
    monkeypatch.setattr(uk, "agac_kunyesi", sahte_kunye)
    monkeypatch.setattr(uk, "isleri_topla", lambda d, m: [])
    monkeypatch.setenv("KARADUL_CACHE_DIR", str(tmp_path / "onbellek"))
    kok = tmp_path / "kok"
    assert uk.main(["--agac", str(tmp_path), "--kok", str(kok)]) == 0
    k = json.loads((kok / "kosu_kunyesi.json").read_text(encoding="utf-8"))
    assert k["KARADUL_CACHE_DIR"] == str(tmp_path / "onbellek")
    assert k["agac"]["imza_vt"] == {"schema_version": "2"} and k["imza_vt_degisti"] is True
    assert k["agac_degisti"] is False                    # var olan alan: yalnız commit + kirli
    for alan in ("amac", "ghidra", "python", "komut", "PYTHONHASHSEED", "tabandaki_is", "bitmeyen"):
        assert alan in k
    # ortamda yoksa None (uydurulmaz); değişmeyen veritabanı → False
    cagri.clear()
    monkeypatch.delenv("KARADUL_CACHE_DIR")
    monkeypatch.setattr(uk, "agac_kunyesi", lambda agac: {"commit": "c", "kirli": [], "karadul_dosyasi": "k",
                                                          "imza_vt": {"x": 1}})
    assert uk.main(["--agac", str(tmp_path), "--kok", str(kok)]) == 0
    k = json.loads((kok / "kosu_kunyesi.json").read_text(encoding="utf-8"))
    assert k["KARADUL_CACHE_DIR"] is None and k["imza_vt_degisti"] is False
