"""Masum ikili kapısı (scripts/measurement/masum_kapi.py) — sayım kuralları.

Sentetik girdilerle: iddia çıkarımı, hüküm (yanlış / doğru bilinen / pozitif set), eşik,
gerçek pozitif, izlenen etiketler, çıktı kipi ayrıştırıcıları, yarım koşu. Ağır setler koşmaz;
tek gerçek örnek (macOS /usr/bin/true, packer + yara) varsa koşar.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "masum_kapi.py"
_spec = importlib.util.spec_from_file_location("masum_kapi_under_test", _PATH)
mk = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mk
_spec.loader.exec_module(mk)


def _kayit(anahtar, katman, *etiketler, **ek):
    return {"anahtar": anahtar, "katmanlar": {katman: {
        "durum": "calisti",
        "iddialar": [dict({"etiket": e, "kanit": ek.get("kanit", [])}, **ek.get("alan", {}))
                     for e in etiketler]}}}


# --------------------------------------------------------------------------------------------
# İddia çıkarımı
# --------------------------------------------------------------------------------------------
def test_bi_iddialari_dort_alan_ve_onek():
    rapor = {"architecture": {
        "algorithms": [{"name": "SHA-256", "evidence": ["sha256sum", "sha256sum"]}],
        "subsystems": [{"name": "Bluetooth", "evidence": ["_ITM_deregisterTMCloneTable"],
                        "confidence": 0.35}],
        "security": [{"name": "SIP (System Integrity)", "risk_level": "kernel", "evidence": ["siphash"]}],
        "protocols": [{"name": "IPsec", "evidence": ["like"]}]}}
    iddialar = mk.bi_iddialari(rapor)
    assert [i["etiket"] for i in iddialar] == [
        "algoritma:SHA-256", "altsistem:Bluetooth", "guvenlik:SIP (System Integrity)", "protokol:IPsec"]
    assert iddialar[0]["kanit"] == ["sha256sum"]          # yinelenen kanıt bir kez
    assert iddialar[2]["risk"] == "kernel"


def test_antidebug_seviye_esikleri_ve_teknik_tekilligi():
    veri = {"findings": [
        {"technique": "RDTSC_Timing", "confidence": 0.30, "evidence": "a", "category": "timing"},
        {"technique": "RDTSC_Timing", "confidence": 0.45, "evidence": "b", "category": "timing"},
        {"technique": "sysctl_kinfo_proc", "confidence": 0.55, "evidence": "c", "category": "macos"}],
        "summary": {"anti_debug_score": 0.7}}
    iddialar = mk.antidebug_iddialari(veri)
    assert [i["etiket"] for i in iddialar] == ["teknik:RDTSC_Timing", "teknik:sysctl_kinfo_proc"]
    assert iddialar[0]["guven"] == 0.45 and iddialar[0]["kanit"] == "b"
    assert iddialar[0]["rapor_seviyesi"] == "HIGH"
    assert mk._anti_debug_seviye(0.69) == "MED"
    assert mk._anti_debug_seviye(0.4) == "MED"
    assert mk._anti_debug_seviye(0.39) == "INFO"
    assert mk.antidebug_iddialari({"findings": [], "summary": {}}) == []


def test_packer_sarif_duzeyi():
    iddialar = mk.packer_iddialari({"fingerprints": [
        {"packer_name": "UPX", "confidence": 0.95}, {"packer_name": "FSG", "confidence": 0.30},
        {"packer_name": "X", "confidence": 0.4}]})
    assert [(i["etiket"], i["sarif"]) for i in iddialar] == [
        ("paketleyici:UPX", "error"), ("paketleyici:FSG", "note"), ("paketleyici:X", "warning")]
    assert mk._sarif_packer_duzeyi(0.7) == "error"


# --------------------------------------------------------------------------------------------
# Hüküm ve özet
# --------------------------------------------------------------------------------------------
ESIK = {"dogru_iddialar": [
    {"katman": "bi", "ikili": ["debian/openssl/*"], "etiket_re": "^algoritma:AES$"},
    {"katman": "bi", "etiket_re": "^guvenlik:Stack Protection$", "kanit_re": "__stack_chk_fail"},
    {"katman": "yara", "set": "pe", "etiket_re": "^kural:MSVC_Compiler$"}]}


def _hukumlu(kayitlar):
    mk.hukumle(kayitlar, ESIK)
    return {(s, k["anahtar"], i["etiket"]): i["hukum"] for s, l in kayitlar.items() for k in l
            for ks in k["katmanlar"].values() for i in ks["iddialar"]}


def test_hukum_masum_set_yanlis_dogru_listesi_ve_pozitif_set():
    h = _hukumlu({
        "gelistirme": [_kayit("debian/openssl/openssl", "bi", "algoritma:AES", "altsistem:Bluetooth"),
                       _kayit("debian/coreutils/true", "bi", "algoritma:AES")],
        "pozitif": [_kayit("libcrypto", "bi", "altsistem:Bluetooth")]})
    assert h[("gelistirme", "debian/openssl/openssl", "algoritma:AES")] == "dogru_bilinen"
    assert h[("gelistirme", "debian/openssl/openssl", "altsistem:Bluetooth")] == "yanlis"
    assert h[("gelistirme", "debian/coreutils/true", "algoritma:AES")] == "yanlis"   # ikili deseni
    assert h[("pozitif", "libcrypto", "altsistem:Bluetooth")] == "pozitif_set"


def test_hukum_kanit_re_ve_set_kisiti():
    k1 = _kayit("a", "bi", "guvenlik:Stack Protection", kanit=["__stack_chk_fail"])
    k2 = _kayit("b", "bi", "guvenlik:Stack Protection", kanit=["stack protector metni"])
    k3 = _kayit("c", "yara", "kural:MSVC_Compiler")
    h = _hukumlu({"macos": [k1, k2, k3]})
    assert h[("macos", "a", "guvenlik:Stack Protection")] == "dogru_bilinen"
    assert h[("macos", "b", "guvenlik:Stack Protection")] == "yanlis"
    assert h[("macos", "c", "kural:MSVC_Compiler")] == "yanlis"   # kural yalnız pe setinde


def test_hukum_cikti_katmani_esine_uyar():
    h = _hukumlu({"gelistirme": [_kayit("debian/openssl/openssl", "intel", "algoritma:AES")]})
    assert h[("gelistirme", "debian/openssl/openssl", "algoritma:AES")] == "dogru_bilinen"


def test_ozet_sayaclari_ve_adet():
    k = _kayit("x", "algoritma_kod", "algoritma:Galois", "algoritma:AES",
               alan={"adet": 4})
    kayitlar = {"gelistirme": [k, _kayit("y", "algoritma_kod")]}
    mk.hukumle(kayitlar, {})
    o = mk.ozetle(kayitlar)["algoritma_kod"]["gelistirme"]
    assert (o["ikili"], o["iddia"], o["yanlis"], o["yanlis_ikili"]) == (2, 2, 2, 1)
    assert o["adet"] == 8 and o["yanlis_adet"] == 8
    assert o["ikili_basina_yanlis"] == {"x": 2, "y": 0}
    assert o["etiket"] == {"algoritma:AES": 1, "algoritma:Galois": 1}


# --------------------------------------------------------------------------------------------
# Eşik, gerçek pozitif, kapı hükmü
# --------------------------------------------------------------------------------------------
def _ozet(ibs, set_adi="gelistirme", katman="bi"):
    return {katman: {set_adi: {"yanlis": sum(ibs.values()), "ikili_basina_yanlis": ibs}}}


def test_esik_icinde_asildi_ve_esiksiz_ikili():
    esik = {"esikler": {"dogrudan": {"bi": {"gelistirme": {"ikililer": {"a": 2, "b": 1}}}}}}
    e = mk.esigi_sina(_ozet({"a": 2, "b": 1}), esik, "dogrudan")[0]
    assert (e["sonuc"], e["yanlis"], e["ust"]) == ("icinde", 3, 3)
    e = mk.esigi_sina(_ozet({"a": 1, "b": 3}), esik, "dogrudan")[0]
    assert (e["sonuc"], e["artan_ikili"]) == ("asildi", ["b"])
    e = mk.esigi_sina(_ozet({"a": 2, "c": 9}), esik, "dogrudan")[0]
    assert (e["sonuc"], e["ust"], e["esiksiz_ikili"], e["esiksiz_yanlis"]) == ("icinde", 2, 1, 9)
    assert mk.esigi_sina(_ozet({"a": 5}, "pozitif"), esik, "dogrudan") == []
    assert mk.esigi_sina(_ozet({"a": 5}), {}, "dogrudan")[0]["sonuc"] == "esik_yok"


def test_gercek_pozitif_var_yok_olculmedi_ve_es_katman():
    esik = {"gercek_pozitifler": [
        {"set": "pozitif", "ikili": "upx", "katman": "packer", "etiket_re": "^paketleyici:UPX$", "zorunlu": True},
        {"set": "pozitif", "ikili": "upx", "katman": "yara", "etiket_re": "^kural:UPX_Packed$", "zorunlu": True},
        {"set": "macos", "ikili": "/bin/ls", "katman": "bi", "etiket_re": "x", "zorunlu": True},
        {"set": "gelistirme", "ikili": "o", "katman": "bi", "etiket_re": "^algoritma:AES$", "zorunlu": True}]}
    kayitlar = {"pozitif": [{"anahtar": "upx", "katmanlar": {
        "packer": {"iddialar": [{"etiket": "paketleyici:UPX"}]},
        "yara": {"iddialar": [{"etiket": "kural:Zlib_Library"}]}}}],
        "gelistirme": [_kayit("o", "intel", "algoritma:AES")]}
    s = mk.gercek_pozitifleri_sina(kayitlar, esik)
    assert [g["sonuc"] for g in s] == ["var", "yok", "olculmedi", "var"]
    assert s[3]["olculen_katman"] == "intel"
    c = {"esik_sinamasi": [], "gercek_pozitifler": s, "girdi_hatalari": []}
    hukum = mk.kapi_hukmu(c)
    assert hukum["cikis_kodu"] == 1 and len(hukum["nedenler"]) == 1   # yalnız "yok" düşürür
    c["gercek_pozitifler"] = [g for g in s if g["sonuc"] != "yok"]
    assert mk.kapi_hukmu(c)["cikis_kodu"] == 0
    c["girdi_hatalari"] = [("x", "girdi değişmiş")]
    assert mk.kapi_hukmu(c)["cikis_kodu"] == 1


def test_kapi_esik_asilinca_duser():
    c = {"esik_sinamasi": [{"katman": "bi", "set": "pe", "sonuc": "asildi", "yanlis": 3, "ust": 2}],
         "gercek_pozitifler": [], "girdi_hatalari": []}
    assert mk.kapi_hukmu(c)["cikis_kodu"] == 1


def test_izlenen_ikili_ve_adet_yalniz_masum_setler():
    esik = {"izlenen_yanlislar": [
        {"ad": "bt", "katman": "bi", "etiket_re": "^altsistem:Bluetooth$"},
        {"ad": "g", "katman": "algoritma_kod", "etiket_re": "Galois", "ikili": ["debian/*"]}]}
    kayitlar = {
        "gelistirme": [_kayit("debian/a", "bi", "altsistem:Bluetooth"), _kayit("debian/b", "bi"),
                       _kayit("debian/c", "algoritma_kod", "algoritma:Galois", alan={"adet": 5}),
                       _kayit("mac/d", "algoritma_kod", "algoritma:Galois", alan={"adet": 7})],
        "pozitif": [_kayit("p", "bi", "altsistem:Bluetooth")]}
    s = {(z["ad"], z["set"]): z for z in mk.izlenenleri_say(kayitlar, esik)}
    assert (s[("bt", "gelistirme")]["ikili"], s[("bt", "gelistirme")]["olculen"]) == (1, 2)
    assert ("bt", "pozitif") not in s
    assert (s[("g", "gelistirme")]["ikili"], s[("g", "gelistirme")]["adet"]) == (1, 5)


def test_izlenen_cikti_esini_de_sayar():
    esik = {"izlenen_yanlislar": [{"ad": "bt", "katman": "bi", "etiket_re": "Bluetooth"}]}
    s = mk.izlenenleri_say({"gelistirme": [_kayit("a", "intel", "altsistem:Bluetooth")]}, esik)
    assert [(z["katman"], z["ikili"]) for z in s] == [("intel", 1)]


def test_karsilastir_fark_ve_etiket_degisimi():
    once = {"ozet": {"bi": {"gelistirme": {"yanlis": 5, "iddia": 6, "ikili": 2,
                                            "etiket": {"altsistem:Bluetooth": 2, "a": 1}}}}}
    sonra = {"ozet": {"bi": {"gelistirme": {"yanlis": 1, "iddia": 2, "ikili": 2,
                                             "etiket": {"a": 1, "b": 1}}}}}
    k = mk.karsilastir(sonra, once)[0]
    assert k["yanlis"] == [5, 1] and k["iddia"] == [6, 2]
    assert k["etiket_degisimi"] == {"altsistem:Bluetooth": [2, 0], "b": [0, 1]}


def test_esik_yaz_birlestirir(tmp_path):
    esik = tmp_path / "esik.json"
    esik.write_text(json.dumps({"dogru_iddialar": [{"etiket_re": "x"}]}), encoding="utf-8")

    def cikti(ad, ibs, commit):
        p = tmp_path / ad
        p.write_text(json.dumps({"kip": "cikti", "agac": {"commit": commit}, "bitis": "t",
                                 "ozet": {"bi": {"gelistirme": {"yanlis": sum(ibs.values()), "ikili": len(ibs),
                                                                "ikili_basina_yanlis": ibs}},
                                          "packer": {"pozitif": {"yanlis": 0, "ikili": 1,
                                                                 "ikili_basina_yanlis": {"u": 0}}}}}),
                     encoding="utf-8")
        return p
    mk.esik_yaz([cikti("a.json", {"x": 3, "y": 1}, "aaaa")], esik)
    mk.esik_yaz([cikti("b.json", {"y": 0, "z": 2}, "bbbb")], esik)
    e = json.loads(esik.read_text(encoding="utf-8"))
    yer = e["esikler"]["cikti"]["bi"]["gelistirme"]
    assert yer["ikililer"] == {"x": 3, "y": 0, "z": 2} and yer["yanlis_toplam"] == 5
    assert len(yer["kaynaklar"]) == 2
    assert "packer" not in e["esikler"]["cikti"]           # pozitif set eşiğe yazılmaz
    assert e["dogru_iddialar"] == [{"etiket_re": "x"}]       # elle yazılan bölüm korunur


# --------------------------------------------------------------------------------------------
# Çıktı kipi ayrıştırıcıları
# --------------------------------------------------------------------------------------------
RAPOR_MD = """# Black Widow Analysis Report -- x

## Deep Algorithm Analysis

### Algorithm Compositions (3 detected)

- **Matrix Solve Pipeline** (pipeline, confidence: 48%)
  - Stages: Allocate -> Factor -> Free

- **FUN_001 -> SSL_read Pipeline** (pipeline, confidence: 30%)

- **VPN Tunnel Setup Pipeline** (pipeline, confidence: 26%)

### Call Chain Traces (3 targets, 9 nodes)

- **Not A Composition** (pipeline, confidence: 99%)

## Artifacts
"""

C_DOSYA = """/**
 * @algorithm Galois field operations (ECC, AES-GF) (asymmetric, confidence: 55%)
 * @security Handles sensitive key material
 * @security Code injection/hooking mechanism
 */
void f(void) {
    /* ALGORITHM: Galois field operations (ECC, AES-GF) (confidence: 55%, via structural) */
    // --- Row-major matrix access: a[i*2 + 1] ---
}
/**
 * @algorithm Galois field operations (ECC, AES-GF) (asymmetric, confidence: 40%)
 */
void g(void) { }
"""


def _ws_out(tmp_path):
    ws, out = tmp_path / "ws", tmp_path / "out"
    (ws / "reports").mkdir(parents=True)
    (ws / "static").mkdir()
    (ws / "reconstructed").mkdir()
    (out / "src/src/a").mkdir(parents=True)
    (out / "src/include").mkdir()
    return ws, out


def test_cikti_bilesim_yalniz_sablonlar_ve_bolum_siniri(tmp_path):
    ws, out = _ws_out(tmp_path)
    (ws / "reports/report.md").write_text(RAPOR_MD, encoding="utf-8")
    s = mk.cikti_bilesim(ws, out, {"Matrix Solve Pipeline", "VPN Tunnel Setup Pipeline",
                                   "Not A Composition"})
    assert [i["etiket"] for i in s["iddialar"]] == ["sablon:Matrix Solve Pipeline",
                                                    "sablon:VPN Tunnel Setup Pipeline"]
    assert s["genel_desen"] == 1 and s["iddialar"][0]["guven"] == 48
    assert mk.cikti_bilesim(tmp_path / "yok", out, set())["durum"] == "yapit_yok"


def test_cikti_kod_etiketleri(tmp_path):
    ws, out = _ws_out(tmp_path)
    (out / "src/src/a/f.c").write_text(C_DOSYA, encoding="utf-8")
    alg = mk.cikti_algoritma_kod(ws, out, set())["iddialar"]
    assert [(i["etiket"], i["adet"]) for i in alg] == [
        ("algoritma:Galois field operations (ECC, AES-GF)", 2)]
    sec = {i["etiket"]: i["adet"] for i in mk.cikti_security_etiketi(ws, out, set())["iddialar"]}
    assert sec == {"security:Code injection/hooking mechanism": 1,
                   "security:Handles sensitive key material": 1}
    blok = mk.cikti_blok_yorumu(ws, out, set())["iddialar"]
    assert [(i["etiket"], i["adet"]) for i in blok] == [("blok:Row-major matrix access", 1)]


def test_cikti_types_h_ve_algoritma_json(tmp_path):
    ws, out = _ws_out(tmp_path)
    (out / "src/include/types.h").write_text(
        "typedef struct recovered_struct_001 recovered_struct_001;\n"
        "struct recovered_struct_001 {\n int a;\n};\nstruct recovered_struct_002 {\n};\n",
        encoding="utf-8")
    t = mk.cikti_types_h(ws, out, set())["iddialar"]
    assert [(i["etiket"], i["adet"]) for i in t] == [("yapi:recovered_struct", 2)]
    (ws / "reconstructed/algorithms.json").write_text(json.dumps({"algorithms": [
        {"name": "G", "function": "f", "evidence": ["galois_field: matched 'mode'"]},
        {"name": "G", "function": "g", "evidence": ["constant"]}]}), encoding="utf-8")
    a = mk.cikti_algoritma_json(ws, out, set())["iddialar"]
    assert [(i["etiket"], i["adet"], i["yapisal"]) for i in a] == [("algoritma:G", 2, 1)]


def test_cikti_sarif_ve_yara_durumu(tmp_path):
    ws, out = _ws_out(tmp_path)
    (ws / "reports/report.sarif.json").write_text(json.dumps({"runs": [{"results": [
        {"ruleId": "KRDL003", "level": "warning", "message": {"text": "Teknoloji"},
         "properties": {"technology_name": "MPRESS_Packed (packer,mpress)"}},
        {"ruleId": "KRDL003", "level": "warning", "message": {"text": "Teknoloji"},
         "properties": {"technology_name": "MPRESS_Packed (packer,mpress)"}},
        {"ruleId": "KRDL004", "level": "error", "message": {"text": "p"},
         "properties": {"packer_name": "UPX"}}]}]}), encoding="utf-8")
    s = {i["etiket"]: (i["adet"], i["duzey"]) for i in mk.cikti_sarif(ws, out, set())["iddialar"]}
    assert s == {"KRDL003:MPRESS_Packed": (2, "warning"), "KRDL004:UPX": (1, "error")}
    pr = {"stages": {"static": {"stats": {"detected_tech": ["MPRESS_Packed (packer,mpress)"]}}}}
    (ws / "reports/pipeline_result.json").write_text(json.dumps(pr), encoding="utf-8")
    y = mk.cikti_yara(ws, out, set())
    assert y["durum"] == "bilinmiyor" and [i["etiket"] for i in y["iddialar"]] == ["kural:MPRESS_Packed"]
    pr["stages"]["static"]["stats"]["yara_backend"] = "yara-python"
    (ws / "reports/pipeline_result.json").write_text(json.dumps(pr), encoding="utf-8")
    assert mk.cikti_yara(ws, out, set())["durum"] == "calisti"


def _kosu(kok, anahtar, bitti=True):
    d = kok / anahtar
    (d / "ws/workspaces/x/20261110_000000/reports").mkdir(parents=True)
    (d / "out").mkdir()
    if bitti:
        (d / "BITTI").write_text("0\n", encoding="utf-8")


def test_cikti_kos_yarim_kosu_hatasi(tmp_path, monkeypatch):
    monkeypatch.setattr(mk, "_bilesim_sablonlari", lambda: set())
    _kosu(tmp_path, "debian/p/a")
    _kosu(tmp_path, "mac/b", bitti=False)
    (tmp_path / "kosu_kunyesi.json").write_text(json.dumps({"secilen_is": 3}), encoding="utf-8")
    kayitlar, hatalar, bilgi = mk.cikti_kos(tmp_path, "gelistirme", ["bilesim"])
    assert [k["anahtar"] for k in kayitlar["gelistirme"]] == ["debian/p/a", "mac/b"]
    nedenler = [h for _, h in hatalar]
    assert any("künyede 3 iş" in n for n in nedenler)
    assert any("BITTI yok" in n for n in nedenler)
    assert bilgi["ikili"] == 2


# --------------------------------------------------------------------------------------------
# Ağaç denetimi ve tek gerçek örnek
# --------------------------------------------------------------------------------------------
def test_yanlis_agac_durur(tmp_path):
    with pytest.raises(SystemExit):
        mk.agaci_yukle(tmp_path)


@pytest.mark.skipif(not Path("/usr/bin/true").is_file(), reason="macOS /usr/bin/true yok")
def test_gercek_ornek_true_packer_yara(tmp_path):
    pytest.importorskip("yara")
    girdi = {"anahtar": "/usr/bin/true", "yol": "/usr/bin/true"}
    k = mk.ikili_olc(girdi, ["packer", "yara"], str(tmp_path))
    assert k["hedef_turu"] in ("universal_binary", "macho_binary")
    assert k["katmanlar"]["packer"]["durum"] == "calisti"
    assert k["katmanlar"]["yara"]["durum"] == "calisti"
    assert all(i["etiket"].startswith("kural:") for i in k["katmanlar"]["yara"]["iddialar"])
    girdi["sha256"] = "0" * 64
    assert "girdi değişmiş" in mk.ikili_olc(girdi, ["packer"], str(tmp_path))["hata"]
