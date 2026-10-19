"""scripts/measurement/dogrulama_seti_kura.py — doğrulama seti kurasının birim testleri.

Kurallar (plan v2 G5, ön kayıt: docs/arge/dogrulama_seti_onkayit.md):
  - Testler gerçek havuz ve gerçek tohumla KURA ÇEKMEZ. Çekimler sentetik havuz ve
    sentetik tohumla yapılır; bir koruma, gerçek havuz ya da tohumla `draw` çağrısını
    test sırasında engeller.
  - Gerçek havuz için yalnız yapısal denetim yapılır: dışlama listeleriyle kesişim,
    tabaka büyüklükleri, alan sayıları, eşiklerin test setini 6/6/3 bölmesi.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import random
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "dogrulama_seti_kura.py"
_spec = importlib.util.spec_from_file_location("dogrulama_seti_kura_under_test", _PATH)
kura = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = kura
_spec.loader.exec_module(kura)

_ORIG_DRAW = kura.draw  # koruma fikstüründen önceki gerçek işlevler (imza denetimi için)
_ORIG_STRESS = kura.stress_draw
_KANIT = Path(__file__).resolve().parents[1] / "docs" / "arge" / "dogrulama_seti_kanit"

STRATA = ("kucuk", "orta", "buyuk")
TOHUM = "sentetik-tohum-yalniz-test"
KOTA = {"kucuk": 4, "orta": 4, "buyuk": 2}
K, O, B = 400, 2000, 20000  # sentetik vekiller: küçük, orta, büyük tabakaya düşer


@pytest.fixture(autouse=True)
def _gercek_kura_yasak(monkeypatch):
    """Gerçek havuz, gerçek işaretli liste ya da gerçek tohumla kura çekilirse testi düşür."""
    orig_draw, orig_stress = kura.draw, kura.stress_draw

    def guarded(pool, seed_text, quota):
        assert pool is not kura.VALIDATION_POOL, "gerçek havuzla kura testte çekilemez"
        assert seed_text != kura.VALIDATION_SEED_TEXT, "gerçek tohumla kura testte çekilemez"
        return orig_draw(pool, seed_text, quota)

    def guarded_stress(flagged, seed_text, k):
        assert flagged is not kura.FLAGGED, "gerçek işaretli listeyle stres kurası testte çekilemez"
        assert seed_text != kura.VALIDATION_SEED_TEXT, "gerçek tohumla stres kurası testte çekilemez"
        return orig_stress(flagged, seed_text, k)

    monkeypatch.setattr(kura, "draw", guarded)
    monkeypatch.setattr(kura, "stress_draw", guarded_stress)


def _pool_genis() -> dict:
    """Alan kısıtının sıkı hâliyle doldurulabilen havuz (16 alan)."""
    return {
        "b1": ("A", "fb1", B), "b2": ("B", "fb2", B), "b3": ("C", "fb3", B), "b4": ("A", "fb4", B),
        "o1": ("A", "fo1", O), "o2": ("B", "fo2", O), "o3": ("D", "fo3", O), "o4": ("E", "fo4", O),
        "o5": ("F", "fo5", O), "o6": ("G", "fo6", O), "o7": ("C", "fo7", O), "o8": ("H", "fo8", O),
        "k1": ("A", "fk1", K), "k2": ("I", "fk2", K), "k3": ("J", "fk3", K), "k4": ("K", "fk4", K),
        "k5": ("L", "fk5", K), "k6": ("M", "fk6", K), "k7": ("D", "fk7", K), "k8": ("N", "fk8", K),
        "k9": ("O", "fo1", K), "k10": ("P", "fk10", K),
    }


def _all(result: dict) -> list[str]:
    return [p for s in STRATA for p in result["ana_kume"][s]]


def _expected_perms(pool: dict, seed_text: str) -> dict:
    rng = random.Random(int(hashlib.sha256(seed_text.encode()).hexdigest()[:16], 16))
    out = {}
    for s in STRATA:
        m = sorted(p for p, v in pool.items() if kura.stratum_of(v[2]) == s)
        rng.shuffle(m)
        out[s] = m
    return out


# ---------------------------------------------------------------- tohum ve eşikler

def test_seed_from_text_ilk_16_hex():
    beklenen = int(hashlib.sha256(TOHUM.encode()).hexdigest()[:16], 16)
    assert kura.seed_from_text(TOHUM) == beklenen


def test_on_kayitli_tohum_metni_ve_degeri():
    # Kura değil: yalnız ön kayıt belgesindeki tohum metninin ve sayısının tutarlılığı.
    assert kura.VALIDATION_SEED_TEXT == "karadul-dogrulama-seti-kura-2026-10-19"
    assert kura.seed_from_text(kura.VALIDATION_SEED_TEXT) == 6938462450958974163


def test_esikler_test_setini_6_6_3_boler():
    s = sorted(kura.TEST_SET_PROXY_KIB.values())
    assert kura.T1 == (s[5] + s[6]) / 2 == 1086.0
    assert kura.T2 == (s[11] + s[12]) / 2 == 9033.5
    assert (kura.LOWER, kura.UPPER) == (s[0], s[-1]) == (309, 70029)
    say = Counter(kura.stratum_of(v) for v in kura.TEST_SET_PROXY_KIB.values())
    assert say == Counter({"kucuk": 6, "orta": 6, "buyuk": 3})


def test_tabaka_sinirlari():
    assert kura.stratum_of(kura.T1 - 0.5) == "kucuk"
    assert kura.stratum_of(kura.T1) == "orta"
    assert kura.stratum_of(kura.T2) == "orta"
    assert kura.stratum_of(kura.T2 + 0.5) == "buyuk"


def test_kota_test_setiyle_orantili():
    assert kura.TEST_SET_QUOTA == {"kucuk": 6, "orta": 6, "buyuk": 3}
    assert kura.VALIDATION_QUOTA == {"kucuk": 4, "orta": 4, "buyuk": 2}
    assert sum(kura.VALIDATION_QUOTA.values()) == kura.VALIDATION_SIZE == 10


def test_esik_vekilleri_test_setinin_15_ana_programi():
    # Test setinin kurası kilit belgesinde yayımlı; burada yalnız aynı listeyi yeniden üretiriz.
    ana = kura._TEST_KURA.draw()["ana_kume"]
    assert set(kura.TEST_SET_PROXY_KIB) == set(ana)


def test_draw_varsayilan_parametre_almaz():
    # Havuz, tohum ve kota açıkça verilmeden kura çekilemesin (yanlışlıkla gerçek kura yok).
    sig = inspect.signature(_ORIG_DRAW)
    for name in ("pool", "seed_text", "quota"):
        assert sig.parameters[name].default is inspect.Parameter.empty
    sig = inspect.signature(_ORIG_STRESS)
    for name in ("flagged", "seed_text", "k"):
        assert sig.parameters[name].default is inspect.Parameter.empty


# ---------------------------------------------------------------- kura (sentetik)

def test_kura_belirlenimci():
    pool = _pool_genis()
    assert kura.draw(pool, TOHUM, KOTA) == kura.draw(pool, TOHUM, KOTA)


def test_kura_tohuma_bagli():
    pool = _pool_genis()
    sonuclar = {str(kura.draw(pool, f"{TOHUM}-{i}", KOTA)["siralar"]) for i in range(6)}
    assert len(sonuclar) > 1


def test_siralar_alfabetik_karistirma_ve_uretec_sirasi():
    pool = _pool_genis()
    for i in range(5):
        t = f"{TOHUM}-{i}"
        assert kura.draw(pool, t, KOTA)["siralar"] == _expected_perms(pool, t)


def test_tabaka_kotalari_dolu():
    pool = _pool_genis()
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        assert {s: len(r["ana_kume"][s]) for s in STRATA} == KOTA
        assert r["eksik"] == {}


def test_alan_ve_aile_tekil():
    pool = _pool_genis()
    for i in range(20):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        secilen = _all(r)
        assert len(secilen) == len(set(secilen)) == 10
        assert len({pool[p][1] for p in secilen}) == 10, "aile tekrar etti"
        assert len({pool[p][0] for p in secilen}) == 10, "alan tekrar etti"
        assert r["notlar"] == []
        for s in STRATA:  # sıkı doldurulabilen havuzda herkes kendi tabakasından
            assert all(kura.stratum_of(pool[p][2]) == s for p in r["ana_kume"][s])


def test_secim_buyukten_baslar():
    # Büyük tabakada tam 2 aday var; ikisi de her tohumda seçilir. Alanlarını taşıyan orta
    # adaylar (oX, oY) bu yüzden hiçbir tohumda seçilmemeli.
    pool = {"b1": ("X", "f1", B), "b2": ("Y", "f2", B),
            "oX": ("X", "f3", O), "oY": ("Y", "f4", O)}
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 7)})
    pool.update({f"k{i}": (f"E{i}", f"h{i}", K) for i in range(1, 7)})
    for i in range(30):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        assert sorted(r["ana_kume"]["buyuk"]) == ["b1", "b2"]
        assert "oX" not in r["ana_kume"]["orta"] and "oY" not in r["ana_kume"]["orta"]


def test_alan_kisiti_gerekirse_gevser_aile_kisiti_gevsemez():
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}
    pool.update({f"o{i}": (dom, f"g{i}", O) for i, dom in enumerate("CDEF", 1)})
    pool.update({"k1": ("A", "h1", K), "k2": ("B", "h2", K), "k3": ("C", "h3", K),
                 "k4": ("A", "h4", K), "k5": ("C", "f1", K)})  # k5'in ailesi b1'inkiyle aynı
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        assert len(r["ana_kume"]["kucuk"]) == 4
        assert "k5" not in r["ana_kume"]["kucuk"]
        gevsek = [n for n in r["notlar"] if n["neden"] == "alan kısıtı gevşetildi"]
        assert len(gevsek) == 4
        assert len({pool[p][1] for p in _all(r)}) == 10


def test_aile_tukenirse_komsu_tabakadan_doldurulur():
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 9)})
    pool.update({f"k{i}": (f"E{i}", "ortak", K) for i in range(1, 7)})  # hepsi aynı aile
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        kucuk = r["ana_kume"]["kucuk"]
        assert len(kucuk) == 4
        assert sum(p.startswith("k") for p in kucuk) == 1
        komsu = [n for n in r["notlar"] if n["neden"] == "komşu tabakadan (orta)"]
        assert len(komsu) == 3
        assert r["eksik"] == {}


def test_yedek_sirasi_karisik_siradan_secilmeyenler():
    pool = _pool_genis()
    for i in range(5):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        secilen = set(_all(r))
        for s in STRATA:
            assert r["yedek_sirasi"][s] == [p for p in r["siralar"][s] if p not in secilen]
            assert set(r["yedek_sirasi"][s]) | set(r["ana_kume"][s]) == set(r["siralar"][s])


# ---------------------------------------------------------------- değişim kuralı

def _beklenen_yedek(pool, r, s, cikan):
    kalan = [p for p in _all(r) if p != cikan]
    dom = {pool[p][0] for p in kalan}
    fam = {pool[p][1] for p in kalan}
    for p in r["yedek_sirasi"][s]:
        if pool[p][0] not in dom and pool[p][1] not in fam:
            return p
    return None


def test_kosulamayan_yerine_ilk_uygun_yedek_gelir_digerleri_kalir():
    pool = _pool_genis()
    denenen = 0
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        for s in STRATA:
            cikan = r["ana_kume"][s][0]
            beklenen = _beklenen_yedek(pool, r, s, cikan)
            if beklenen is None:  # sıkı aday yoksa gevşetme devreye girer; ayrı testte
                continue
            denenen += 1
            r2 = kura.replace_failed(r, pool, [cikan])
            assert r2["degisimler"] == [{"cikan": cikan, "giren": beklenen, "tabaka": s, "notlar": []}]
            for t in STRATA:
                eski = [p for p in r["ana_kume"][t] if p != cikan]
                assert eski == [p for p in r2["ana_kume"][t] if p != beklenen]
            assert sorted(r2["ana_kume"][s]) == sorted([p for p in r["ana_kume"][s] if p != cikan] + [beklenen])
    assert denenen >= 20


def _elle_sonuc(siralar: dict, ana_kume: dict) -> dict:
    """Kurayı atlayıp `replace_failed` için sonuç sözlüğü kurar (sıra elle verilir)."""
    secilen = {p for s in STRATA for p in ana_kume[s]}
    return {"siralar": siralar, "ana_kume": ana_kume, "kota": dict(KOTA),
            "yedek_sirasi": {s: [p for p in siralar[s] if p not in secilen] for s in STRATA}}


def _elle_havuz() -> dict:
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 5)})
    pool.update({"k1": ("E1", "h1", K), "k2": ("E2", "h2", K), "k3": ("E3", "h3", K),
                 "k4": ("E4", "h4", K), "k5": ("E5", "h5", K), "k6": ("E6", "h6", K),
                 "k7": ("E5", "h7", K), "k8": ("E2", "h8", K)})
    return pool


def _elle_kura() -> dict:
    return _elle_sonuc(
        {"buyuk": ["b1", "b2"], "orta": ["o1", "o2", "o3", "o4"],
         "kucuk": ["k1", "k2", "k3", "k4", "k8", "k7", "k5", "k6"]},
        {"buyuk": ["b1", "b2"], "orta": ["o1", "o2", "o3", "o4"], "kucuk": ["k1", "k2", "k3", "k4"]},
    )


def test_degisim_yedek_sirasindaki_ilk_uygun_programi_alir():
    pool, r = _elle_havuz(), _elle_kura()
    # k1 çıkınca sıradaki k8 (E2) kalan k2 ile aynı alanda: atlanır; k7 (E5) gelir.
    r2 = kura.replace_failed(r, pool, ["k1"])
    assert r2["degisimler"][0]["giren"] == "k7"
    assert sorted(r2["ana_kume"]["kucuk"]) == ["k2", "k3", "k4", "k7"]
    assert r2["ana_kume"]["buyuk"] == ["b1", "b2"] and r2["ana_kume"]["orta"] == ["o1", "o2", "o3", "o4"]


def test_gelistirmeye_aktarilanin_alani_kullanilmis_sayilir_elle():
    pool, r = _elle_havuz(), _elle_kura()
    # k5 geliştirme setine aktarıldı: alanı E5 kullanılmış sayılır, k7 (E5) atlanır, k6 gelir.
    r2 = kura.replace_failed(r, pool, ["k1"], blocked=["k5"])
    assert r2["degisimler"][0]["giren"] == "k6"
    assert "k5" not in r2["ana_kume"]["kucuk"]


def test_cakisan_yedek_atlanir():
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 5)})
    pool.update({f"k{i}": (f"E{i}", f"h{i}", K) for i in range(1, 5)})
    pool.update({"k5": ("A", "h5", K), "k6": ("E9", "h6", K)})  # k5 b1 ile aynı alanda
    for i in range(20):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        cikan = r["ana_kume"]["kucuk"][0]
        r2 = kura.replace_failed(r, pool, [cikan])
        giren = r2["degisimler"][0]["giren"]
        assert giren != "k5"
        assert giren == _beklenen_yedek(pool, r, "kucuk", cikan)


def test_yedek_kosulamazsa_kume_degismez():
    pool = _pool_genis()
    r = kura.draw(pool, TOHUM, KOTA)
    yedek = r["yedek_sirasi"]["orta"][0]
    r2 = kura.replace_failed(r, pool, [yedek])
    assert r2["ana_kume"] == r["ana_kume"]
    assert r2["degisimler"] == []


def test_tabakada_yedek_yoksa_komsu_tabaka():
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}  # büyükte yedek yok
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 9)})
    pool.update({f"k{i}": (f"E{i}", f"h{i}", K) for i in range(1, 9)})
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        r2 = kura.replace_failed(r, pool, ["b1"])
        d = r2["degisimler"][0]
        assert d["giren"] == r["yedek_sirasi"]["orta"][0]
        assert d["notlar"] == [{"program": d["giren"], "tabaka": "buyuk", "neden": "komşu tabakadan (orta)"}]
        assert "b2" in r2["ana_kume"]["buyuk"] and "b1" not in r2["ana_kume"]["buyuk"]


def test_degisim_belirlenimci_ve_birikimli():
    pool = _pool_genis()
    r = kura.draw(pool, TOHUM, KOTA)
    a = r["ana_kume"]["kucuk"][0]
    r1 = kura.replace_failed(r, pool, [a])
    b = r1["degisimler"][0]["giren"]
    r2 = kura.replace_failed(r, pool, [a, b])  # giren de koşulamazsa sıradaki gelir
    assert r2 == kura.replace_failed(r, pool, [b, a])
    assert b not in _all(r2) and a not in _all(r2)
    assert len(r2["ana_kume"]["kucuk"]) == 4


# ---------------------------------------------------------------- geliştirme seti tamamlama

def test_gelistirme_tamamlama_korumali_yedekleri_ve_yakinlari_vermez():
    pool = _pool_genis()
    for i in range(10):
        r = kura.draw(pool, f"{TOHUM}-{i}", KOTA)
        sira = kura.dev_topup_order(r, pool)
        secilen = _all(r)
        dom = {pool[p][0] for p in secilen}
        fam = {pool[p][1] for p in secilen}
        korumali = {p for s in STRATA for p in r["yedek_sirasi"][s][:KOTA[s]]}
        assert not set(sira) & set(secilen)
        assert not set(sira) & korumali
        assert all(pool[p][0] not in dom and pool[p][1] not in fam for p in sira)
        assert len(sira) == len(set(sira))


def test_gelistirme_tamamlama_donusumlu_sira():
    pool = {"b1": ("A", "f1", B), "b2": ("B", "f2", B)}
    pool.update({f"o{i}": (f"D{i}", f"g{i}", O) for i in range(1, 11)})
    pool.update({f"k{i}": (f"E{i}", f"h{i}", K) for i in range(1, 11)})
    r = kura.draw(pool, TOHUM, KOTA)
    sira = kura.dev_topup_order(r, pool, floor={"kucuk": 1, "orta": 1, "buyuk": 0})
    kq = r["yedek_sirasi"]["kucuk"][1:]
    oq = r["yedek_sirasi"]["orta"][1:]
    beklenen = [x for pair in zip(kq, oq) for x in pair]
    assert sira[: len(beklenen)] == beklenen


# ---------------------------------------------------------------- havuz denetimi

def test_check_pool_disari_alinanlari_yakalar():
    with pytest.raises(ValueError, match="dışlanan"):
        kura.check_pool({"vim": ("editör", "vim", 500)}, excluded={"vim"})
    with pytest.raises(ValueError, match="işaretli program"):
        kura.check_pool({"sed": ("metin", "sed", 500)}, excluded=set(), flagged={"sed"})
    with pytest.raises(ValueError, match="aralığı dışında"):
        kura.check_pool({"x": ("a", "b", kura.LOWER - 1)}, excluded=set())
    with pytest.raises(ValueError, match="aralığı dışında"):
        kura.check_pool({"x": ("a", "b", kura.UPPER + 1)}, excluded=set())
    with pytest.raises(ValueError, match="boş"):
        kura.check_pool({"x": ("", "b", 500)}, excluded=set())


def test_gercek_havuz_dislama_kesisimi_bos():
    havuz = set(kura.VALIDATION_POOL)
    assert havuz.isdisjoint(kura.EXCLUDED)
    assert set(kura.FLAGGED).isdisjoint(kura.EXCLUDED)
    assert set(kura.FLAGGED).isdisjoint(havuz)
    for liste in (kura.TEST_SET_POOL_NAMES, kura.TEST_SET_STRESS, kura.CANDIDATES,
                  kura.DEV_SET, kura.LINEAGE, kura.NEAR_DEV):
        assert havuz.isdisjoint(liste)
    kura.check_pool(kura.VALIDATION_POOL, kura.EXCLUDED, kura.FLAGGED)


def test_dislama_listesi_test_setini_ve_stresi_kapsar():
    beklenen = {"unzip", "memcached", "dash", "dcraw", "gifsicle", "mawk", "dnsmasq", "gpg",
                "nasm", "rsync", "ssh", "zsh", "vim", "git", "haproxy",
                "ag", "less", "cmus", "tcpdump", "lynx",
                "wget", "nano", "screen", "lua", "pigz"}
    assert beklenen <= kura.EXCLUDED
    assert {"neovim", "valkey", "tmux", "htop", "coreutils", "redis", "sqlite3", "zstd",
            "openssl", "tree", "xxd", "zip", "yasm", "tmate"} <= kura.EXCLUDED


def test_gercek_havuz_tabaka_buyuklukleri_ve_alanlar():
    uyeler = {s: [p for p, v in kura.VALIDATION_POOL.items() if kura.stratum_of(v[2]) == s]
              for s in STRATA}
    assert {s: len(m) for s, m in uyeler.items()} == {"kucuk": 38, "orta": 23, "buyuk": 7}
    for s in STRATA:
        assert len(uyeler[s]) >= kura.VALIDATION_QUOTA[s] + 2, f"{s}: yedek az"
        alanlar = {kura.VALIDATION_POOL[p][0] for p in uyeler[s]}
        assert len(alanlar) >= kura.VALIDATION_QUOTA[s], f"{s}: alan sayısı kotadan az"
    tum_alanlar = {v[0] for v in kura.VALIDATION_POOL.values()}
    assert len(tum_alanlar) >= kura.VALIDATION_SIZE


# ---------------------------------------------------------------- kayıt denetimi

class _Cikti:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_kayit_denetimi_izlenmeyen_dosyada_reddeder():
    def run(cmd, **_):
        return _Cikti(1) if "ls-files" in cmd else _Cikti(0, "")
    ok, msg = kura.registration_check(["a", "b"], run=run)
    assert not ok and "izlenmiyor" in msg


def test_kayit_denetimi_degisiklikte_reddeder():
    def run(cmd, **_):
        return _Cikti(0, " M scripts/measurement/dogrulama_seti_kura.py\n" if "status" in cmd else "")
    ok, msg = kura.registration_check(["a"], run=run)
    assert not ok and "commit edilmemiş" in msg


def test_kayit_denetimi_temizse_gecer():
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw.get("cwd")))
        return _Cikti(0, "")
    ok, _ = kura.registration_check(["a", "b"], run=run)
    assert ok
    assert all(cwd == kura.REPO_ROOT for _, cwd in calls)
    assert any("status" in c and "--porcelain" in c for c, _ in calls)


def test_main_kayitsizken_kura_cekmez(monkeypatch, capsys):
    monkeypatch.setattr(kura, "registration_check", lambda paths, run=subprocess.run: (False, "deneme"))

    def yasak(*a, **k):
        raise AssertionError("kayıt yokken kura çekildi")
    monkeypatch.setattr(kura, "draw", yasak)
    assert kura.main([]) == 2
    assert "KURA ÇEKİLMEDİ" in capsys.readouterr().err


# ---------------------------------------------------------------- doğrulama stres alt kümesi

ISARETLI_SENTETIK = [f"s{i:02d}" for i in range(1, 14)]  # 13 sentetik ad


def _beklenen_stres(flagged, seed_text, k):
    alt = seed_text + "/stres"
    order = sorted(flagged)
    random.Random(int(hashlib.sha256(alt.encode()).hexdigest()[:16], 16)).shuffle(order)
    return alt, order[:k], order[k:]


def test_stres_alt_tohumu_ana_tohumdan_turetilir():
    assert kura.stress_seed_text(TOHUM) == TOHUM + "/stres"
    # Kura değil: ön kayıt belgesindeki alt tohum değerinin tutarlılığı.
    alt = kura.stress_seed_text(kura.VALIDATION_SEED_TEXT)
    assert alt == "karadul-dogrulama-seti-kura-2026-10-19/stres"
    assert kura.seed_from_text(alt) == 1099394289718775035
    assert kura.seed_from_text(alt) != kura.seed_from_text(kura.VALIDATION_SEED_TEXT)


def test_stres_cekimi_bes_program_ve_belirlenimci():
    assert kura.STRESS_SIZE == 5
    for i in range(6):
        t = f"{TOHUM}-{i}"
        r = kura.stress_draw(ISARETLI_SENTETIK, t, kura.STRESS_SIZE)
        alt, kume, yedek = _beklenen_stres(ISARETLI_SENTETIK, t, 5)
        assert r["alt_tohum_metni"] == alt
        assert r["kume"] == kume and r["yedek_sirasi"] == yedek
        assert len(r["kume"]) == 5 and len(r["yedek_sirasi"]) == 8
        assert sorted(r["kume"] + r["yedek_sirasi"]) == sorted(ISARETLI_SENTETIK)
        assert r == kura.stress_draw(list(reversed(ISARETLI_SENTETIK)), t, 5)  # girdi sırası etkisiz


def test_stres_cekimi_ana_kuranin_uretecine_dokunmaz():
    pool = _pool_genis()
    once = kura.draw(pool, TOHUM, KOTA)
    kura.stress_draw(ISARETLI_SENTETIK, TOHUM, 5)
    assert kura.draw(pool, TOHUM, KOTA) == once
    assert "isaretli_sira" not in once


def test_stres_degisim_siradaki_ilk_programi_alir():
    r = kura.stress_draw(ISARETLI_SENTETIK, TOHUM, 5)
    cikan = r["kume"][1]
    r2 = kura.stress_replace(r, [cikan])
    assert r2["kume"] == [p for p in r["kume"] if p != cikan] + [r["yedek_sirasi"][0]]
    assert r2["degisimler"] == [{"cikan": cikan, "giren": r["yedek_sirasi"][0]}]
    # yedek koşulamazsa küme değişmez
    r3 = kura.stress_replace(r, [r["yedek_sirasi"][0]])
    assert r3["kume"] == r["kume"] and r3["degisimler"] == []
    # ilk yedek de koşulamazsa ikincisi gelir
    r4 = kura.stress_replace(r, [cikan, r["yedek_sirasi"][0]])
    assert r4["degisimler"] == [{"cikan": cikan, "giren": r["yedek_sirasi"][1]}]


# ---------------------------------------------------------------- koşulamama nedenleri (K3 = derleme)

def test_kosulamama_nedeni_cozulur():
    assert kura.parse_failures("a:K1, b:K6,c:K2", {"a", "b", "c"}) == {"a": "K1", "b": "K6", "c": "K2"}
    assert kura.parse_failures("", {"a"}) == {}
    assert set(kura.REPLACEMENT_REASONS) == {"K1", "K2", "K4", "K5", "K6"}


def test_k3_degisim_nedeni_degil():
    with pytest.raises(ValueError, match="K3 değişim nedeni değil"):
        kura.parse_failures("a:K3", {"a"})


def test_nedensiz_ya_da_bilinmeyen_neden_reddedilir():
    with pytest.raises(ValueError, match="neden eksik"):
        kura.parse_failures("a", {"a"})
    with pytest.raises(ValueError, match="neden eksik"):
        kura.parse_failures("a:", {"a"})
    with pytest.raises(ValueError, match="bilinmeyen neden"):
        kura.parse_failures("a:K9", {"a"})
    with pytest.raises(ValueError, match="yok"):
        kura.parse_failures("z:K1", {"a"})


def test_main_k3_ile_kura_cekmez(monkeypatch, capsys):
    monkeypatch.setattr(kura, "registration_check", lambda paths, run=subprocess.run: (True, "kayıtlı"))

    def yasak(*a, **k):
        raise AssertionError("geçersiz girdiyle kura çekildi")
    monkeypatch.setattr(kura, "draw", yasak)
    monkeypatch.setattr(kura, "stress_draw", yasak)
    assert kura.main(["--kosulamayan", "abcm2ps:K3"]) == 2
    assert "K3" in capsys.readouterr().err
    assert kura.main(["--kosulamayan", "abcm2ps"]) == 2
    assert "neden eksik" in capsys.readouterr().err


# ---------------------------------------------------------------- kanıt dosyaları

def test_kanit_havuz_betikle_tutarli():
    data = json.loads((_KANIT / "pool_data.json").read_text(encoding="utf-8"))
    assert set(data) == set(kura.VALIDATION_POOL)
    for ad, v in data.items():
        assert (v["alan"], v["aile"], v["vekil_kib"]) == kura.VALIDATION_POOL[ad], ad
        assert v["tabaka"] == kura.stratum_of(v["vekil_kib"]), ad
        assert v["elf"] <= 4, ad
        assert v["dbgsym_surum"] == v["deb_surum"], ad
        assert len(v["sise_sha256"]) == 64 and int(v["sise_sha256"], 16) >= 0, ad


def test_kanit_isaretli_betikle_tutarli():
    data = json.loads((_KANIT / "isaretli_data.json").read_text(encoding="utf-8"))
    assert set(data) == set(kura.FLAGGED)
    for ad, v in data.items():
        assert v["isaret"] == kura.FLAGGED[ad], ad
        assert kura.LOWER <= v["vekil_kib"] <= kura.UPPER, ad
        assert v["elf"] <= 4, ad
        assert v["dbgsym_surum"] == v["deb_surum"], ad
