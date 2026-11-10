"""CProjectBuilder sağlamlık testleri — çıktı sağlamlığı denetimi (2026-11-10).

Denetim (docs/arge/2026-11-10_cikti_saglamligi/rapor.md) iki kusur buldu:

  Kusur 2.  Fonksiyonlar son çıktıdan sessizce düşüyordu. Kurucu dosya adından
            baştaki `_` karakterini siliyor, `_exit` ile `exit` aynı dosyaya
            yazılıyordu; rapor yine "başarılı" diyordu.
  Kusur 14. Dosya yerleşimi koşudan koşuya değişiyordu: topluluk tespitinde
            eşitlik bir `set` dolaşım sırasıyla, yani PYTHONHASHSEED ile
            bozuluyordu.

Bu testler iki değişmezi kilitler:

  * Girdideki her fonksiyon çıktıda tam bir kez yer alır (her çakışma türünde,
    harf duyarsız dosya sisteminde de); kurucu ihlali kendisi bildirir.
  * Yerleşim girdi sırasından ve karma tohumundan bağımsızdır.

Sayım kurucunun defterine değil diske dayanır: fonksiyon, kaynak başlığındaki
`// Address:` satırıyla tanınır.
"""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

from karadul.reconstruction import c_project_builder
from karadul.reconstruction.c_project_builder import (
    CProjectBuilder,
    _BuildLedger,
    _MAX_FILE_STEM_LEN,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
_ADRES_RE = re.compile(r"^// Address:\s+(\S+)\s*$", re.M)


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _kaynak(ad: str, adres: str, satir: int = 12) -> str:
    """Ghidra çıktısı biçiminde tek fonksiyonluk kaynak (başlık + gövde)."""
    return (
        f"// Function: {ad}\n// Address:  {adres}\n\n"
        f"void {ad}(void)\n{{\n" + f"  adim_{adres}();\n" * satir + "}\n"
    )


class _CalismaAlani:
    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def get_stage_dir(self, ad: str) -> Path:
        return self._kok / ad


def _girdi_yaz(kok: Path, dosyalar: dict[str, str], graf: dict | None = None) -> None:
    """`dosyalar`: göreli yol (uzantısız) -> içerik. `graf`: çağrı grafı JSON'u."""
    for goreli, icerik in dosyalar.items():
        yol = kok / "kaynak" / f"{goreli}.c"
        yol.parent.mkdir(parents=True, exist_ok=True)
        yol.write_text(icerik)
    if graf is not None:
        (kok / "static").mkdir(parents=True, exist_ok=True)
        (kok / "static" / "ghidra_call_graph.json").write_text(json.dumps(graf))


def _kur(kok: Path, dosyalar: dict[str, str], graf: dict | None = None,
         cikti: str = "proje"):
    _girdi_yaz(kok, dosyalar, graf)
    sonuc = CProjectBuilder(None).build(
        kok / "kaynak", kok / cikti, workspace=_CalismaAlani(kok),
    )
    return sonuc, kok / cikti


def _adres_yerleri(proje: Path) -> dict[str, list[str]]:
    """adres -> başlığının geçtiği kaynak dosyalar (src/ altı, göreli yol)."""
    yerler: dict[str, list[str]] = defaultdict(list)
    for yol in sorted((proje / "src").rglob("*.c")):
        for adres in _ADRES_RE.findall(yol.read_text()):
            yerler[adres].append(yol.relative_to(proje / "src").as_posix())
    return dict(yerler)


def _kaynak_adlari(proje: Path) -> list[str]:
    return sorted(p.name for p in (proje / "src").rglob("*.c"))


def _disk_dosya_sayisi(proje: Path) -> int:
    return sum(1 for p in proje.rglob("*") if p.is_file())


def _tam_bir_kez(sonuc, proje: Path, adresler: list[str]) -> None:
    """Her adres çıktıda tam bir dosyada; kurucu da öyle bildiriyor."""
    yerler = _adres_yerleri(proje)
    assert sorted(yerler) == sorted(adresler)
    assert all(len(v) == 1 for v in yerler.values()), yerler
    assert sonuc.success is True, sonuc.errors
    assert sonuc.errors == []
    assert (sonuc.functions_total, sonuc.functions_placed) == (len(adresler),) * 2
    assert (sonuc.functions_missing, sonuc.functions_duplicated) == (0, 0)
    # Harf duyarsız dosya sisteminde de çakışma yok
    adlar = [p.relative_to(proje).as_posix().casefold()
             for p in (proje / "src").rglob("*.c")]
    assert len(adlar) == len(set(adlar))
    assert sonuc.files_written == _disk_dosya_sayisi(proje)


# ---------------------------------------------------------------------------
# 1. Çakışma türleri: hiçbir fonksiyon düşmez
# ---------------------------------------------------------------------------

def test_bastaki_alt_cizgi_ayri_dosya(tmp_path):
    """Denetimdeki kusur: `_exit` ile `exit` aynı dosyaya yazılıyordu."""
    sonuc, proje = _kur(tmp_path, {
        "_exit": _kaynak("_exit", "00101b50"),
        "exit": _kaynak("exit", "00101b98"),
        "__redisAppendCommand": _kaynak("__redisAppendCommand", "00102000"),
        "redisAppendCommand": _kaynak("redisAppendCommand", "00103000"),
    })
    _tam_bir_kez(sonuc, proje, ["00101b50", "00101b98", "00102000", "00103000"])
    # Ad temizlenince değişmiyorsa dosya adı fonksiyon adıdır
    assert _kaynak_adlari(proje) == [
        "__redisAppendCommand.c", "_exit.c", "exit.c", "redisAppendCommand.c"]
    assert _adres_yerleri(proje)["00101b50"] == ["subsystem_misc/_exit.c"]
    assert _adres_yerleri(proje)["00101b98"] == ["subsystem_misc/exit.c"]


def test_harf_farki_harf_duyarsiz_dosya_sisteminde_cakismaz(tmp_path):
    """`Foo`, `foo`, `FOO`: macOS dosya sisteminde üçü aynı dosya adıdır."""
    sonuc, proje = _kur(tmp_path, {
        # Girdi de harf duyarsız dosya sisteminde durabilsin diye ayrı dizinler
        "a/Foo": _kaynak("Foo", "00001000"),
        "b/foo": _kaynak("foo", "00002000"),
        "c/FOO": _kaynak("FOO", "00003000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000", "00003000"])
    # Anahtar sırasıyla ilk gelen adını alır, ötekiler adres eki
    assert _kaynak_adlari(proje) == ["FOO.c", "Foo_00001000.c", "foo_00002000.c"]


def test_gecersiz_karakter_ve_temiz_ad(tmp_path):
    """`a$b` temizlenince `a_b` olur; gerçek `a_b` adını korur."""
    sonuc, proje = _kur(tmp_path, {
        "a$b": _kaynak("a$b", "00001000"),
        "a_b": _kaynak("a_b", "00002000"),
        "a b": _kaynak("a b", "00003000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000", "00003000"])
    yerler = _adres_yerleri(proje)
    assert yerler["00002000"] == ["subsystem_misc/a_b.c"]
    assert yerler["00003000"] == ["subsystem_misc/a_b_00003000.c"]
    assert yerler["00001000"] == ["subsystem_misc/a_b_00001000.c"]


def test_gecersiz_karakter_cakisma_yoksa_ek_almaz(tmp_path):
    sonuc, proje = _kur(tmp_path, {"runtime$sys": _kaynak("runtime$sys", "00001000")})
    _tam_bir_kez(sonuc, proje, ["00001000"])
    assert _kaynak_adlari(proje) == ["runtime_sys.c"]


def test_kesilen_uzun_adlar_cakismaz(tmp_path):
    """Ortak ön eki sınırdan uzun iki ad: kesilince aynı, adres ekiyle ayrı."""
    on_ek = "u" * (_MAX_FILE_STEM_LEN + 5)
    bir, iki = on_ek + "_bir", on_ek + "_iki"
    sonuc, proje = _kur(tmp_path, {
        bir: _kaynak("uzun_bir", "00001000"),
        iki: _kaynak("uzun_iki", "00002000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000"])
    adlar = _kaynak_adlari(proje)
    assert all(len(Path(a).stem) <= _MAX_FILE_STEM_LEN for a in adlar), adlar
    assert sorted(a[-len("_00001000.c"):] for a in adlar) == ["_00001000.c", "_00002000.c"]


def test_sinirda_uzun_ad_kesilmez(tmp_path):
    ad = "s" * _MAX_FILE_STEM_LEN
    sonuc, proje = _kur(tmp_path, {ad: _kaynak("sinir", "00001000")})
    _tam_bir_kez(sonuc, proje, ["00001000"])
    assert _kaynak_adlari(proje) == [ad + ".c"]


def test_ayni_ad_farkli_adres(tmp_path):
    """headless.py aynı adlı ikinci fonksiyona adres eki koyar; ek zaten doluysa
    sıra numarası gelir."""
    sonuc, proje = _kur(tmp_path, {
        "a/Dup": _kaynak("Dup", "00001000"),
        "b/dup": _kaynak("dup", "00002000"),
        "dup_00002000": _kaynak("dup", "00009000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000", "00009000"])
    assert _kaynak_adlari(proje) == ["Dup.c", "dup_00002000.c", "dup_00002000_2.c"]
    assert _adres_yerleri(proje)["00009000"] == ["subsystem_misc/dup_00002000.c"]


def test_alt_dizinlerde_ayni_govde(tmp_path):
    """Aynı dosya gövdesi iki alt dizinde: eski kod birini sessizce atıyordu."""
    sonuc, proje = _kur(tmp_path, {
        "memcmp": _kaynak("memcmp", "00001000"),
        "x/memcmp": _kaynak("memcmp", "00002000"),
        "y/memcmp": _kaynak("memcmp", "00003000"),
        "x/yalniz_altta": _kaynak("yalniz_altta", "00004000"),
        "y/yalniz_altta": _kaynak("yalniz_altta", "00005000"),
    })
    _tam_bir_kez(sonuc, proje,
                 ["00001000", "00002000", "00003000", "00004000", "00005000"])
    assert _kaynak_adlari(proje) == [
        "memcmp.c", "x_memcmp.c", "x_yalniz_altta.c", "y_memcmp.c", "y_yalniz_altta.c"]


def test_sondaki_nokta_ve_adsiz(tmp_path):
    sonuc, proje = _kur(tmp_path, {
        "foo": _kaynak("foo", "00001000"),
        "foo.": _kaynak("foo.", "00002000"),
        "$$": _kaynak("adsiz_bir", "00003000"),
        "$$$": _kaynak("adsiz_iki", "00004000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000", "00003000", "00004000"])
    assert _kaynak_adlari(proje) == [
        "foo.c", "foo_00002000.c", "unnamed.c", "unnamed_00004000.c"]


def test_kurucunun_kendi_dosya_adlari_ayrilmis(tmp_path):
    """`thunks_and_stubs` ve `main` adlı fonksiyon kurucunun dosyasını ezmez."""
    sonuc, proje = _kur(tmp_path, {
        "thunks_and_stubs": _kaynak("thunks_and_stubs", "00001000"),
        "thunks_and_stubs_part2": _kaynak("thunks_and_stubs_part2", "00002000"),
        "buyuk_harf/Thunks_And_Stubs": _kaynak("Thunks_And_Stubs", "00006000"),
        "kisa_bir": _kaynak("kisa_bir", "00003000", satir=1),
        "kisa_iki": _kaynak("kisa_iki", "00004000", satir=1),
        "main.": _kaynak("main.", "00005000"),
    })
    _tam_bir_kez(sonuc, proje, [
        "00001000", "00002000", "00003000", "00004000", "00005000", "00006000"])
    yerler = _adres_yerleri(proje)
    assert yerler["00003000"] == yerler["00004000"] == ["subsystem_misc/thunks_and_stubs.c"]
    assert yerler["00001000"] == ["subsystem_misc/thunks_and_stubs_00001000.c"]
    assert yerler["00002000"] == ["subsystem_misc/thunks_and_stubs_part2_00002000.c"]
    assert yerler["00006000"] == ["subsystem_misc/Thunks_And_Stubs_00006000.c"]
    assert yerler["00005000"] == ["subsystem_misc/main_00005000.c"]


def test_giris_noktalari_main_c_icinde_bir_kez(tmp_path):
    sonuc, proje = _kur(tmp_path, {
        "main": _kaynak("main", "00001000"),
        "_start": _kaynak("_start", "00002000"),
        "is": _kaynak("is", "00003000"),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", "00002000", "00003000"])
    yerler = _adres_yerleri(proje)
    assert yerler["00001000"] == yerler["00002000"] == ["main.c"]


def test_adres_basligi_yoksa_ozet_eki(tmp_path):
    """Başlıksız kaynakta ek, birim anahtarının özetidir; koşudan koşuya aynı."""
    govde = "int f(void)\n{\n" + "  g();\n" * 12 + "}\n"
    dosyalar = {"a/Bar": govde + "// bir\n", "b/bar": govde + "// iki\n"}
    sonuc, proje = _kur(tmp_path / "1", dosyalar)
    sonuc2, proje2 = _kur(tmp_path / "2", dosyalar)
    assert sonuc.success and sonuc2.success
    adlar = _kaynak_adlari(proje)
    assert adlar == _kaynak_adlari(proje2)
    assert adlar[0] == "Bar.c" and re.fullmatch(r"bar_[0-9a-f]{8}\.c", adlar[1]), adlar
    assert sonuc.functions_placed == 2 and sonuc.functions_missing == 0


def test_asiri_uzun_adres_yerine_ozet_eki(tmp_path):
    """Başlıktaki adres beklenmedik uzunluktaysa dosya adına taşınmaz."""
    uzun = "9" * 40
    sonuc, proje = _kur(tmp_path, {
        "a/Baz": _kaynak("Baz", "00001000"),
        "b/baz": _kaynak("baz", uzun),
    })
    _tam_bir_kez(sonuc, proje, ["00001000", uzun])
    adlar = _kaynak_adlari(proje)
    assert adlar[0] == "Baz.c" and re.fullmatch(r"baz_[0-9a-f]{8}\.c", adlar[1]), adlar


@pytest.mark.parametrize("ham, beklenen", [
    ("_exit", "_exit"),
    ("__libc_start_main", "__libc_start_main"),
    ("son_", "son_"),
    ("a..b", "a.b"),
    ("..", "unnamed"),
    ("___", "unnamed"),
    (".gizli", "gizli"),
    ("../../etc/passwd", "_._etc_passwd"),
])
def test_ad_temizleme(ham, beklenen):
    assert CProjectBuilder._sanitize_stem(ham) == beklenen


def test_dosya_adi_atamasi_siradan_bagimsiz():
    """Aynı anahtar kümesi, farklı sıra -> aynı atama."""
    anahtarlar = ["Foo", "foo", "FOO", "a$b", "a_b", "a b", "_x", "x", "x."]
    icerik = {k: _kaynak("f", "%08x" % (0x1000 * (i + 1))) for i, k in enumerate(anahtarlar)}
    kurucu = CProjectBuilder(None)
    beklenen = kurucu._assign_file_stems(anahtarlar, icerik)
    assert len({v.casefold() for v in beklenen.values()}) == len(anahtarlar)
    rastgele = random.Random(7)
    for _ in range(10):
        karisik = anahtarlar[:]
        rastgele.shuffle(karisik)
        assert kurucu._assign_file_stems(karisik, icerik) == beklenen


# ---------------------------------------------------------------------------
# 2. Fonksiyon gövdesi iki dosyaya bölünmez (denetim kusur 19)
# ---------------------------------------------------------------------------

def test_uzun_fonksiyon_tek_dosyada(tmp_path, monkeypatch):
    monkeypatch.setattr(CProjectBuilder, "MAX_LINES_PER_FILE", 40)
    icerik = _kaynak("buyuk", "00001000", satir=200)
    sonuc, proje = _kur(tmp_path, {"buyuk": icerik})
    _tam_bir_kez(sonuc, proje, ["00001000"])
    assert _kaynak_adlari(proje) == ["buyuk.c"]
    assert (proje / "src" / "subsystem_misc" / "buyuk.c").read_text() == icerik


def test_birlesik_dosya_fonksiyon_sinirindan_bolunur(tmp_path, monkeypatch):
    monkeypatch.setattr(CProjectBuilder, "MAX_LINES_PER_FILE", 30)
    dosyalar = {f"kisa_{i:02d}": _kaynak(f"kisa_{i:02d}", "%08x" % (0x1000 + i), satir=2)
                for i in range(12)}
    # Sınırdan uzun tek bir thunk: sıralamada en başa düşer, kendi parçasını alır
    dosyalar["THUNK_buyuk"] = _kaynak("THUNK_buyuk", "00000fff", satir=100)
    sonuc, proje = _kur(tmp_path, dosyalar)
    _tam_bir_kez(sonuc, proje, ["00000fff"] + ["%08x" % (0x1000 + i) for i in range(12)])
    parcalar = sorted((proje / "src" / "subsystem_misc").glob("*.c"))
    assert [p.name for p in parcalar] == [
        f"thunks_and_stubs_part{i}.c" for i in range(1, len(parcalar) + 1)]
    assert len(parcalar) > 2
    metinler = [p.read_text() for p in parcalar]
    for metin in metinler:
        # Her parça başlıklı (başlıksız `_partN.c` yok); sınırı yalnız tek
        # fonksiyonluk parça aşabilir
        assert len(_ADRES_RE.findall(metin)) >= 1
        assert metin.count("\n") <= 30 or len(_ADRES_RE.findall(metin)) == 1
    for icerik in dosyalar.values():
        # Her fonksiyonun gövdesi bütün olarak tek parçada
        assert sum(icerik.rstrip() in metin for metin in metinler) == 1


def test_birlesik_dosya_satir_siniri_baslik_dahil(tmp_path, monkeypatch):
    """Sınır dosyanın bütün satırlarını sayar (parça başlığı dahil)."""
    monkeypatch.setattr(CProjectBuilder, "MAX_LINES_PER_FILE", 30)
    dosyalar = {f"kisa_{i}": _kaynak(f"kisa_{i}", "%08x" % (0x1000 + i), satir=2)
                for i in range(6)}
    sonuc, proje = _kur(tmp_path, dosyalar)
    _tam_bir_kez(sonuc, proje, ["%08x" % (0x1000 + i) for i in range(6)])
    parcalar = sorted((proje / "src" / "subsystem_misc").glob("*.c"))
    # Başlık 4 satır, her fonksiyon bloğu 10 satır: parça başına 2 fonksiyon (24 satır)
    assert [p.read_text().count("\n") for p in parcalar] == [24, 24, 24]


# ---------------------------------------------------------------------------
# 3. Değişmez denetimi: ihlal sessiz kalmaz
# ---------------------------------------------------------------------------

def test_degismez_ustune_yazilan_fonksiyonu_bildirir(tmp_path, monkeypatch):
    """Ad ataması bozulursa (iki fonksiyon aynı dosya) kurucu başarı demez."""
    monkeypatch.setattr(
        CProjectBuilder, "_assign_file_stems",
        lambda self, keys, contents: {k: "ayni" for k in keys},
    )
    sonuc, proje = _kur(tmp_path, {
        "alfa": _kaynak("alfa", "00001000"),
        "beta": _kaynak("beta", "00002000"),
    })
    assert sonuc.success is False
    assert (sonuc.functions_total, sonuc.functions_placed) == (2, 1)
    assert (sonuc.functions_missing, sonuc.functions_duplicated) == (1, 0)
    assert len(sonuc.errors) == 1
    assert "Değişmez ihlali: 1 fonksiyon çıktıda yok (alfa)" in sonuc.errors[0]
    # Sayaç diskteki dosyayı sayar, yazma girişimini değil (denetim kusur 13)
    assert sonuc.files_written == _disk_dosya_sayisi(proje)


def test_degismez_harf_farkiyla_ezilmeyi_bildirir(tmp_path, monkeypatch):
    """Defter harf duyarsızdır: harf duyarlı dosya sisteminde de aynı hüküm."""
    monkeypatch.setattr(
        CProjectBuilder, "_assign_file_stems",
        lambda self, keys, contents: {k: k for k in keys},
    )
    sonuc, _proje = _kur(tmp_path, {
        "a/Foo": _kaynak("Foo", "00001000"),
        "b/foo": _kaynak("foo", "00002000"),
    })
    assert sonuc.success is False
    assert sonuc.functions_missing == 1


def _defter(tmp_path: Path) -> tuple[_BuildLedger, Path]:
    kok = tmp_path / "proje"
    (kok / "src" / "alt").mkdir(parents=True)
    return _BuildLedger(kok), kok / "src"


def test_defter_harf_duyarsiz(tmp_path):
    """Yalnız harfle ayrılan iki yol tek dosya sayılır; ilk yazılan ezilmiştir.
    Hüküm, testin koştuğu dosya sisteminin harf duyarlılığına bağlı değildir."""
    defter, src = _defter(tmp_path)
    birimler = {"Foo": _kaynak("Foo", "00001000"), "foo": _kaynak("foo", "00002000")}
    defter.write(src / "alt" / "Foo.c", birimler["Foo"], ("Foo",))
    defter.write(src / "alt" / "foo.c", birimler["foo"], ("foo",))
    assert defter.files_written == 1
    eksik, cift, iletiler = CProjectBuilder(None)._check_placement(birimler, defter, src)
    assert (eksik, cift) == (["Foo"], [])
    assert len(iletiler) == 1 and "1 fonksiyon çıktıda yok (Foo)" in iletiler[0]


def test_degismez_eksik_cift_ve_yabanci_dosya(tmp_path):
    defter, src = _defter(tmp_path)
    birimler = {k: _kaynak(k, f"0000{i}000") for i, k in enumerate(
        ["tamam", "yerlesmedi", "cift", "silindi", "bozuldu"], start=1)}
    defter.write(src / "alt" / "tamam.c", birimler["tamam"], ("tamam",))
    defter.write(src / "alt" / "cift.c", birimler["cift"], ("cift",))
    defter.write(src / "alt" / "cift2.c", birimler["cift"], ("cift",))
    defter.write(src / "alt" / "silindi.c", birimler["silindi"], ("silindi",))
    defter.write(src / "alt" / "bozuldu.c", birimler["bozuldu"], ("bozuldu",))
    (src / "alt" / "silindi.c").unlink()
    (src / "alt" / "bozuldu.c").write_text("// yarım\n")
    (src / "alt" / "eski_kurulum.c").write_text(birimler["tamam"])

    eksik, cift, iletiler = CProjectBuilder(None)._check_placement(birimler, defter, src)
    assert eksik == ["bozuldu", "silindi", "yerlesmedi"]
    assert cift == ["cift"]
    assert len(iletiler) == 3
    assert "3 fonksiyon çıktıda yok (bozuldu, silindi, yerlesmedi)" in iletiler[0]
    assert "1 fonksiyon çıktıda birden çok kez var (cift)" in iletiler[1]
    assert "yazmadığı 1 kaynak dosya var (src/alt/eski_kurulum.c)" in iletiler[2]
    assert all(i.startswith("Değişmez ihlali: ") for i in iletiler)


def test_degismez_temiz_kurulumda_sessiz(tmp_path):
    defter, src = _defter(tmp_path)
    birimler = {"bir": _kaynak("bir", "00001000"), "iki": _kaynak("iki", "00002000")}
    defter.write(src / "alt" / "bir.c", birimler["bir"], ("bir",))
    defter.write(src / "alt" / "birlesik.c", "// baş\n" + birimler["iki"].rstrip() + "\n\n",
                 ("iki",))
    assert CProjectBuilder(None)._check_placement(birimler, defter, src) == ([], [], [])


def test_onceki_kurulumdan_kalan_dosya_bildirilir(tmp_path):
    """Aynı dizine ikinci kurulum: girdi aynıysa temiz; değiştiyse kalan dosya
    (aynı fonksiyonun ikinci kopyası) bildirilir."""
    dosyalar = {"bir": _kaynak("bir", "00001000"), "iki": _kaynak("iki", "00002000")}
    ilk, proje = _kur(tmp_path, dosyalar)
    tekrar, _ = _kur(tmp_path, dosyalar)
    assert ilk.success and tekrar.success and tekrar.errors == []

    (tmp_path / "kaynak" / "iki.c").rename(tmp_path / "kaynak" / "iki_yeni.c")
    sonra = CProjectBuilder(None).build(
        tmp_path / "kaynak", proje, workspace=_CalismaAlani(tmp_path))
    assert sonra.success is False
    assert sonra.functions_missing == 0
    assert any("yazmadığı 1 kaynak dosya var (src/subsystem_misc/iki.c)" in e
               for e in sonra.errors)
    assert len(_adres_yerleri(proje)["00002000"]) == 2


# ---------------------------------------------------------------------------
# 4. Belirlenimci yerleşim
# ---------------------------------------------------------------------------

def _graf(dugumler: dict[str, tuple[str, list[str]]],
          kenarlar: list[tuple[str, str]]) -> dict:
    """`dugumler`: adres -> (ad, çağrılan adları)."""
    return {
        "program": "deneme",
        "nodes": {
            adres: {"name": ad, "address": adres, "caller_count": 0,
                    "callee_count": len(cagrilan), "callers": [],
                    "callees": [{"name": c} for c in cagrilan]}
            for adres, (ad, cagrilan) in dugumler.items()
        },
        "edges": [{"from_name": a, "to_name": b} for a, b in kenarlar],
    }


def _rastgele_graf(n: int = 60, tohum: int = 11) -> tuple[dict[str, str], dict]:
    """Eşitliği bol bir çağrı grafı: her düğümün 2-3 komşusu var."""
    r = random.Random(tohum)
    adlar = [f"fn_{i:02d}" for i in range(n)]
    kenarlar = sorted({tuple(r.sample(adlar, 2)) for _ in range(n + n // 2)})
    dosyalar = {ad: _kaynak(ad, "%08x" % (0x1000 * (i + 1))) for i, ad in enumerate(adlar)}
    dugumler = {"%08x" % (0x1000 * (i + 1)): (ad, []) for i, ad in enumerate(adlar)}
    return dosyalar, _graf(dugumler, kenarlar)


def _agac(proje: Path) -> dict[str, str]:
    """Göreli yol -> içerik; çıktı kökünün mutlak yolu yer tutucuyla değişir."""
    return {
        p.relative_to(proje).as_posix(): p.read_text().replace(str(proje), "<KÖK>")
        for p in sorted(proje.rglob("*")) if p.is_file()
    }


def test_topluluk_tespiti_kenar_sirasindan_bagimsiz():
    _dosyalar, graf = _rastgele_graf()
    kurucu = CProjectBuilder(None)
    beklenen = kurucu._detect_communities(graf)
    assert len(set(beklenen.values())) >= 3          # sınama anlamlı: birden çok topluluk
    rastgele = random.Random(3)
    for _ in range(10):
        karisik = dict(graf, edges=graf["edges"][:])
        rastgele.shuffle(karisik["edges"])
        # Kenarın yönü de (kimin kimi çağırdığı) topluluğu değiştirmez
        karisik["edges"] = [
            e if rastgele.random() < 0.5
            else {"from_name": e["to_name"], "to_name": e["from_name"]}
            for e in karisik["edges"]
        ]
        assert kurucu._detect_communities(karisik) == beklenen


def test_esit_buyuklukte_topluluk_numarasi_etiket_adiyla():
    """İki ayrık üçgen: numara kenar sırasına değil etiket adına bağlı."""
    a = [("a1", "a2"), ("a2", "a3"), ("a1", "a3")]
    b = [("b1", "b2"), ("b2", "b3"), ("b1", "b3")]
    kurucu = CProjectBuilder(None)
    once_a = kurucu._detect_communities(_graf({}, a + b))
    once_b = kurucu._detect_communities(_graf({}, b + a))
    assert once_a == once_b
    assert {once_a[x] for x in ("a1", "a2", "a3")} == {"group_0"}
    assert {once_a[x] for x in ("b1", "b2", "b3")} == {"group_1"}


def test_esit_puanda_altsistem_kural_sirasiyla():
    """malloc (memory) ve fopen (file_io) eşit puan: tablo sırası kazanır."""
    kurucu = CProjectBuilder(None)
    bir = kurucu._classify_subsystem("f", [{"name": "malloc"}, {"name": "fopen"}])
    iki = kurucu._classify_subsystem("f", [{"name": "fopen"}, {"name": "malloc"}])
    assert bir == iki == "file_io"
    assert kurucu._classify_subsystem(
        "f", [{"name": "malloc"}, {"name": "free"}, {"name": "fopen"}]) == "memory"


def test_ayni_adli_dugumlerde_girdi_sirasindan_bagimsiz(tmp_path):
    """Aynı adı taşıyan iki düğüm: sonuç düğümlerin JSON'daki sırasına bağlı değil."""
    dosyalar = {"dup": _kaynak("dup", "00001000"), "tek": _kaynak("tek", "00003000")}
    dugumler = {
        "00001000": ("dup", ["socket"]),
        "00002000": ("dup", ["malloc"]),
        "00003000": ("tek", []),
    }
    ters = dict(reversed(list(dugumler.items())))
    _s1, p1 = _kur(tmp_path / "1", dosyalar, _graf(dugumler, []))
    _s2, p2 = _kur(tmp_path / "2", dosyalar, _graf(ters, []))
    assert _adres_yerleri(p1) == _adres_yerleri(p2)
    assert _adres_yerleri(p1)["00001000"] == ["subsystem_memory/dup.c"]
    agac1, agac2 = _agac(p1), _agac(p2)
    for yol in ("include/subsystem_memory.h", "analysis/subsystem_map.md"):
        assert agac1[yol] == agac2[yol]
    assert "void dup(void);  // @00001000" in agac1["include/subsystem_memory.h"]


_ALT_SUREC = r"""
import sys
from pathlib import Path
from karadul.reconstruction import c_project_builder as m

class CalismaAlani:
    def __init__(self, kok):
        self.kok = kok
    def get_stage_dir(self, ad):
        return self.kok / ad

kok, cikti = Path(sys.argv[1]), Path(sys.argv[2])
sonuc = m.CProjectBuilder(None).build(kok / "kaynak", cikti, workspace=CalismaAlani(kok))
assert sonuc.success, sonuc.errors
print(m.__file__)
"""

_KARMA_TOHUMLARI = ("0", "1", "2", "3", "4", "5")


def test_yerlesim_karma_tohumundan_bagimsiz(tmp_path):
    """Farklı PYTHONHASHSEED ile bütün proje ağacı aynı (denetim kusur 14)."""
    dosyalar, graf = _rastgele_graf()
    _girdi_yaz(tmp_path / "girdi", dosyalar, graf)
    ortam = {k: v for k, v in os.environ.items() if k != "PYTHONHASHSEED"}
    ortam["PYTHONPATH"] = str(REPO_ROOT)
    ortam["PYTHONDONTWRITEBYTECODE"] = "1"
    surecler = {}
    for tohum in _KARMA_TOHUMLARI:
        cikti = tmp_path / f"cikti_{tohum}"
        surecler[tohum] = (cikti, subprocess.Popen(
            [sys.executable, "-c", _ALT_SUREC, str(tmp_path / "girdi"), str(cikti)],
            cwd=REPO_ROOT, env={**ortam, "PYTHONHASHSEED": tohum},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    agaclar = {}
    for tohum, (cikti, surec) in surecler.items():
        stdout, stderr = surec.communicate(timeout=300)
        assert surec.returncode == 0, stderr[-2000:]
        # Alt süreç bu testle aynı kurucuyu yükledi
        assert (Path(stdout.strip().splitlines()[-1]).resolve()
                == Path(c_project_builder.__file__).resolve())
        agaclar[tohum] = _agac(cikti)

    ilk = agaclar[_KARMA_TOHUMLARI[0]]
    dizinler = {Path(y).parts[1] for y in ilk if y.startswith("src/")}
    assert len(dizinler) >= 3, dizinler             # sınama anlamlı: birden çok dizin
    for tohum in _KARMA_TOHUMLARI[1:]:
        assert sorted(agaclar[tohum]) == sorted(ilk), f"PYTHONHASHSEED={tohum}: dosya kümesi farklı"
        for yol in ilk:
            assert agaclar[tohum][yol] == ilk[yol], f"PYTHONHASHSEED={tohum}: {yol} farklı"
