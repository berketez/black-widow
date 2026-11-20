"""Bayrak ön paketi (KARARLAR A-19 a, A-13; Dalga 0, 2026-11-20).

Bütün planların ``karadul/config.py`` alanları tek pakette, okunmadan eklendi (her biri
``INERT_SETTINGS``'te); ad eşiği tek sabit (``naming_labels.AD_ESIGI``). Envanter ve bağlama
tablosu: ``docs/arge/2026-11-20_dalga0/BAYRAK.md``.

Bu dosya:
  (a) envanterdeki her alan var; HENÜZ BAĞLANMAMIŞSA türü ve öntanımı envanterdeki gibi;
  (b) bağlanmamış alan ``INERT_SETTINGS``'te ve alan satırında ``# ETKİSİZ: <paket> bağlayacak``
      yorumu var; ikisi birlikte kalkar (biri kalırsa kırmızı);
  (c) boş YAML ve depodaki örnek ayar dosyasıyla yüklenen ``Config``'in yeni alanlar dışındaki
      içeriği "dosyanın yazdığı + öntanım"; yeni alanlar öntanımda; yeni anahtar uyarı üretmiyor;
  (d) YAML'da her yeni alana (yeni bölümler dahil) değer verilince alan değişiyor; tür denetimi
      ve bilinmeyen anahtar hatası yeni bölümlerde de çalışıyor;
  (e) ``AD_ESIGI = L / (L + 1)``, ``L = 10`` (kesirle; "0,909" yuvarlanmış yazım).

Bağlama: bağlayan paket alanın INERT satırını siler ve alan satırındaki ``# ETKİSİZ`` yorumunu
kaldırır; bu dosyayı değiştirmesi gerekmez (bağlanan alanın tür / öntanım kilidi kalkar, bağlayan
paket kendi testinde kilitler). Yeni alanların hiçbir kodda okunmadığını
``tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate`` denetler.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
from fractions import Fraction
from pathlib import Path

import pytest
from click.testing import CliRunner

import karadul.config as config_mod
from karadul.cli import main as karadul_main
from karadul.config import INERT_SETTINGS, Config, ConfigValueError, _config_sections
from karadul.core import naming_labels

ROOT = Path(__file__).resolve().parents[1]

# (bölüm, alan, tür, öntanım, bağlayacak paket) — BAYRAK.md §1.1 ile aynı sıra.
ENVANTER: list[tuple[str, str, object, object, str]] = [
    ("binary_reconstruction", "enable_anchored_reference_matching", bool, False, "PK-4"),
    ("binary_reconstruction", "enable_separate_debug_naming", bool, False, "PK-5"),
    ("binary_reconstruction", "debug_file_dirs", list[str], [], "PK-5"),
    ("binary_reconstruction", "anchored_reference_witness_gate", bool, False, "PK-7"),
    ("binary_reconstruction", "oz_ad_verbatim", bool, False, "ÖK-1"),
    ("binary_reconstruction", "oz_ad_uniqueness_gate", bool, False, "ÖK-2"),
    ("binary_reconstruction", "enable_unique_identifier_names", bool, False, "ÖK-3"),
    ("binary_reconstruction", "enable_record_affix_names", bool, False, "ÖK-4b"),
    ("binary_reconstruction", "enable_module_prefix_evidence", bool, False, "ÖK-6"),
    ("binary_reconstruction", "enable_go_metadata_recovery", bool, False, "P-ÜV1"),
    ("binary_reconstruction", "enable_objc_metadata_recovery", bool, False, "P-ÜV2"),
    ("binary_reconstruction", "enable_swift_metadata_recovery", bool, False, "P-ÜV3"),
    ("binary_reconstruction", "enable_go_pclntab_naming", bool, False, "P-ÜV6"),
    ("binary_reconstruction", "enable_objc_metadata_naming", bool, False, "P-ÜV6"),
    ("binary_reconstruction", "enable_swift_metadata_naming", bool, False, "P-ÜV6"),
    ("binary_reconstruction", "enable_macho_entry_main", bool, False, "P-ÜV5"),
    ("binary_reconstruction", "enable_go_metadata_integrity", bool, False, "P-ÜV6"),
    ("analysis", "cozumleyici_takilma_sn", int, 0, "ÖL-1"),
    ("analysis", "bekci_aralik_sn", int, 15, "ÖL-1"),
    ("timeouts", "ghidra_adim", int, 0, "ÖL-2"),
    ("bsim", "bos_depoda_sorgu_atla", bool, False, "ÖL-2"),
    ("bsim", "ingest_butcesi_sn", int, 0, "ÖL-2"),
    ("analysis", "akis_yazimi", bool, False, "ÖL-3"),
    ("analysis", "istihbarat_butcesi_sn", int, 0, "ÖL-3b"),
    ("paket", "yonetici", bool, False, "ÖL-5a"),
    ("paket", "genis_kapsam", bool, False, "ÖL-5a"),
    ("paket", "toplam_butce_sn", int, 0, "ÖL-5a"),
    ("paket", "bilesen_butce_sn", int, 0, "ÖL-5a"),
    ("paket", "bilinen_bilesen", bool, False, "ÖL-11"),
    ("kaynak", "disk_on_denetim", bool, False, "ÖL-6"),
    ("kaynak", "disk_guvenlik_carpani", float, 1.5, "ÖL-6"),
    ("kaynak", "azami_bellek_orani", float, 0.0, "ÖL-6"),
    ("reconstruct", "ara_kopyalar", bool, True, "ÖL-7"),
    ("onbellek", "ghidra_kosusu", bool, False, "ÖL-9"),
    ("onbellek", "azami_gb", float, 0.0, "ÖL-9"),
    ("buyuk_ikili", "tembel", bool, False, "ÖL-10"),
    ("buyuk_ikili", "esik_mb", int, 0, "ÖL-10"),
    ("perf", "ayrilmis_bellek_mb", int, 0, "HZ-5"),
    ("perf", "decompile_verim_cekirdegi", bool, False, "HZ-5"),
    ("perf", "jvm_cds", bool, False, "HZ-5"),
    ("bsim", "paralel_tarama", bool, False, "HZ-2"),
    ("analysis", "decompile_parti_boyu", int, 0, "HZ-3"),
    ("analysis", "dokum_tek_gecis", bool, False, "HZ-4a"),
    ("analysis", "dokum_java_yardimci", bool, False, "HZ-4b"),
    ("perf", "desen_onbellegi_ust_sinir", int, 200_000, "HZ-7a"),
    ("perf", "metin_onbellegi_mb", int, 0, "HZ-7b"),
    ("binary_reconstruction", "pipeline_tek_tur_kosulu", bool, False, "HZ-7c"),
    ("perf", "ortak_havuz", bool, False, "HZ-7d"),
    ("perf", "forkserver", bool, False, "HZ-7d"),
]
ANAHTARLAR = [f"{s}.{a}" for s, a, *_ in ENVANTER]
YENI_ANAHTARLAR = frozenset(ANAHTARLAR)

# Planın adıyla yeni bölümler (olcek/PLAN.md: PaketConfig, KaynakConfig, OnbellekConfig,
# BuyukIkiliConfig; `reconstruct` bölümünün sınıf adı planda yok).
YENI_BOLUMLER = {
    "paket": "PaketConfig",
    "kaynak": "KaynakConfig",
    "reconstruct": "ReconstructConfig",
    "onbellek": "OnbellekConfig",
    "buyuk_ikili": "BuyukIkiliConfig",
}

_ISARET = re.compile(r"#\s*ETKİSİZ:\s*(\S+)\s+bağlayacak\s+\(INERT_SETTINGS\)")


def _bolum_sinifi(bolum: str) -> type:
    return _config_sections()[bolum]


def _alan_satiri(bolum: str, alan: str) -> str:
    """Alanın dataclass gövdesindeki tanım satırı (kaynaktan)."""
    for satir in inspect.getsource(_bolum_sinifi(bolum)).splitlines():
        if re.match(r"\s+%s\s*:" % re.escape(alan), satir):
            return satir
    raise AssertionError(f"{bolum}.{alan}: tanım satırı bulunamadı")


def _isaret_paketi(bolum: str, alan: str) -> str | None:
    m = _ISARET.search(_alan_satiri(bolum, alan))
    return m.group(1) if m else None


def _bekliyor(anahtar: str) -> bool:
    """Alan henüz bağlanmadı mı (bayrak ön paketinin INERT kaydı duruyor mu)."""
    return anahtar in INERT_SETTINGS


def _yaml(tmp_path: Path, metin: str, ad: str = "karadul.yaml") -> Path:
    yol = tmp_path / ad
    yol.write_text(metin, encoding="utf-8")
    return yol


# ---------------------------------------------------------------------------------------
# (a) alanlar var; bağlanmamışken tür ve öntanım envanterdeki gibi


def test_envanter_49_alan_tekil() -> None:
    assert len(ENVANTER) == 49
    assert len(YENI_ANAHTARLAR) == 49


@pytest.mark.parametrize("bolum,alan,tur,ontanim,paket", ENVANTER, ids=ANAHTARLAR)
def test_alan_var_tur_ve_ontanim(bolum: str, alan: str, tur: object, ontanim: object,
                                 paket: str) -> None:
    cls = _bolum_sinifi(bolum)
    alanlar = {f.name for f in dataclasses.fields(cls)}
    assert alan in alanlar, f"{bolum}.{alan} yok (alanlar silinmez; kullanıcı YAML'ı kırılır)"
    if not _bekliyor(f"{bolum}.{alan}"):
        pytest.skip("bağlandı: tür / öntanım kilidi bağlayan paketin testinde")
    assert config_mod._field_type_hints(cls)[alan] == tur
    deger = getattr(getattr(Config(), bolum), alan)
    assert deger == ontanim
    assert type(deger) is type(ontanim), (deger, ontanim)  # False ≠ 0, 0 ≠ 0.0


def test_yeni_bolumler_planin_adiyla() -> None:
    bolumler = _config_sections()
    for bolum, sinif in YENI_BOLUMLER.items():
        assert bolumler[bolum].__name__ == sinif
        assert dataclasses.is_dataclass(getattr(Config(), bolum))


# ---------------------------------------------------------------------------------------
# (b) INERT kaydı ve alan satırındaki işaret birlikte


@pytest.mark.parametrize("bolum,alan,tur,ontanim,paket", ENVANTER, ids=ANAHTARLAR)
def test_inert_kaydi_ve_isaret_birlikte(bolum: str, alan: str, tur: object, ontanim: object,
                                       paket: str) -> None:
    anahtar = f"{bolum}.{alan}"
    isaret = _isaret_paketi(bolum, alan)
    if _bekliyor(anahtar):
        assert INERT_SETTINGS[anahtar] == config_mod._pending_binding(paket)
        assert isaret == paket, f"{anahtar}: satırda '# ETKİSİZ: {paket} bağlayacak' yok"
    else:
        # Bağlandı: INERT satırı silindi; "ETKİSİZ" yorumu kalırsa kod yalan söyler.
        assert isaret is None, f"{anahtar}: INERT kaydı yok ama satırda hâlâ '# ETKİSİZ' var"


def test_bekleyen_kayitlarin_hepsi_envanterde() -> None:
    onek = config_mod._pending_binding("X").split("X")[0]
    bekleyen = {k for k, v in INERT_SETTINGS.items() if v.startswith(onek)}
    assert bekleyen <= YENI_ANAHTARLAR, bekleyen - YENI_ANAHTARLAR


def test_gerekce_bagli_paketi_soyler() -> None:
    g = config_mod._pending_binding("ÖL-2")
    assert "ÖL-2" in g and "okumuyor" in g


# ---------------------------------------------------------------------------------------
# (c) yükleme: yeni alanlar dışındaki içerik "dosyanın yazdığı + öntanım"


def _var_olan_gorunum(cfg: Config) -> dict[str, object]:
    """Yeni alanlar dışındaki bütün bölüm alanları + bölüm olmayan kökler."""
    out: dict[str, object] = {}
    for bolum in _config_sections():
        obj = getattr(cfg, bolum)
        for f in dataclasses.fields(obj):
            anahtar = f"{bolum}.{f.name}"
            if anahtar not in YENI_ANAHTARLAR:
                out[anahtar] = getattr(obj, f.name)
    for ad in ("project_root", "data_root", "scripts_dir", "ghidra_scripts_dir"):
        out[ad] = getattr(cfg, ad)
    return out


def _yeni_alanlar_ontanimda(cfg: Config) -> None:
    taban = Config()
    for bolum, alan, *_ in ENVANTER:
        assert getattr(getattr(cfg, bolum), alan) == getattr(getattr(taban, bolum), alan), alan


def _ornek_ayar_dosyalari() -> list[Path]:
    yollar = sorted({*ROOT.glob("karadul.yaml"), *ROOT.glob("docker/**/karadul.yaml")})
    assert yollar, "depoda örnek ayar dosyası bulunamadı (docker/measurement/karadul.yaml)"
    return yollar


def test_bos_yaml_ile_icerik_ayni(tmp_path: Path) -> None:
    cfg = Config.load(_yaml(tmp_path, ""))
    assert _var_olan_gorunum(cfg) == _var_olan_gorunum(Config())
    _yeni_alanlar_ontanimda(cfg)
    assert cfg.yaml_keys == frozenset()
    assert cfg.inert_setting_warnings() == []


@pytest.mark.parametrize("yol", _ornek_ayar_dosyalari(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_ornek_ayar_dosyasi_ile_icerik(yol: Path) -> None:
    import yaml

    veri = yaml.safe_load(yol.read_text(encoding="utf-8")) or {}
    cfg = Config.load(yol)
    yazilan = {f"{b}.{a}" for b, govde in veri.items() for a in (govde or {})}
    assert cfg.yaml_keys == frozenset(yazilan)
    assert not (yazilan & YENI_ANAHTARLAR)
    beklenen = _var_olan_gorunum(Config())
    gorunen = _var_olan_gorunum(cfg)
    for anahtar in yazilan:
        bolum, alan = anahtar.split(".", 1)
        beklenen[anahtar] = config_mod._coerce_value(
            config_mod._field_type_hints(_bolum_sinifi(bolum))[alan], veri[bolum][alan], anahtar,
        )
    assert gorunen == beklenen
    _yeni_alanlar_ontanimda(cfg)
    assert not any(w.split(" ", 1)[0] in YENI_ANAHTARLAR for w in cfg.inert_setting_warnings())


# ---------------------------------------------------------------------------------------
# (d) YAML'dan değer verilince alan değişiyor


def _ontanim_disi(tur: object, ontanim: object) -> tuple[object, str]:
    """(beklenen değer, YAML yazımı)."""
    if tur is bool:
        return (not ontanim, "true" if not ontanim else "false")
    if tur is int:
        return (int(ontanim) + 7, str(int(ontanim) + 7))
    if tur is float:
        return (float(ontanim) + 0.25, repr(float(ontanim) + 0.25))
    if tur == list[str]:
        return (["/tmp/karadul-debug"], '["/tmp/karadul-debug"]')
    raise AssertionError(f"envanterde beklenmeyen tür: {tur}")


@pytest.mark.parametrize("bolum,alan,tur,ontanim,paket", ENVANTER, ids=ANAHTARLAR)
def test_yamldan_deger_alan_degisir(tmp_path: Path, bolum: str, alan: str, tur: object,
                                    ontanim: object, paket: str) -> None:
    beklenen, yazim = _ontanim_disi(tur, getattr(getattr(Config(), bolum), alan))
    cfg = Config.load(_yaml(tmp_path, f"{bolum}:\n  {alan}: {yazim}\n"))
    assert getattr(getattr(cfg, bolum), alan) == beklenen
    anahtar = f"{bolum}.{alan}"
    assert anahtar in cfg.yaml_keys
    if _bekliyor(anahtar):
        assert any(w.startswith(f"{anahtar} etkisiz:") and paket in w
                   for w in cfg.inert_setting_warnings())


def test_her_yeni_bolum_tek_dosyada(tmp_path: Path) -> None:
    satirlar = []
    beklenen: dict[str, object] = {}
    for bolum in YENI_BOLUMLER:
        satirlar.append(f"{bolum}:")
        for b, alan, tur, _ontanim, _paket in ENVANTER:
            if b != bolum:
                continue
            deger, yazim = _ontanim_disi(tur, getattr(getattr(Config(), b), alan))
            satirlar.append(f"  {alan}: {yazim}")
            beklenen[f"{b}.{alan}"] = deger
    cfg = Config.load(_yaml(tmp_path, "\n".join(satirlar) + "\n"))
    for anahtar, deger in beklenen.items():
        bolum, alan = anahtar.split(".", 1)
        assert getattr(getattr(cfg, bolum), alan) == deger, anahtar
    assert cfg.yaml_keys == frozenset(beklenen)


def test_yeni_bolumde_tur_denetimi_ve_bilinmeyen_anahtar(tmp_path: Path) -> None:
    with pytest.raises(ConfigValueError) as e1:
        Config.load(_yaml(tmp_path, "paket:\n  toplam_butce_sn: abc\n", "a.yaml"))
    assert any("paket.toplam_butce_sn" in p for p in e1.value.problems)
    with pytest.raises(ConfigValueError) as e2:
        Config.load(_yaml(tmp_path, "kaynak:\n  disk_on_denetimm: true\n", "b.yaml"))
    assert any("bilinmeyen anahtar" in p and "disk_on_denetim" in p for p in e2.value.problems)
    with pytest.raises(ConfigValueError):
        Config.load(_yaml(tmp_path, "onbellek:\n  ghidra_kosusu: \"belki\"\n", "c.yaml"))


def test_config_validate_yeni_alani_etkisiz_gosterir(tmp_path: Path) -> None:
    yol = _yaml(tmp_path, "buyuk_ikili:\n  tembel: true\nbinary_reconstruction:\n"
                          "  oz_ad_verbatim: true\n")
    res = CliRunner().invoke(karadul_main, ["config", "validate", "--config", str(yol)])
    assert res.exit_code == 0, res.output
    for anahtar in ("buyuk_ikili.tembel", "binary_reconstruction.oz_ad_verbatim"):
        if _bekliyor(anahtar):
            assert f"{anahtar} etkisiz" in res.stdout


# ---------------------------------------------------------------------------------------
# (e) ad eşiği: AD_ESIGI = L / (L + 1), L = 10 (KARARLAR A-2, A-13)


def test_maliyet_orani_on() -> None:
    assert naming_labels.MALIYET_ORANI_L == 10
    assert type(naming_labels.MALIYET_ORANI_L) is int


def test_ad_esigi_kesirle() -> None:
    L = naming_labels.MALIYET_ORANI_L
    assert naming_labels.AD_ESIGI == L / (L + 1)
    assert naming_labels.AD_ESIGI == 10 / 11
    assert Fraction(naming_labels.AD_ESIGI).limit_denominator(1000) == Fraction(10, 11)


def test_ad_esigi_yuvarlanmis_degil() -> None:
    """A-13'ün "0,909"u yazım; karşılaştırma kesirle: alt sınırı tam 0,909 olan kanal geçmez."""
    assert round(naming_labels.AD_ESIGI, 3) == 0.909
    assert naming_labels.AD_ESIGI > 0.909
    assert naming_labels.AD_ESIGI != 0.9  # 1 − e / L kullanılmaz (A-13)


def test_ad_esigi_belge_dizgisi_kurali_yaziyor() -> None:
    agac = ast.parse(Path(naming_labels.__file__).read_text(encoding="utf-8"))
    govde = agac.body
    for i, dugum in enumerate(govde):
        hedef = getattr(dugum, "target", None)
        if isinstance(dugum, ast.AnnAssign) and getattr(hedef, "id", None) == "AD_ESIGI":
            belge = govde[i + 1]
            break
    else:
        raise AssertionError("AD_ESIGI tanımı bulunamadı")
    assert isinstance(belge, ast.Expr) and isinstance(belge.value, ast.Constant)
    metin = belge.value.value
    for parca in ("A-2", "A-13", "A-14", "Wilson", "AD_ESIGI", "örnek düzeyinde",
                  "yön başına", "en az 3 bağımsız programda", "0,909"):
        assert parca in metin, parca
