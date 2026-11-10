"""Ghidra'nın decompiler uyarıları çıktıda korunur (çıktı sağlamlığı denetimi, kusur 12).

Kök neden: ``BinaryDeobfuscator.GHIDRA_ARTIFACTS`` içindeki iki kalıp
``/* WARNING: ... */`` ve ``/* DISPLAY WARNING ... */`` yorumlarını "Ghidra
artığı" sayıp siliyordu.  Ölçüm (119 ikili, 2026-11-10): ham çıktıda 78 182
uyarı (41 106 fonksiyon), son çıktıda 0.  Decompiler'ın "bu fonksiyon eksik
çözüldü" dediği yer (jumptable kurtarılamadı, tip yayılımı oturmadı, bozuk
komut) kullanıcıya ulaşmıyordu.  Aynı kalıp sqlite3'te bir dizgi sabitinin
içini de sildi: ``"/* WARNING: Script requires ... */\\n"`` -> ``"\\n"``.

Bu testler şunları sabitler:
  1. Uyarı yorumları dosyada bayt bayt kalır (tek satır, çok satır, sütun 0,
     gövde içi).
  2. Sayaçlar dürüst: ``ghidra_artifacts_cleaned`` yalnız silineni,
     ``ghidra_warnings_kept`` dosyada duran uyarıyı, ``ghidra_warnings_lost``
     arada düşeni sayar.
  3. Dizgi sabitinin içindeki uyarı görünümlü metin ne silinir ne sayılır.
  4. Üçüncü kalıp (``  /* @... */``) eskisi gibi silinir ve sayılır.
"""
from __future__ import annotations

import logging

import pytest

from karadul.config import Config
from karadul.deobfuscators.binary_deobfuscator import BinaryDeobfuscator


class _Workspace:
    """``get_stage_dir`` sunan en küçük çalışma alanı."""

    def __init__(self, root, sources: dict[str, str]):
        self._root = root
        raw = root / "static" / "ghidra_output" / "decompiled"
        raw.mkdir(parents=True)
        for name, text in sources.items():
            (raw / name).write_text(text, encoding="utf-8")
        (root / "deobfuscated").mkdir()

    def get_stage_dir(self, name: str):
        return self._root / name


def _run(tmp_path, sources: dict[str, str], deobf: BinaryDeobfuscator | None = None):
    ws = _Workspace(tmp_path, sources)
    result = (deobf or BinaryDeobfuscator(Config())).deobfuscate(ws)
    assert result.success is True
    out = {
        name: (tmp_path / "deobfuscated" / "decompiled" / name).read_text(encoding="utf-8")
        for name in sources
    }
    return result, out


# coreutils/tree ham çıktısından (FUN_001060e8, FUN_00104100, FUN_00105df4)
GOVDE_ICI = """\
// Function: FUN_001060e8
// Address:  001060e8


ulong FUN_001060e8(long *param_1,long *param_2)

{
  uint uVar1;
  ulong uVar2;

  if (*(byte *)(*param_2 + 0x10) == *(byte *)(*param_1 + 0x10)) {
                    /* WARNING: Could not recover jumptable at 0x00106110. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (*(code *)PTR_FUN_00130110)();
    return uVar2;
  }
  uVar1 = 0xffffffff;
  return (ulong)uVar1;
}
"""

SUTUN_SIFIR = """\
// Function: FUN_00104100
// Address:  00104100


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Type propagation algorithm not settling */

void FUN_00104100(int param_1,long param_2)

{
  if (param_1 == 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
"""


def test_govde_ici_uyarilar_bayt_bayt_korunur(tmp_path):
    result, out = _run(tmp_path, {"FUN_001060e8.c": GOVDE_ICI})
    assert out["FUN_001060e8.c"] == GOVDE_ICI
    assert result.stats["ghidra_warnings_kept"] == 2
    assert result.stats["ghidra_artifacts_cleaned"] == 0
    assert result.stats["ghidra_warnings_lost"] == 0


def test_sutun_sifir_ve_govde_ici_uyarilar_korunur(tmp_path):
    result, out = _run(tmp_path, {"FUN_00104100.c": SUTUN_SIFIR})
    assert out["FUN_00104100.c"] == SUTUN_SIFIR
    assert "/* WARNING: Type propagation algorithm not settling */\n" in out["FUN_00104100.c"]
    assert result.stats["ghidra_warnings_kept"] == 3
    assert result.stats["ghidra_artifacts_cleaned"] == 0


def test_cok_satirli_uyari_korunur_ve_tek_sayilir(tmp_path):
    src = (
        "/* WARNING: Removing unreachable block (ram,0x00105e04)\n"
        "   devam satırı\n"
        "   üçüncü satır */\n"
        "void FUN_00105df4(void)\n\n{\n  return;\n}\n"
    )
    result, out = _run(tmp_path, {"FUN_00105df4.c": src})
    assert out["FUN_00105df4.c"] == src
    assert result.stats["ghidra_warnings_kept"] == 1


def test_display_warning_korunur_ve_sayilir(tmp_path):
    src = (
        "int func(void)\n{\n"
        "  /* DISPLAY WARNING - bad instruction */\n"
        "  return 0;\n}\n"
    )
    result, out = _run(tmp_path, {"func.c": src})
    assert out["func.c"] == src
    assert result.stats["ghidra_warnings_kept"] == 1
    assert result.stats["ghidra_artifacts_cleaned"] == 0


def test_bosluksuz_uyari_basi_da_sayilir(tmp_path):
    src = "/*WARNING: x */\n/*   WARNING: y */\n/*\n WARNING: z */\nint f;\n"
    result, out = _run(tmp_path, {"f.c": src})
    assert out["f.c"] == src
    assert result.stats["ghidra_warnings_kept"] == 3


def test_sayac_dosyalar_uzerinden_toplanir(tmp_path):
    result, out = _run(tmp_path, {
        "FUN_001060e8.c": GOVDE_ICI,
        "FUN_00104100.c": SUTUN_SIFIR,
        "temiz.c": "int temiz(void)\n{\n  return 0;\n}\n",
    })
    assert result.stats["ghidra_warnings_kept"] == 5
    assert result.stats["ghidra_artifacts_cleaned"] == 0
    assert result.stats["ghidra_warnings_lost"] == 0
    assert out["temiz.c"] == "int temiz(void)\n{\n  return 0;\n}\n"


def test_uyarisiz_girdide_sayaclar_sifir_ama_var(tmp_path):
    result, _ = _run(tmp_path, {"temiz.c": "int temiz(void)\n{\n  return 0;\n}\n"})
    assert result.stats["ghidra_warnings_kept"] == 0
    assert result.stats["ghidra_warnings_lost"] == 0
    assert result.stats["ghidra_artifacts_cleaned"] == 0


def test_dizgi_icindeki_uyari_metni_silinmez_ve_sayilmaz(tmp_path):
    """sqlite3 FUN_001304a0: ikilinin kendi dizgisi uyarı kalıbına uyuyor."""
    src = (
        "void FUN_001304a0(void)\n\n{\n"
        '  FUN_1("/* WARNING: Script requires that SQLITE_DBCONFIG_DEFENSIVE be disabled */\\n");\n'
        "                    /* WARNING: Subroutine does not return */\n"
        "  exit(1);\n}\n"
    )
    result, out = _run(tmp_path, {"FUN_001304a0.c": src})
    assert out["FUN_001304a0.c"] == src
    assert (
        '"/* WARNING: Script requires that SQLITE_DBCONFIG_DEFENSIVE be disabled */\\n"'
        in out["FUN_001304a0.c"]
    )
    # Yalnız gerçek yorum sayılır
    assert result.stats["ghidra_warnings_kept"] == 1
    assert result.stats["ghidra_artifacts_cleaned"] == 0


def test_satir_yorumu_ve_karakter_sabiti_icindeki_metin_sayilmaz(tmp_path):
    src = (
        "// /* WARNING: satır yorumu içinde */\n"
        "int f(void)\n{\n"
        "  c = '\"'; /* WARNING: gerçek */ d = '\"';\n"
        "  return 0;\n}\n"
    )
    result, out = _run(tmp_path, {"f.c": src})
    assert out["f.c"] == src
    assert result.stats["ghidra_warnings_kept"] == 1


def test_uyari_olmayan_yorum_sayilmaz(tmp_path):
    src = (
        "/* not a WARNING: x */\n/* INFO: WARNING: y */\n"
        "/* WARNING yok iki nokta */\n/* warning: küçük harf */\n"
        "int f;\n"
    )
    result, out = _run(tmp_path, {"f.c": src})
    assert out["f.c"] == src
    assert result.stats["ghidra_warnings_kept"] == 0


def test_ucuncu_kalip_eskisi_gibi_silinir_ve_sayilir(tmp_path):
    """``  /* @... */`` açıklama yorumları bu işin dışında: davranış aynı."""
    src = (
        "/* WARNING: Subroutine does not return */\n"
        "int f(void)\n{\n"
        "  x = 1;  /* @annotation bir */\n"
        "  y = 2;  /* @iki */  /*@ üç */\n"
        "  return 0;\n}\n"
    )
    result, out = _run(tmp_path, {"f.c": src})
    assert out["f.c"] == (
        "/* WARNING: Subroutine does not return */\n"
        "int f(void)\n{\n"
        "  x = 1;\n"
        "  y = 2;\n"
        "  return 0;\n}\n"
    )
    assert result.stats["ghidra_artifacts_cleaned"] == 3
    assert result.stats["ghidra_warnings_kept"] == 1
    assert result.stats["ghidra_warnings_lost"] == 0


def test_clean_ghidra_artifacts_uyariyi_saymaz_ve_silmez():
    deobf = BinaryDeobfuscator(Config())
    src = "/* WARNING: a */\n/* DISPLAY WARNING b */\n  /* @c */ x;\n"
    content, cleaned = deobf._clean_ghidra_artifacts(src)
    assert content == "/* WARNING: a */\n/* DISPLAY WARNING b */\n x;\n"
    assert cleaned == 1


def test_ghidra_artifacts_listesinde_uyari_kalibi_yok():
    """Sınıf sabiti: uyarı kalıpları temizlik listesine geri dönmemeli."""
    for pattern in BinaryDeobfuscator.GHIDRA_ARTIFACTS:
        assert not pattern.search("/* WARNING: Subroutine does not return */")
        assert not pattern.search("/* DISPLAY WARNING - bad instruction */")
    assert len(BinaryDeobfuscator.GHIDRA_ARTIFACTS) == 1


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", 0),
        ("int f;", 0),
        ("/* WARNING: a */", 1),
        ("/* WARNING: a */ /* WARNING: b */", 2),
        ("/* WARNING: kapanmayan yorum", 1),          # dosya sonuna kadar tek yorum
        ('"/* WARNING: a */"', 0),
        ('"kapanmayan /* WARNING: a */', 1),          # dizgi kapanmadı: yorum gerçek
        ("// /* WARNING: a */", 0),
        ("/* x */ /* WARNING: a */", 1),
        ("/* x /* WARNING: a */", 0),                 # dıştaki yorumun içi
        ("a = b /* WARNING: c */ / d;", 1),
        ("/* DISPLAY WARNING */", 1),
        ("/* DISPLAYWARNING */", 0),
    ],
)
def test_count_ghidra_warnings(text, expected):
    assert BinaryDeobfuscator(Config())._count_ghidra_warnings(text) == expected


def test_arada_dusen_uyari_ayri_sayaca_yazilir(tmp_path, caplog):
    """Sonraki adım uyarı taşıyan bloğu atarsa kayıp sessiz kalmaz."""
    deobf = BinaryDeobfuscator(Config())
    real = deobf._opaque_detector.eliminate_in_code

    def drop_one(content):
        new_content, res = real(content)
        return new_content.replace(
            "                    /* WARNING: Treating indirect jump as call */\n", "",
        ), res

    deobf._opaque_detector.eliminate_in_code = drop_one  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING, logger="karadul.deobfuscators.binary_deobfuscator"):
        result, out = _run(tmp_path, {
            "FUN_001060e8.c": GOVDE_ICI, "FUN_00104100.c": SUTUN_SIFIR,
        }, deobf)

    assert "Treating indirect jump" not in out["FUN_001060e8.c"]
    assert "Could not recover jumptable" in out["FUN_001060e8.c"]
    # kept = dosyada gerçekten duran; lost = girişte olup çıkışta olmayan
    assert result.stats["ghidra_warnings_kept"] == 4
    assert result.stats["ghidra_warnings_lost"] == 1
    assert result.stats["ghidra_artifacts_cleaned"] == 0
    dusen = [r for r in caplog.records if "düştü" in r.getMessage()]
    assert len(dusen) == 1
    assert "FUN_001060e8.c" in dusen[0].getMessage()


def test_kayip_yokken_gunluge_uyari_yazilmaz(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="karadul.deobfuscators.binary_deobfuscator"):
        result, _ = _run(tmp_path, {"FUN_001060e8.c": GOVDE_ICI})
    assert result.stats["ghidra_warnings_lost"] == 0
    assert not [r for r in caplog.records if "düştü" in r.getMessage()]


def test_ozet_gunlugu_korunan_uyari_sayisini_yazar(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="karadul.deobfuscators.binary_deobfuscator"):
        _run(tmp_path, {"FUN_001060e8.c": GOVDE_ICI, "FUN_00104100.c": SUTUN_SIFIR})
    ozet = [r.getMessage() for r in caplog.records if "tamamlandi" in r.getMessage()]
    assert len(ozet) == 1
    assert "5 Ghidra uyarısı korundu" in ozet[0]
    assert ozet[0].startswith("Binary deobfuscation tamamlandi: 0 temizlik")


def test_ham_dizin_degismez(tmp_path):
    """Deobfuscation kopya üzerinde çalışır; Ghidra'nın ham çıktısı aynı kalır."""
    _run(tmp_path, {"FUN_00104100.c": SUTUN_SIFIR})
    raw = tmp_path / "static" / "ghidra_output" / "decompiled" / "FUN_00104100.c"
    assert raw.read_text(encoding="utf-8") == SUTUN_SIFIR
