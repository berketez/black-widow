"""KİMLİK çift grupları (``scripts/measurement/kimlik_ciftler.py``) — kilit süzgeci ve grup tanımı sınamaları.

PLAN PK-6 / PK-11 "Sınama ve mutasyon": her grubun iki ikilisi farklı sha256, aynı program adı; kilitli ad süzgeci
(kilit belgelerindeki adlarla kesişim boş). Mutant "süzgeç boş" → kırmızı (``mutation_specs_kimlik_ciftler.json``).
Veri gerektiren sınamalar (``~/karadul_olcum``) veri yoksa atlanır; kilit sınamaları depodaki belgelerle koşar.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OLCUM = REPO / "scripts" / "measurement"
ARGE = REPO / "scripts" / "arge" / "kimlik"


def _modul(ad: str, yol: Path):
    if ad in sys.modules:
        return sys.modules[ad]
    spec = importlib.util.spec_from_file_location(ad, yol)
    m = importlib.util.module_from_spec(spec)
    sys.modules[ad] = m
    spec.loader.exec_module(m)
    return m


kc = _modul("kimlik_ciftler", OLCUM / "kimlik_ciftler.py")
VERI_VAR = kc.TABAN.is_dir() and (kc.TABAN / "debian" / "coreutils").is_dir()


# ------------------------------------------------------------------------------------------------
# Kilit süzgeci (veri gerektirmez)

def test_kilit_suzgeci_kilitli_adi_yakalar():
    kilitli = kc.kilitli_adlar()
    assert len(kilitli) > 50, "kilit belgelerinden ad okunamadı"
    # lua kilitli setin stres alt kümesinde (KARARLAR A-23); tree / zstd geliştirme setinde
    assert kc.kilit_suzgeci(["lua", "tree", "ZSTD"], kilitli) == ["lua"]
    assert kc.kilit_suzgeci(["LUA"], kilitli) == ["LUA"]          # harf duyarsız


def test_kilit_denetimi_kesisimde_durur():
    with pytest.raises(kc.KilitliAd):
        kc.kilit_denetimi("deneme", [("debian/lua/lua", "tabA/lua/lua")])
    # temiz grup geçer, aynı listeyi döner
    c = [("tabA/tree/tree", "debian/tree/tree")]
    assert kc.kilit_denetimi("deneme", c) == c


def test_grup_adlari_kumesi_program_ve_ikili_iceriyor():
    adlar = kc.grup_adlari_kumesi([("tabA/redis-tools/redis-cli", "debian/redis-tools/redis-cli"),
                                   ("v1gcc/redis-benchmark", "v1clang/redis-benchmark")])
    assert {"redis-tools", "redis-cli", "redis", "redis-benchmark"} <= adlar


def test_veri_yok_grubu_sessiz_bos_donmez():
    assert "iyilestirme" in kc.VERI_YOK
    with pytest.raises(LookupError):
        kc.grup("iyilestirme")


def test_program_adi():
    assert kc.program_adi("tabB12/redis-tools/redis-cli") == "redis"
    assert kc.program_adi("v1clang/redis-benchmark") == "redis"
    assert kc.program_adi("v1gcc/zstd") == "zstd"
    assert kc.program_adi("kitaplik/libzstd") == "zstd"
    assert kc.program_adi("debian/coreutils/cat") == "coreutils"
    assert kc.program_adi("debian/tmux") == "tmux"


def test_disarida_kalanlar_gruplarda_yok():
    secilen = {f"{p}/{b}" for p, b in kc.TABAKA_PROGRAMLARI}
    assert not secilen & set(kc.DISARIDA)


# ------------------------------------------------------------------------------------------------
# Grup tanımları (geliştirme seti dizini gerekir)

@pytest.mark.skipif(not VERI_VAR, reason="~/karadul_olcum geliştirme seti koşusu yok")
def test_butun_gruplar_kilit_disi_ve_tanimli():
    for g in kc.GRUP_ADLARI:
        if g in kc.VERI_YOK:
            continue
        c = kc.grup(g)
        assert c, g


@pytest.mark.skipif(not VERI_VAR, reason="~/karadul_olcum geliştirme seti koşusu yok")
def test_tur1_gruplari_aynen_tasindi():
    eski_yol = str(ARGE)
    sys.path.insert(0, eski_yol)
    try:
        eski = _modul("ciftler_tur1", ARGE / "ciftler.py")
    finally:
        sys.path.remove(eski_yol)
    for g in eski.CIFT_GRUPLARI:
        assert kc.grup(g) == eski.grup(g), g


@pytest.mark.skipif(not VERI_VAR, reason="~/karadul_olcum geliştirme seti koşusu yok")
def test_pk6_secimi_ve_yonler():
    assert len(kc.coreutils_secimi()) == 11
    assert len(kc.grup("mimari")) == 19
    assert len(kc.grup("derleyici_surumu")) == 38
    assert len(kc.yonler("mimari")) == 38
    assert kc.yonler("gomulu_kitaplik") == [("debian/zstd/zstd", "kitaplik/libzstd")]


def _sha(yol: Path) -> str:
    return hashlib.sha256(Path(yol).read_bytes()).hexdigest()


def _girdi_sha(kimlik: str) -> str:
    """Kimliğin analiz edilen ikilisinin sha256'sı (geliştirme seti: koşunun ``target_info.json``'ı)."""
    p = kimlik.split("/")
    if p[0] == "debian":
        kok = kc.TABAN / "debian" / p[1] / (p[2] if len(p) == 3 else p[1])
        ti = next((kok / "ws" / "workspaces").glob("*/*/raw/target_info.json"))
        return json.loads(ti.read_text(encoding="utf-8"))["file_hash"]
    sys.path.insert(0, str(ARGE))
    try:
        d0 = _modul("d0_veri", ARGE / "d0_veri.py")
    finally:
        sys.path.remove(str(ARGE))
    yol, _ = d0.girdi(kimlik)
    if not yol.is_file():
        pytest.skip(f"{kimlik}: girdi yok ({yol})")
    return _sha(yol)


@pytest.mark.skipif(not VERI_VAR, reason="~/karadul_olcum geliştirme seti koşusu yok")
@pytest.mark.parametrize("grup", ["mimari", "derleyici_surumu", "surum_esli", "surum_esli_platform", "gomulu_kitaplik"])
def test_cift_ayni_program_farkli_ikili(grup):
    for q, r in kc.grup(grup):
        assert kc.program_adi(q) == kc.program_adi(r), (q, r)
        assert _girdi_sha(q) != _girdi_sha(r), (q, r)
