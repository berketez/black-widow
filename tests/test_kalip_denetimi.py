"""Tam takımın düzenli ifade kapısı (BA-2; KARARLAR A-36).

``re`` eşleşmesi GIL'i bırakmaz ve SIGTERM'e yanıt vermez: üstel geri izleyen
bir kalıp süreci kilitlediğinde süreç içinden hiçbir bekçi koşamaz. Bu sınıf
ancak koda girmeden önlenir: ``karadul/`` + ``ui/server.py``'deki sabit
kalıplarda üstel sınıfa giren yeni bir kalıp bu testi kırmızı yapar.

Yanlış alarm çıkarsa kalıp, gerekçesi ve ölçülen süresiyle
``scripts/measurement/kalip_denetimi.py`` içindeki ``ISTISNALAR``'a girer ve
aşağıdaki beklenen sayı birlikte güncellenir.

Bütün düşmanca girdi ölçümleri ayrı bir çocuk süreçte, bekçiyle koşar
(``kalip_denetimi.toplu_dogrula``); takılan çocuk SIGKILL ile öldürülür.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK / "scripts" / "measurement"))

import kalip_denetimi as K  # noqa: E402

# İstisna listesinin beklenen uzunluğu (liste testte sayılır).
BEKLENEN_ISTISNA_SAYISI = 0

# Bilinen kusurlu kalıplar: BA-1'in üçü (block_annotator.py, main 0b4d948) ve
# BA-2'nin ikisi (c_namer.py, constraint_solver.py; main cfe93cef).
BILINEN_USTEL = {
    "ba1_memcpy": r"memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
    "ba1_memset": r"memset\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
    "ba1_memmove": r"memmove\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*((?:[^()]+|\([^)]*\))+)\s*\)",
    "ba2_cpp_zn": r"_ZN(\d+\w+)+E",
    "ba2_linked_list": (
        r"(?P<var>\w+)\s*=\s*\*\s*\(\s*"
        r"(?P<type>[a-zA-Z_](?:\w+\s*)*\*{0,2})\s*\*?\s*\)\s*\(\s*"
        r"(?P=var)\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\)"
    ),
}


@pytest.fixture(scope="module")
def kapi_raporu() -> tuple[list[dict], dict]:
    kaliplar, _dinamik = K.kapi_kaliplari()
    return kaliplar, K.denetle(kaliplar)


def test_kapi_sabit_kaliplarda_ustel_yok(kapi_raporu) -> None:
    kaliplar, rapor = kapi_raporu
    assert rapor["derlenemeyen"] == 0
    ustel = [(s["yer"], s["kalip"], s["dogrulama"].get("en_kisa")) for s in rapor["ustel"]]
    assert ustel == [], (
        "üstel geri izleyen kalıp (onar ya da ölçümle yanlış alarm olduğunu gösterip "
        f"ISTISNALAR'a ekle): {ustel}"
    )


def test_kapi_kapsami_korlesmedi(kapi_raporu) -> None:
    kaliplar, rapor = kapi_raporu
    dosyalar = {k["dosya"] for k in kaliplar}
    assert "ui/server.py" in dosyalar
    assert "karadul/reconstruction/recovery_layers/constraint_solver.py" in dosyalar
    assert "karadul/reconstruction/engineering/block_annotator.py" in dosyalar
    assert any(d.startswith("karadul/") and not d.startswith("karadul/reconstruction/")
               for d in dosyalar)
    # BA-2 ölçümü: 1 479 sabit kalıp; kapsam daralırsa (yol, işlev listesi) düşer.
    assert len(kaliplar) >= 1_400, len(kaliplar)
    # Durağan sınıflayıcının adayları devingen doğrulamaya gidiyor.
    assert rapor["aday_ic_ice"] >= 30, rapor["aday_ic_ice"]


def test_bilinen_kusurlu_kaliplar_ustel_bulunur() -> None:
    kayitlar = [{"dosya": f"bilinen/{ad}.py", "satir": 1, "kalip": k, "bayrak": 0}
                for ad, k in BILINEN_USTEL.items()]
    rapor = K.denetle(kayitlar)
    bulunan = sorted(s["dosya"] for s in rapor["ustel"])
    assert bulunan == sorted(k["dosya"] for k in kayitlar), rapor["adaylar"]


def test_istisna_listesi_sayili() -> None:
    assert len(K.ISTISNALAR) == BEKLENEN_ISTISNA_SAYISI
    for i in K.ISTISNALAR:
        assert {"dosya", "kalip", "gerekce", "olculen_sure"} <= set(i), i


def test_istisna_yalniz_kendi_kalibini_gecirir() -> None:
    kayitlar = [{"dosya": f"bilinen/{ad}.py", "satir": 1, "kalip": k, "bayrak": 0}
                for ad, k in BILINEN_USTEL.items()]
    istisna = [{"dosya": "bilinen/ba2_cpp_zn.py", "kalip": BILINEN_USTEL["ba2_cpp_zn"],
                "gerekce": "sınama", "olculen_sure": "sınama"}]
    rapor = K.denetle(kayitlar, istisnalar=istisna)
    assert [s["dosya"] for s in rapor["istisna_ile_gecen"]] == ["bilinen/ba2_cpp_zn.py"]
    assert len(rapor["ustel"]) == len(kayitlar) - 1


def test_bekci_takilan_cocugu_oldurup_ustel_sayar() -> None:
    sinif = K.siniflandir(BILINEN_USTEL["ba2_cpp_zn"], 0)
    aday = {"id": 7, "kalip": BILINEN_USTEL["ba2_cpp_zn"], "bayrak": 0,
            "denemeler": K.denemeler(BILINEN_USTEL["ba2_cpp_zn"], 0, sinif)}
    sonuc = K.toplu_dogrula([aday], zaman_asimi=0.3, en_kisa=True)
    assert sonuc[7]["ustel"] is True
    assert sonuc[7].get("zaman_asimi"), sonuc[7]


def test_onarilmis_kaliplar_ustel_degil() -> None:
    from karadul.reconstruction.recovery_layers.constraint_solver import _LINKED_LIST_RE

    kayitlar = [
        {"dosya": "c_namer", "satir": 1, "kalip": r"_ZN(\d\w+)E", "bayrak": 0},
        {"dosya": "constraint_solver", "satir": 1, "kalip": _LINKED_LIST_RE.pattern, "bayrak": 0},
    ]
    rapor = K.denetle(kayitlar)
    assert rapor["ustel"] == []


def test_sablon_toplama_yerlestirmeyi_ayirir(tmp_path: Path) -> None:
    f = tmp_path / "ornek.py"
    f.write_text(
        "import re\n"
        "AD = r'(a+)+b'\n"
        "re.compile(AD)\n"
        "def g(x, y):\n"
        "    re.search(rf'\\b{re.escape(x)}\\s*=', y)\n"
        "    re.search(rf'{x}(?:\\w+\\s*)*;', y)\n"
        "    re.search('|'.join(re.escape(s) for s in y), x)\n"
        "    re.search(x, y)\n",
        encoding="utf-8",
    )
    hepsi, dinamik = K.kaliplari_topla([f], sablonlar=True)
    turler = [(k["tur"], k["kalip"], k["kacissiz"]) for k in hepsi]
    assert dinamik == 5
    assert turler[0] == ("ad", "(a+)+b", [])
    assert turler[1] == ("sablon", r"\bQ\s*=", [])
    assert turler[2] == ("sablon", r"Q(?:\w+\s*)*;", ["x"])
    assert turler[3] == ("sablon", "Q|Q", [])
    assert turler[4][0] == "taranamadi"
