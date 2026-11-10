"""Paralel decompile'da aynı adlı fonksiyonların dosya adı yarışı (2026-11-10).

Kök neden: ``GhidraHeadless._decompile_single_function`` önce ``exists()`` ile bakıp sonra
yazıyordu. Aynı adlı iki fonksiyon (ör. iki PLT thunk'ı) farklı iş parçacıklarında denetimi
birlikte geçince ikisi de ``ad.c``'ye yazıyor, biri kayboluyordu. 117 Debian koşusunun 5'inde
birer fonksiyon böyle kayıptı (``decompiled.json`` başarı sayısı dosya sayısından 1 fazla).

Testler Ghidra istemez: gerçek fonksiyon sahte Ghidra nesneleriyle çağrılır; üç üst veri
çıkarıcı sabit değer döndürür, dosya adı seçimi ve yazma kodu olduğu gibi çalışır.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from karadul.ghidra.headless import GhidraHeadless

XREF = {"caller_count": 0, "callee_count": 0, "callers": [], "callees": []}


class _Govde:
    def getNumAddresses(self):
        return 4


class _Fonk:
    def __init__(self, ad, adres):
        self._ad, self._adres = ad, adres

    def getName(self):
        return self._ad

    def getEntryPoint(self):
        return self._adres

    def getBody(self):
        return _Govde()


class _CFonk:
    def __init__(self, fonk):
        self._fonk = fonk

    def getC(self):
        return "void %s(void)\n{\n  return; /* %s */\n}\n" % (self._fonk.getName(), self._fonk.getEntryPoint())


class _Sonuc:
    def __init__(self, fonk):
        self._fonk = fonk

    def getDecompiledFunction(self):
        return _CFonk(self._fonk)


class _Decomp:
    def decompileFunction(self, func, timeout, monitor):
        return _Sonuc(func)


@pytest.fixture
def sahte_cikaricilar(monkeypatch):
    monkeypatch.setattr(GhidraHeadless, "_extract_disassembly", staticmethod(lambda program, func: []))
    monkeypatch.setattr(GhidraHeadless, "_extract_stack_frame", staticmethod(lambda func: None))
    monkeypatch.setattr(GhidraHeadless, "_extract_func_xrefs", staticmethod(lambda program, func: dict(XREF)))


def _yaz(fonk, hedef):
    return GhidraHeadless._decompile_single_function(_Decomp(), fonk, None, hedef, 30, None)


def _adresler(hedef):
    """Diskteki her dosyanın başlığındaki adres (dosyanın kimliği)."""
    bulunan = []
    for dosya in sorted(hedef.glob("*.c")):
        for satir in dosya.read_text(encoding="utf-8").splitlines():
            if satir.startswith("// Address:"):
                bulunan.append(satir.split(":", 1)[1].strip())
                break
    return sorted(bulunan)


def test_sirali_yazmada_ikinci_ayni_adli_fonksiyon_adres_eki_alir(tmp_path, sahte_cikaricilar):
    a = _yaz(_Fonk("memcmp", "00101df8"), tmp_path)
    b = _yaz(_Fonk("memcmp", "0012c160"), tmp_path)
    assert a["success"] and b["success"]
    assert a["file"] == "memcmp.c"
    assert b["file"] == "memcmp_0012c160.c"          # kayıt, gerçekten yazılan dosyayı gösterir
    assert sorted(p.name for p in tmp_path.glob("*.c")) == ["memcmp.c", "memcmp_0012c160.c"]
    assert _adresler(tmp_path) == ["00101df8", "0012c160"]
    # ilk dosya ezilmedi
    assert "00101df8" in (tmp_path / "memcmp.c").read_text(encoding="utf-8")


def test_iki_is_parcacigi_ayni_anda_yazinca_dosya_kaybolmaz(tmp_path, monkeypatch, sahte_cikaricilar):
    """Bariyer iki iş parçacığını yazmadan hemen önce buluşturur (eski kodda: exists()'ten sonra)."""
    bariyer = threading.Barrier(2, timeout=5)

    class BariyerliXref(dict):
        def __getitem__(self, anahtar):
            if anahtar == "caller_count":
                try:
                    bariyer.wait()
                except threading.BrokenBarrierError:
                    pass
            return dict.__getitem__(self, anahtar)

    monkeypatch.setattr(
        GhidraHeadless, "_extract_func_xrefs", staticmethod(lambda program, func: BariyerliXref(XREF)),
    )
    fonklar = [_Fonk("memcmp", "00101df8"), _Fonk("memcmp", "0012c160")]
    with ThreadPoolExecutor(max_workers=2) as havuz:
        sonuclar = list(havuz.map(lambda f: _yaz(f, tmp_path), fonklar))
    assert all(s["success"] for s in sonuclar)
    assert len(list(tmp_path.glob("*.c"))) == 2
    assert _adresler(tmp_path) == ["00101df8", "0012c160"]
    # her kayıt var olan, kendi adresini taşıyan dosyayı gösterir
    for s in sonuclar:
        assert s["address"] in (tmp_path / s["file"]).read_text(encoding="utf-8")
    assert len({s["file"] for s in sonuclar}) == 2


def test_dokuz_is_parcaciginda_ayni_adlar_hic_kaybolmaz(tmp_path, sahte_cikaricilar):
    """Zorlamasız en kötü durum: her ad her parçada var (9 parça × 32 ad)."""
    parca_sayisi, parca_boyu = 9, 32
    parcalar = [
        [_Fonk(f"dup_{i}", "%08x" % (0x100000 + p * 0x10000 + i * 4)) for i in range(parca_boyu)]
        for p in range(parca_sayisi)
    ]
    beklenen = sorted(f.getEntryPoint() for parca in parcalar for f in parca)
    for tur in range(5):
        hedef = tmp_path / f"tur{tur}"
        hedef.mkdir()
        with ThreadPoolExecutor(max_workers=parca_sayisi) as havuz:
            sonuclar = [
                s for liste in havuz.map(lambda parca, h=hedef: [_yaz(f, h) for f in parca], parcalar)
                for s in liste
            ]
        assert sum(1 for s in sonuclar if s["success"]) == parca_sayisi * parca_boyu
        assert _adresler(hedef) == beklenen
        assert len({s["file"] for s in sonuclar}) == parca_sayisi * parca_boyu
