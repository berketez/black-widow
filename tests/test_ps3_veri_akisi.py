"""P-S3 kalem 2: veri akışı kenar sayısı aynı girdiyle belirlenimci.

``InterProceduralDataFlow.analyze`` dosyaları iş parçacıklarında çözümler. Eskiden sonuçlar BİTİŞ
sırasıyla (``as_completed``) birleşiyordu: aynı fonksiyon adını birden çok dosya tanımlayınca
(Ghidra'nın aynı adlı thunk / dış kayıt fonksiyonları: ``free.c`` ve ``free_00135198.c``) hangi
gövdenin kaldığı koşudan koşuya değişiyor, çapraz fonksiyon kenarları da onunla değişiyordu (aynı
girdiyle htop 4 286 ↔ 4 273, tree 123 ↔ 131). Şimdi sonuçlar GİRDİ sırasıyla birleşir ve aynı ad
için ilk dosyanın (eksiz ``ad.c``) gövdesi tutulur.

Sınama: bitiş sırası ``as_completed`` yamasıyla iki uca zorlanır (gönderim sırası ve tersi); iki
koşunun kenar kümesi aynı olmalı ve eksiz dosyanın gövdesinden çıkan kenar bulunmalı.
"""

from __future__ import annotations

import json
from concurrent.futures import wait
from pathlib import Path

import pytest

from karadul.reconstruction.engineering import data_flow as DF


def _girdi(tmp_path: Path) -> dict[str, Path]:
    d = tmp_path / "decompiled"
    d.mkdir()
    # Ayırıcı bellek ayırıp tamponu release_buf'a veriyor.
    (d / "alloc_user.c").write_text(
        "void alloc_user(void)\n{\n  long buf;\n  buf = malloc(0x10);\n  release_buf(buf);\n"
        "  return;\n}\n", encoding="utf-8")
    # Aynı adı iki dosya tanımlıyor: eksiz dosya (adres sırasında ilk) gerçek gövde, ekli dosya
    # Ghidra'nın dış kayıt yer tutucusu (gövde yok).
    (d / "release_buf.c").write_text(
        "void release_buf(void *param_1)\n{\n  free(param_1);\n  return;\n}\n", encoding="utf-8")
    (d / "release_buf_00135198.c").write_text(
        "void release_buf(void *param_1)\n{\n  halt_baddata();\n}\n", encoding="utf-8")
    cg = {"nodes": {
        "00101000": {"name": "alloc_user", "callers": [],
                     "callees": [{"name": "malloc"}, {"name": "release_buf"}]},
        "00102000": {"name": "release_buf", "callers": [{"name": "alloc_user"}],
                     "callees": [{"name": "free"}]},
    }}
    (tmp_path / "cg.json").write_text(json.dumps(cg), encoding="utf-8")
    (tmp_path / "functions.json").write_text(json.dumps({"functions": []}), encoding="utf-8")
    return {"decompiled_dir": d, "functions_json": tmp_path / "functions.json",
            "call_graph_json": tmp_path / "cg.json"}


def _kos(monkeypatch, girdi: dict[str, Path], ters: bool):
    """``as_completed``'i bütün işler bitince gönderim sırasıyla (ya da tersiyle) verecek biçimde yamala."""

    def sirali(futures, timeout=None):
        sira = list(futures)
        wait(sira)
        return iter(reversed(sira) if ters else sira)

    monkeypatch.setattr(DF, "as_completed", sirali)
    r = DF.InterProceduralDataFlow().analyze(**girdi)
    assert r.success
    kume = {(e.source_func, e.target_func, e.flow_type, e.data_name) for e in r.graph.edges}
    return r.total_edges, kume


def test_bitis_sirasi_sonucu_degistirmez(tmp_path, monkeypatch):
    girdi = _girdi(tmp_path)
    ileri = _kos(monkeypatch, girdi, ters=False)
    geri = _kos(monkeypatch, girdi, ters=True)
    assert ileri == geri


def test_ayni_adda_eksiz_dosyanin_govdesi(tmp_path, monkeypatch):
    """release_buf için eksiz dosyanın gövdesi (free çağırır) tutulur: ayırıcı → serbest bırakan kenarı."""
    girdi = _girdi(tmp_path)
    for ters in (False, True):
        _, kume = _kos(monkeypatch, girdi, ters=ters)
        assert ("alloc_user", "release_buf", "allocation_chain", "alloc_buf_lifecycle") in kume


def test_hata_iletileri_girdi_sirasiyla(tmp_path, monkeypatch):
    """Çözümlenemeyen dosyaların iletileri bitiş sırasından bağımsız, girdi sırasıyla."""
    girdi = _girdi(tmp_path)
    eski = DF.InterProceduralDataFlow._analyze_file

    def bozuk(self, filepath, func_info, cg_nodes):
        if filepath.name != "alloc_user.c":
            raise ValueError(f"bozuk {filepath.name}")
        return eski(self, filepath, func_info, cg_nodes)

    monkeypatch.setattr(DF.InterProceduralDataFlow, "_analyze_file", bozuk)
    iletiler = []
    for ters in (False, True):
        def sirali(futures, timeout=None, _ters=ters):
            sira = list(futures)
            wait(sira)
            return iter(reversed(sira) if _ters else sira)
        monkeypatch.setattr(DF, "as_completed", sirali)
        r = DF.InterProceduralDataFlow().analyze(**girdi)
        iletiler.append([e for e in r.errors if "bozuk" in e])
    assert iletiler[0] == iletiler[1]
    assert [e.split("for ")[1].split(":")[0] for e in iletiler[0]] == [
        "release_buf.c", "release_buf_00135198.c"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
