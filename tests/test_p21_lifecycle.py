"""P21 / LM-05 + B-E5 — yerel model sunucusu ana süreç ölünce yetim kalmaz; anahtar komut satırında görünmez.

Kusur (``kulvar_LM.md`` LM-05, B-E5): sunucu kendi süreç grubunda açılıyor, kapanışı yalnız ``atexit``
ve hata yollarına bağlıydı. ``atexit`` SIGKILL'de ve ``os._exit``'te (arayüzün ebeveyn bekçisi tam bunu
kullanıyor) çalışmaz: ~16 GiB ``mlock``'lu sunucu geride kalırdı. API anahtarı ``--api-key`` ile komut
satırındaydı (``ps`` her kullanıcıya gösterir).

Gerçek süreç sınaması: sahte ``llama-server`` (yalnız uyuyan bir Python betiği) ve onu başlatan ayrı bir
"ana süreç"; ana süreç ``os._exit`` ya da SIGKILL ile ölür, sunucunun kapandığı beklenir. Model yok, ağ
yok (HTTP taşıyıcısı sahte).

Mutasyon koruması: ``scripts/measurement/mutation_specs_p21.json``.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from karadul.lm import backend as B
from tests.test_lm_backend import ANAHTAR, KAPI, SahteBekci, SahteTasiyici, _arka_uc

KOK = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------------------------
# Birim: bekçi kurulur ve kapatılır; anahtar ortamda; anahtarsız istek denetimi


def test_bekci_kurulur_ve_durdurmada_kapatilir(tmp_path):
    bekci = SahteBekci()
    b, _ = _arka_uc(tmp_path, bekci=bekci)
    b.start()
    assert bekci.cagrilar == [(4321, str(b.binary), KAPI)] and b.identity()["ebeveyn_bekcisi"] == 9000
    b.stop()
    assert bekci.surecler[0].terminate_sayisi == 1
    # başlatma hatasında da bekçi kapatılır (sunucu hazır olmadı)
    bekci2 = SahteBekci()
    b2, _ = _arka_uc(tmp_path / "2", bekci=bekci2, tasiyici=SahteTasiyici(saglik=(503,)), hazir_suresi=4.0)
    with pytest.raises(B.BackendError):
        b2.start()
    assert len(bekci2.cagrilar) == 1 and bekci2.surecler[0].terminate_sayisi == 1


def test_anahtar_ortamda_ve_sunucu_onu_uygulamali(tmp_path):
    b, _ = _arka_uc(tmp_path / "1", tasiyici=SahteTasiyici(props=200))  # sunucu anahtarı okumadı
    with pytest.raises(B.BackendError) as ei:
        b.start()
    assert "LLAMA_API_KEY" in str(ei.value) and b.state == B.STATE_ERROR and not b.pid_file.exists()
    b, _ = _arka_uc(tmp_path / "2", tasiyici=SahteTasiyici(props=404))  # uç yok: doğrulanamadı, uydurma yok
    b.start()
    assert b.identity()["anahtar_denetimi"] == "dogrulanamadi:http_404"
    tasiyici = SahteTasiyici()
    b, _ = _arka_uc(tmp_path / "3", tasiyici=tasiyici)
    b.start()
    assert b.identity()["anahtar_denetimi"] == "zorunlu"
    props = [c for c in tasiyici.cagrilar if c["url"].endswith("/props")]
    assert len(props) == 1 and "Authorization" not in props[0]["headers"]   # anahtarsız sorulur
    assert all(c["headers"].get("Authorization") == f"Bearer {ANAHTAR}" for c in tasiyici.cagrilar
               if c["url"].endswith("/health"))


# --------------------------------------------------------------------------------------------
# Gerçek süreç: ana süreç ölünce sunucu kapanır


_SAHTE_SUNUCU = """#!{python}
import sys, time
if "--version" in sys.argv:
    print("version: sahte (build 0)")
    sys.exit(0)
time.sleep(120)
"""

_ANA_SUREC = r"""
import json, os, signal, sys
from pathlib import Path
from karadul.lm import backend as B

ikili, model, durum, kip, bekci = sys.argv[1:6]

def tasima(method, url, headers, body, timeout):
    if url.endswith("/props"):
        raise B.HttpStatusError(401, "")
    return B.HttpResponse(200, iter(()), lambda: b"", lambda: None)

b = B.LlamaServerBackend(Path(ikili), Path(model), Path(durum), transport=tasima, ready_timeout=30,
                         **({} if bekci == "1" else {"watchdog": None}))
b.start()
w = b.identity()["ebeveyn_bekcisi"]
print(json.dumps({"sunucu": b.pid, "bekci": w}), flush=True)
if kip == "exit":
    os._exit(0)
os.kill(os.getpid(), signal.SIGKILL)
"""


def _yasiyor(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(out) and not out.startswith("Z")


def _bekle_olsun(pid: int, sure: float) -> bool:
    son = time.monotonic() + sure
    while time.monotonic() < son:
        if not _yasiyor(pid):
            return True
        time.sleep(0.2)
    return False


def _kos(tmp_path, kip: str, bekci: bool) -> dict:
    ikili = tmp_path / "llama-server"
    ikili.write_text(_SAHTE_SUNUCU.format(python=sys.executable), encoding="utf-8")
    ikili.chmod(0o755)
    model = tmp_path / "m.gguf"
    model.write_bytes(b"GGUF")
    env = {**os.environ, "HOME": str(tmp_path / "ev"), "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([sys.executable, "-c", _ANA_SUREC, str(ikili), str(model), str(tmp_path / "durum"), kip,
                        "1" if bekci else "0"], cwd=KOK, env=env, capture_output=True, text=True, timeout=120)
    satir = [s for s in r.stdout.splitlines() if s.startswith("{")]
    assert satir, (r.returncode, r.stdout, r.stderr[-2000:])
    return json.loads(satir[-1])


@pytest.mark.parametrize("kip", ["exit", "sigkill"])
def test_ana_surec_olunce_sunucu_kapanir(tmp_path, kip):
    pids = _kos(tmp_path, kip, bekci=True)
    assert isinstance(pids["sunucu"], int) and isinstance(pids["bekci"], int)
    try:
        assert _bekle_olsun(pids["sunucu"], 20.0), "sunucu yetim kaldı"
        assert _bekle_olsun(pids["bekci"], 10.0), "bekçi çıkmadı"
    finally:
        for p in (pids["sunucu"], pids["bekci"]):
            if _yasiyor(p):
                os.kill(p, signal.SIGKILL)


def test_bekcisiz_sunucu_yetim_kalir_kusurun_gosterimi(tmp_path):
    """Kusurun kendisi: bekçi kapalıyken ``os._exit`` sonrası sunucu yaşamaya devam eder."""
    pids = _kos(tmp_path, "exit", bekci=False)
    try:
        assert pids["bekci"] is None
        time.sleep(3.0)
        assert _yasiyor(pids["sunucu"])
    finally:
        if _yasiyor(pids["sunucu"]):
            os.kill(pids["sunucu"], signal.SIGKILL)
