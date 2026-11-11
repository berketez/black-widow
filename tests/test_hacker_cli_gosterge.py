"""Canlı CLI ekranında sahte gösterge yok.

Eski kod bir CPU yüzdesini rastgele sayıyla (``random.randint(78, 99)``) üretiyor ve aşama
sürerken hazır bir listeden eylem metinlerini zamanlayıcıyla döndürüyordu. Ekrandaki her sayı ve
metin gerçek bir olaydan gelmelidir; gerçek veri yoksa gösterge hiç çizilmez.
"""

from __future__ import annotations

import io
import time

import pytest

hacker_cli = pytest.importorskip("karadul.hacker_cli")


def _metin(renderable) -> str:
    from rich.console import Console

    tampon = io.StringIO()
    Console(file=tampon, width=140, force_terminal=False, color_system=None).print(renderable)
    return tampon.getvalue()


def _durum(**alanlar):
    durum = hacker_cli.LiveAnalysisState(target_name="hedef", target_type="elf", total_stages=5,
                                         start_time=time.monotonic() - 10.0)
    for ad, deger in alanlar.items():
        setattr(durum, ad, deger)
    return durum


def test_modul_rastgele_sayi_ureteci_kullanmaz():
    assert not hasattr(hacker_cli, "random")


def test_canli_panelde_cpu_yuzdesi_yok():
    durum = _durum(current_stage="static", current_action="Running static...", is_running=True)
    assert "CPU" not in _metin(hacker_cli._build_live_panel(durum))


def test_canli_panel_ayni_durumda_ayni_metni_verir():
    durum = _durum(current_stage="static", current_action="Running static...", is_running=True,
                   start_time=0.0)
    durum.start_time = 0.0  # geçen süre gösterilmesin diye başlamamış sayılır
    ilk = _metin(hacker_cli._build_live_panel(durum))
    assert all(_metin(hacker_cli._build_live_panel(durum)) == ilk for _ in range(5))


def test_eylem_metni_zamanlayiciyla_degismez():
    durum = _durum(current_stage="static", current_action="Running static...", is_running=True)
    pano = hacker_cli._LiveDashboard(durum)
    for _ in range(200):
        list(pano.__rich_console__(None, None))
    assert durum.current_action == "Running static..."
