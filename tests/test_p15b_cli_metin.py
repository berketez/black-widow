"""P15b kalem 6 — MEK-09 (d): CLI metinleri ASCII'ye kaçmış Türkçe ("calistir", "goster").

Bütün komut ve alt komutların ``--help`` çıktısında ASCII biçimli Türkçe sözcük
aranır (sözcük sınırıyla). Taban kodda ana yardımda bile "komutlari", "goster",
"yonetimi", "uret", "olc" vardı.
"""

from __future__ import annotations

import re

import click
import pytest
from click.testing import CliRunner

from karadul.cli import main

# Düzeltilen sözcüklerin ASCII biçimi (mekanik düzeltmenin haritası; ayrıntı P15b.md).
ASCII_TURKCE = (
    "acik ac AC adi anlamli araclarin aranir arasinda arasindaki asil atlaniyor ayni ayrilmis "
    "bastirilir bazli bulunamadi calistir calistirin calistirma calistirmak cikar cikarildi "
    "cikarimi cikti ciktilar degisiklik detayli dogru dosyasi dosyasini duzenlenmis edilmis "
    "erisimi esigi farki farklari formati goster gosterilir guvenlik hakkinda henuz hiz icin "
    "kapali kazanir kesfedilir komutlari konfigurasyon kullanici kullanilir modulu olc "
    "oldugundan olmali onceden secimi sonuc tabanli tum uret uretilmis ust uyari varsayilan "
    "veritabani yapi yavas yazdir yonetimi uzerinde Iki Gecersiz Gecerli Henuz DEGIL GIRDI"
).split()
_DESEN = re.compile(r"(?<![\w'])(" + "|".join(map(re.escape, ASCII_TURKCE)) + r")(?![\w'])")


def _komutlar(grup: click.Group, onek: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    out = [onek]
    for ad, alt in sorted(grup.commands.items()):
        if isinstance(alt, click.Group):
            out.extend(_komutlar(alt, onek + (ad,)))
        else:
            out.append(onek + (ad,))
    return out


@pytest.mark.parametrize("yol", _komutlar(main), ids=lambda y: " ".join(y) or "karadul")
def test_yardim_metninde_ascii_turkce_yok(yol: tuple[str, ...]) -> None:
    res = CliRunner().invoke(main, [*yol, "--help"], terminal_width=400)
    assert res.exit_code == 0, res.output
    # "--no-deep"/"enable_x" gibi seçenek ve tanıtıcılar sözcük sayılmaz (alt çizgi, tire).
    bulunan = sorted({m.group(1) for m in _DESEN.finditer(res.output.replace("-", " - "))})
    assert bulunan == [], f"{' '.join(yol)} --help: {bulunan}"
