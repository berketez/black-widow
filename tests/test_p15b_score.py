"""P15b kalem 5 — TIP-10: `karadul score` doğruluk ölçmüyor; sabit 100 baseline kaldırıldı.

Taban (P15a sonrası): çıktıda "yüzey ölçütü" notu vardı ama ``compare`` debug
puanını tanım gereği 100 alıyor, ``normalized`` = yeniden kurulan puan; rastgele
İngilizce adlı ağaç gerçek adlı ağaçla aynı "debug'a göre %X" iddiasını alıyordu.
Debug bilgisi yoksa 0.0 yazılıyordu (uydurma sayı).
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from karadul.cli import main
from karadul.quality import ReadabilityScorer
from karadul.quality.dwarf_baseline import DwarfBaselineResult

GOVDE = """
int {a}(char *buffer, int length)
{{
  int count = 0;
  for (int index = 0; index < length; index++) {{
    if (buffer[index] == '\\n') {{
      count = count + 1;
    }}
  }}
  return count;
}}

void {b}(const char *path)
{{
  {a}((char *)path, 4);
}}
"""


def _agac(kok: Path, a: str, b: str) -> Path:
    kok.mkdir(parents=True)
    (kok / "m.c").write_text(GOVDE.format(a=a, b=b), encoding="utf-8")
    return kok


def test_rastgele_ve_gercek_ad_ayni_dogruluk_iddiasini_almaz(tmp_path: Path) -> None:
    gercek = _agac(tmp_path / "gercek", "count_newlines", "print_lines")
    rastgele = _agac(tmp_path / "rastgele", "banana_window", "velvet_cloud")
    sc = ReadabilityScorer()
    bl = DwarfBaselineResult(score=None, available=True, statistics={"function_count": 2})
    rg, rr = sc.score_directory(gercek), sc.score_directory(rastgele)
    # Yüzey puanı adın DOĞRU olup olmadığını bilmez; hangisi yüksek çıkarsa çıksın
    # hiçbirine doğruluk / "debug'a göre %" iddiası verilmez.
    for r in (rg, rr):
        c = sc.compare(bl, r)
        assert c.baseline_score is None
        assert c.normalized is None
        assert c.accuracy is None


def test_cli_json_baseline_uydurma_sayi_yazmaz(tmp_path: Path) -> None:
    d = _agac(tmp_path / "src", "count_newlines", "print_lines")
    debugsiz = tmp_path / "ikili"
    debugsiz.write_bytes(b"\x7fELF" + b"\0" * 60)
    res = CliRunner().invoke(main, ["score", str(d), "--json", "--baseline", str(debugsiz)])
    assert res.exit_code == 0, res.output
    out = json.loads(res.output[res.output.index("{"):])
    assert out["measure"] == "yuzey_olcutu"
    assert "sabit 100" not in out["note"]
    cmp = out["compare"]
    assert cmp["baseline_score"] is None and cmp["normalized"] is None and cmp["delta"] is None
    assert cmp["accuracy"] is None
    assert cmp["baseline_available"] is False


def test_cli_tablo_debug_yuzdesi_vermez(tmp_path: Path) -> None:
    d = _agac(tmp_path / "src", "count_newlines", "print_lines")
    debugsiz = tmp_path / "ikili"
    debugsiz.write_bytes(b"\x7fELF" + b"\0" * 60)
    res = CliRunner().invoke(main, ["score", str(d), "--baseline", str(debugsiz)],
                             terminal_width=300)
    assert res.exit_code == 0, res.output
    assert "reconstructed/baseline" not in res.output
    assert "Doğruluk ölçülmedi" in res.output
