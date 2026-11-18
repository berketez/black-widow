"""P15a / MEK-09 (a, b) ve TIP-10'un CLI tarafı.

Eski davranış: `karadul clean <olmayan>` önce silme onayı soruyordu (varlık denetimi
onaydan sonraydı); `karadul clean .` çalışma alanı kökünün kendisini, yani BÜTÜN
çalışma alanlarını siliyordu; `karadul score <boş dizin>` uyarısız `0.00/100` ve
çıkış 0 veriyordu; `score` puanının doğruluk ölçmediği hiçbir yerde yazmıyordu.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from karadul.cli import main as karadul_main


def _ws(tmp_path: Path) -> Path:
    root = tmp_path / "workspaces"
    (root / "hedef" / "20261118_000000").mkdir(parents=True)
    (root / "baska" / "20261118_000000").mkdir(parents=True)
    return root


def test_clean_missing_target_fails_before_asking(tmp_path: Path) -> None:
    root = _ws(tmp_path)
    res = CliRunner().invoke(karadul_main, ["clean", "yok", "--output-dir", str(root)])
    assert res.exit_code == 1
    assert "Workspace bulunamadı" in res.stderr
    assert "silinsin mi" not in res.output


def test_clean_dot_does_not_delete_all_workspaces(tmp_path: Path) -> None:
    root = _ws(tmp_path)
    res = CliRunner().invoke(karadul_main, ["clean", ".", "--output-dir", str(root), "--yes"])
    assert res.exit_code == 1
    assert root.is_dir() and (root / "baska").is_dir()


def test_clean_without_yes_noninteractive_keeps_dir(tmp_path: Path) -> None:
    root = _ws(tmp_path)
    res = CliRunner().invoke(karadul_main, ["clean", "hedef", "--output-dir", str(root)])
    assert res.exit_code == 1
    assert (root / "hedef").is_dir()
    assert "--yes" in res.stderr


def test_clean_with_yes_deletes_only_target(tmp_path: Path) -> None:
    root = _ws(tmp_path)
    res = CliRunner().invoke(karadul_main, ["clean", "hedef", "--output-dir", str(root), "--yes"])
    assert res.exit_code == 0, res.output
    assert not (root / "hedef").exists() and (root / "baska").is_dir()


def test_score_empty_dir_is_error(tmp_path: Path) -> None:
    empty = tmp_path / "bos"
    empty.mkdir()
    res = CliRunner().invoke(karadul_main, ["score", str(empty)])
    assert res.exit_code == 1
    assert "C dosyası yok" in res.stderr
    assert "0.00/100" not in res.output


def _c_tree(tmp_path: Path) -> Path:
    d = tmp_path / "src"
    d.mkdir()
    (d / "a.c").write_text(
        "// dosyayı aç\nint open_file(char *path) {\n  int fd = 0;\n  return fd;\n}\n",
        encoding="utf-8",
    )
    return d


def test_score_says_surface_metric(tmp_path: Path) -> None:
    res = CliRunner().invoke(karadul_main, ["score", str(_c_tree(tmp_path))],
                             terminal_width=200)
    assert res.exit_code == 0, res.output
    assert "YÜZEY ölçütüdür, doğruluk ölçmez" in res.output


def test_score_json_marks_measure(tmp_path: Path) -> None:
    res = CliRunner().invoke(karadul_main, ["score", str(_c_tree(tmp_path)), "--json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert payload["measure"] == "yuzey_olcutu"
    assert "doğruluk ölçmez" in payload["note"]
