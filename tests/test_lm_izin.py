"""P22e kalem 2-3 — kipler ve izin modeli (KaradulLM v2 tasarımı §3.4, §3.9).

  (a) izin tablosu tasarımla aynı; ``uygula`` / ``calistir`` her kipte deny ve kilitli; politika yalnız daraltır;
  (b) öneri, ağ ve uzun iş kararları;
  (c) kip tanımları: araç kümesi P22d'ninki, hat kiplerinin öneki ajanınkiyle bayt bayt aynı (KL-0 / KL-1
      değişmedi), keşif öneki + blok dilime sığar, plan kipinde önek yok;
  (d) katman 2: durağan "süreç başlatma yok" sınaması (oturum, kip, terminal, defter, olay, özet modülleri);
  (e) katman 3: yerel sunucunun ikilisi hedef olamaz (``check_server_binary``; ``build_llama_command``).

Model yok. Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_oturum.json``.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from karadul.lm import BUDGET_PREFIX_TOKENS
from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import context as C
from karadul.lm import modes as M
from karadul.lm import tools as T
from tests.test_lm_tools import default_ws

KOK = Path(__file__).resolve().parents[1]
LM = KOK / "karadul" / "lm"

# --------------------------------------------------------------------------------------------
# (a) izin tablosu


TASARIM_TABLOSU = {   # tasarım §3.9 (ağ: keşifte karar 8 (a))
    "oku": ("allow", "allow", "allow", "allow"),
    "oner": ("deny", "allow", "allow", "deny"),
    "uygula": ("deny", "deny", "deny", "deny"),
    "ag": ("deny", "ask", "ask", "ask"),
    "calistir": ("deny", "deny", "deny", "deny"),
    "uzun_is": ("ask", "ask", "ask", "ask"),
}


def test_izin_tablosu_tasarimla_ayni():
    assert M.SESSION_MODES == ("kesif", "acikla", "adlandir", "plan")
    assert M.DEFAULT_MODE == "kesif"
    assert M.ACTIONS == tuple(TASARIM_TABLOSU)
    p = M.PermissionPolicy()
    for eylem, satir in TASARIM_TABLOSU.items():
        assert tuple(p.decide(eylem, k) for k in M.SESSION_MODES) == satir, eylem
    with pytest.raises(ValueError):
        p.decide("sil", "kesif")
    with pytest.raises(ValueError):
        p.decide("oku", "kabuk")


def test_politika_yalniz_daraltir_kilitli_satirlar_acilmaz():
    # daraltma: allow → deny, allow → ask, ask → deny
    p = M.PermissionPolicy({("oner", "adlandir"): "deny", ("oku", "plan"): "ask", ("uzun_is", "kesif"): "deny"})
    assert (p.decide("oner", "adlandir"), p.decide("oku", "plan"), p.decide("uzun_is", "kesif")) == (
        "deny", "ask", "deny")
    assert M.PermissionPolicy().decide("oner", "adlandir") == "allow"    # tablo kopyalanır, değişmez
    # gevşetme yok
    for hucre, deger in ((("oner", "kesif"), "allow"), (("uzun_is", "acikla"), "allow"), (("ag", "acikla"), "allow")):
        with pytest.raises(ValueError, match="daraltır"):
            M.PermissionPolicy({hucre: deger})
    # kilitli: uygula / çalıştır her kipte, ağ keşifte; aynı değeri yazmak serbest
    for k in M.SESSION_MODES:
        for eylem in ("uygula", "calistir"):
            with pytest.raises(ValueError, match="kilitli"):
                M.PermissionPolicy({(eylem, k): "allow"})
            with pytest.raises(ValueError, match="kilitli"):
                M.PermissionPolicy({(eylem, k): "ask"})
            assert M.PermissionPolicy({(eylem, k): "deny"}).decide(eylem, k) == "deny"
    with pytest.raises(ValueError, match="kilitli"):
        M.PermissionPolicy({("ag", "kesif"): "ask"})
    for bozuk in ({("oku",): "deny"}, {("sil", "kesif"): "deny"}, {("oku", "kesif"): "belki"}):
        with pytest.raises(ValueError):
            M.PermissionPolicy(bozuk)
    for esik in (0, -1, True, "600"):
        with pytest.raises(ValueError):
            M.PermissionPolicy(long_job_sec=esik)


# --------------------------------------------------------------------------------------------
# (b) öneri, ağ, uzun iş


def test_oneri_ag_uzun_is_kararlari():
    p = M.PermissionPolicy()
    assert [k for k in M.SESSION_MODES if p.may_propose(k, "ad")] == ["adlandir"]
    assert [k for k in M.SESSION_MODES if p.may_propose(k, "yorum")] == ["acikla"]
    assert not p.may_propose("adlandir", "not")
    assert not M.PermissionPolicy({("oner", "adlandir"): "ask"}).may_propose("adlandir", "ad")
    # ağ: keşifte hiçbir koşulda; öbürlerinde yalnız ayar (katı bool) VE onay
    assert not p.network_allowed("kesif", enabled=True, consent=True)
    assert p.network_allowed("acikla", enabled=True, consent=True)
    for en, on in ((True, False), (False, True), (1, True), (True, 1), ("true", True)):
        assert not p.network_allowed("acikla", enabled=en, consent=on), (en, on)
    assert not M.PermissionPolicy({("ag", "adlandir"): "deny"}).network_allowed("adlandir", enabled=True, consent=True)
    # uzun iş: süre bilinmiyorsa onay; eşik dahil onay; altında izin
    assert M.LONG_JOB_THRESHOLD_SEC == 600.0
    assert p.long_job("acikla", None) == "onay"
    assert p.long_job("acikla", 600.0) == "onay"
    assert p.long_job("acikla", 599.9) == "izin"
    assert M.PermissionPolicy(long_job_sec=60).long_job("acikla", 61) == "onay"
    assert M.PermissionPolicy({("uzun_is", "plan"): "deny"}).long_job("plan", 1.0) == "ret"
    # izin satırı tablodan
    assert p.line("kesif") == "kip: keşif (salt okur · uygula yok · çalıştır yok · ağ kapalı)"
    assert p.line("adlandir").startswith("kip: adlandır (öneri: ad ·")
    assert "model çağrılmaz" in p.line("plan")
    assert M.PermissionPolicy({("oner", "acikla"): "deny"}).line("acikla").startswith("kip: açıkla (salt okur")


# --------------------------------------------------------------------------------------------
# (c) kip tanımları ve önek bütçesi


def test_kip_tanimlari_arac_kumesi_ve_onekler(tmp_path):
    for k in M.SESSION_MODES:
        assert M.mode_spec(k).tools == T.MODE_TOOLSETS[k]
    with pytest.raises(ValueError):
        M.mode_spec("kabuk")
    # hat kipleri: blok boş, önek ajanın öneki (KL-0 / KL-1 bayt bayt aynı)
    ajan = G.Agent(B.FakeBackend([]), T.Workspace(default_ws(tmp_path / "ws")))
    assert M.mode_spec("adlandir").block == M.mode_spec("acikla").block == ""
    assert M.mode_prefix("adlandir") == ajan.prefix("K0") == C.fixed_prefix(
        "K0", T.default_registry().definition_lines())
    assert M.mode_prefix("acikla") == ajan.prefix("K0", C.PROMPT_VERSION_KL1)
    # keşif: K2 öneki keşif araçlarıyla + blok (sona eklenir)
    kesif = M.mode_prefix("kesif")
    assert kesif == C.fixed_prefix("K2", T.registry_for_mode("kesif").definition_lines()) + M.EXPLORE_BLOCK
    assert f"at most {M.EXPLORE_ANSWER_MAX_CHARS} characters" in kesif and M.EXPLORE_ANSWER_MAX_CHARS == 480
    assert "You cannot file proposals" in kesif
    assert M.mode_prefix("plan") is None
    # her kipin öneki K2 önek dilimine sığar (ajanın kestirimiyle)
    tablo = {r["kip"]: r for r in M.prefix_table()}
    for k in ("kesif", "acikla", "adlandir"):
        assert tablo[k]["kestirim"] == C.estimate_text_tokens(M.mode_prefix(k))
        assert tablo[k]["kestirim"] <= BUDGET_PREFIX_TOKENS and tablo[k]["sigar"] is True, tablo[k]
    assert tablo["plan"]["kestirim"] is None and tablo["plan"]["sigar"] is None
    # keşif bloğu olmadan önek P22d'nin ölçtüğü 2 027 jeton; blok payı küçük kalmalı
    assert C.estimate_text_tokens(kesif) - C.estimate_text_tokens(kesif[:-len(M.EXPLORE_BLOCK)]) < 120


# --------------------------------------------------------------------------------------------
# (d) katman 2: durağan "süreç başlatma yok" sınaması

TARANAN = ("session.py", "modes.py", "repl.py", "notebook.py", "__main__.py", "events.py", "summaries.py",
           "order.py")
SUREC_YASAK_MODUL = ("subprocess", "pty", "multiprocessing", "ctypes", "socket", "concurrent.futures.process",
               "karadul.frida", "karadul.core.safe_subprocess", "karadul.core.subprocess_runner", "karadul.ghidra",
               "shutil")
SUREC_YASAK_OS = {"system", "popen", "fork", "forkpty", "execv", "execve", "execl", "execle", "execlp", "execlpe", "execvp",
            "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
            "posix_spawn", "posix_spawnp", "startfile", "kill", "killpg", "remove", "unlink", "rmdir",
            "removedirs", "rename", "replace"}
SUREC_YASAK_YERLESIK = {"exec", "eval", "compile", "__import__"}


def surec_ihlalleri(yol: Path) -> list[str]:
    """Dosyadaki süreç başlatma / silme yolları: yasak modül içe aktarımı, ``os`` üzerinden yasak çağrı
    (``os.system`` ya da ``from os import system``), ``shell=True``, ``exec`` / ``eval`` / ``__import__``."""
    out: list[str] = []
    for d in ast.walk(ast.parse(yol.read_text(encoding="utf-8"))):
        if isinstance(d, ast.Import):
            out += [f"import {a.name}" for a in d.names
                    if any(a.name == m or a.name.startswith(m + ".") for m in SUREC_YASAK_MODUL)]
        elif isinstance(d, ast.ImportFrom) and d.module and not d.level:
            if any(d.module == m or d.module.startswith(m + ".") for m in SUREC_YASAK_MODUL):
                out.append(f"from {d.module}")
            if d.module == "os" and {a.name for a in d.names} & SUREC_YASAK_OS:
                out.append("from os import …")
            if d.module == "karadul" and {a.name for a in d.names} & {"frida", "ghidra"}:
                out.append("from karadul import frida/ghidra")
        elif isinstance(d, ast.Attribute) and isinstance(d.value, ast.Name) and d.value.id == "os" \
                and d.attr in SUREC_YASAK_OS:
            out.append(f"os.{d.attr}:{d.lineno}")
        elif isinstance(d, ast.Call):
            if isinstance(d.func, ast.Name) and d.func.id in SUREC_YASAK_YERLESIK:
                out.append(f"{d.func.id}():{d.lineno}")
            for kw in d.keywords:
                if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    out.append(f"shell=:{d.lineno}")
    return out


def test_durağan_surec_baslatma_yok():
    var = [n for n in TARANAN if (LM / n).is_file()]
    assert {"modes.py", "events.py", "summaries.py", "order.py"} <= set(var)
    for n in var:
        assert surec_ihlalleri(LM / n) == [], n


def test_durağan_tarayici_ihlali_yakalar(tmp_path):
    ornek = tmp_path / "kotu.py"
    ornek.write_text("import subprocess\nimport os\nfrom os import system\nfrom karadul import frida\n"
                     "import karadul.ghidra.x\nos.execv('a', [])\nos.posix_spawn('a', [], {})\n"
                     "f(shell=True)\neval('1')\nos.unlink('x')\nimport pty\n", encoding="utf-8")
    bul = surec_ihlalleri(ornek)
    for beklenen in ("import subprocess", "from os import …", "from karadul import frida/ghidra",
                     "import karadul.ghidra.x", "os.execv:6", "os.posix_spawn:7", "shell=:8", "eval():9",
                     "os.unlink:10", "import pty"):
        assert beklenen in bul, (beklenen, bul)
    temiz = tmp_path / "temiz.py"
    temiz.write_text("import os\nos.open('x', os.O_RDONLY)\nf(shell=False)\n", encoding="utf-8")
    assert surec_ihlalleri(temiz) == []


# --------------------------------------------------------------------------------------------
# (e) katman 3: yerel sunucunun ikilisi hedef olamaz


def _calistirilabilir(yol: Path, icerik: bytes) -> Path:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_bytes(icerik)
    os.chmod(yol, 0o755)
    return yol


def test_sunucu_ikilisi_hedef_olamaz(tmp_path):
    import hashlib
    ws = default_ws(tmp_path / "ws")
    hedef_icerik = b"\x7fELF hedef ikili"
    hedef_sha = hashlib.sha256(hedef_icerik).hexdigest()
    _calistirilabilir(ws / "raw" / "hedef", hedef_icerik)
    iyi = _calistirilabilir(tmp_path / "bin" / "llama-server", b"#!/bin/sh\n")
    assert M.check_server_binary(iyi, ws, hedef_sha) == iyi.resolve()
    cmd = B.build_llama_command(M.check_server_binary(iyi, ws, hedef_sha), Path("/m.gguf"), 8080)
    assert cmd[0] == str(iyi.resolve()) and "--model" in cmd and str(ws) not in " ".join(cmd)
    # adı yanlış
    with pytest.raises(M.ServerBinaryRefused, match="adı"):
        M.check_server_binary(_calistirilabilir(tmp_path / "bin" / "sunucu", b"#!/bin/sh\n"), ws, hedef_sha)
    # çalışma alanının içinde (adı doğru olsa da)
    with pytest.raises(M.ServerBinaryRefused, match="içinde"):
        M.check_server_binary(_calistirilabilir(ws / "raw" / "llama-server", b"#!/bin/sh\nx\n"), ws, hedef_sha)
    # hedefin kopyası başka bir yerde, adı llama-server
    with pytest.raises(M.ServerBinaryRefused, match="aynı"):
        M.check_server_binary(_calistirilabilir(tmp_path / "kopya" / "llama-server", hedef_icerik), ws, hedef_sha)
    # adı llama-server olan sembolik bağ hedefi gösteriyor
    bag = tmp_path / "bag" / "llama-server"
    bag.parent.mkdir()
    bag.symlink_to(ws / "raw" / "hedef")
    with pytest.raises(M.ServerBinaryRefused):
        M.check_server_binary(bag, ws, hedef_sha)
    # yok / çalıştırılamaz
    with pytest.raises(M.ServerBinaryRefused, match="bulunamadı"):
        M.check_server_binary(tmp_path / "yok" / "llama-server", ws, hedef_sha)
    kapali = tmp_path / "kapali" / "llama-server"
    kapali.parent.mkdir()
    kapali.write_bytes(b"x")
    os.chmod(kapali, 0o644)
    with pytest.raises(M.ServerBinaryRefused, match="çalıştırılabilir"):
        M.check_server_binary(kapali, ws, hedef_sha)
    # hedef özeti bilinmiyorsa yalnız ad ve yer denetlenir
    assert M.check_server_binary(iyi, ws, None) == iyi.resolve()


# --------------------------------------------------------------------------------------------
# (f) süreç düzeyinde: bütün bir oturum akışında hiç süreç başlatılmaz, çalışma alanı değişmez


def test_oturum_akisi_surec_baslatmaz_calisma_alanini_degistirmez(tmp_path, monkeypatch):
    import subprocess

    from karadul.lm import session as S
    from tests.test_lm_summaries import R, X, ZINCIR_METIN, OzetArka, zincir_ws
    cagrilar: list[str] = []

    def kaydet(ad):
        def f(*a, **k):
            cagrilar.append(ad)
            raise OSError(f"{ad} bu sınamada yasak")
        return f
    for ad in ("Popen", "run", "call", "check_output"):
        monkeypatch.setattr(subprocess, ad, kaydet(f"subprocess.{ad}"))
    for ad in ("system", "posix_spawn", "posix_spawnp", "fork", "execv", "execve", "spawnv", "popen", "kill"):
        if hasattr(os, ad):
            monkeypatch.setattr(os, ad, kaydet(f"os.{ad}"))
    kok = zincir_ws(tmp_path / "ws").root
    once = {p: p.read_bytes() for p in kok.rglob("*") if p.is_file()}
    s = S.open_session(kok, backend=OzetArka(dict(ZINCIR_METIN)), binary_sha256="ab" * 32,
                       store_root=tmp_path / "depo", mode="acikla")
    try:
        for satir in ("/yardim", f"/acikla FUN_{X} 0", f"/acikla FUN_{R}", "/onayla", f"/not FUN_{X} not",
                      "/oneriler", "/ac r1", "/kip plan", "/plan dizgi dizgisi", "/onayla", "/durdur",
                      "karadullm; sh", "/kip adlandir", f"/ad FUN_{X}"):
            s.submit(satir)
            assert s.wait_idle(20.0)
    finally:
        s.close()
    assert cagrilar == []
    assert {p: p.read_bytes() for p in kok.rglob("*") if p.is_file()} == once
    # oturum yalnız ~/.karadul/lm/<sha>/ karşılığına yazdı
    yazilan = sorted(str(p.relative_to(tmp_path / "depo")).split("/")[1] for p in (tmp_path / "depo").rglob("*")
                     if p.is_file())
    assert set(yazilan) <= {"defter.jsonl", "ozet.jsonl", "sonuclar"}
