"""``tabaka_indir.py`` birim sınaması (P-Ö7: kilitli ad süzgeci, sha256 doğrulaması, sürüm sırası, güvenli açma).

Ağ kullanılmaz. Koşum (depo kökünden):
  PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider scripts/arge/olcu/test_tabaka_indir.py -q
Mutant sınaması: ``TABAKA_INDIR_YOLU`` ortam değişkeni sınanacak modül dosyasını değiştirir (mutant kopya
gerçek dosyaya dokunmadan sınanır). Mutant: ``kilit_suzgeci`` boş liste döner → süzgeç sınamaları KIRMIZI.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import lzma
import os
import sys
import tarfile
from pathlib import Path

import pytest

_YOL = Path(os.environ.get("TABAKA_INDIR_YOLU", Path(__file__).with_name("tabaka_indir.py")))
_spec = importlib.util.spec_from_file_location("tabaka_indir_sinanan", _YOL)
ti = importlib.util.module_from_spec(_spec)
sys.modules["tabaka_indir_sinanan"] = ti
_spec.loader.exec_module(ti)

GERCEK_TABAKA_INDIR = Path(__file__).with_name("tabaka_indir.py")

SENTETIK_KILIT = """# Sentetik kilit
| # | Program (ölçülecek ikili) | Alan | Homebrew | Debian 13 arm64 | Not |
|---|---|---|---|---|---|
| 1 | alfa (`alfa`) | kabuk | `alfa-shell` 1.0 | alfa-bin 1.0-1 | |
| 2 | Beta (`beta`; Debian `beta-tools`) | ağ | `beta` 2.0 | beta-tools 1:2.0-3 | |

**Kurada dışarıda kalanlar** (yedek sırası):
- küçük: `gama`, `delta`

| Program | Neden ayrı |
|---|---|
| epsilon | gnulib |

- **orta:** korumalı: zeta, eta. Sonrası: teta, iota.

**Stres yedek sırası:** kappa, lambda-x, mu.
"""


def test_sentetik_kilit_adlari():
    adlar = ti.kilitli_adlar_metinden(SENTETIK_KILIT)
    beklenen = {"alfa", "alfa-shell", "alfa-bin", "beta", "beta-tools", "gama", "delta", "epsilon",
                "zeta", "eta", "teta", "iota", "kappa", "lambda-x", "mu"}
    assert beklenen <= adlar


def test_suzgec_kesisimi_bulur():
    adlar = ti.kilitli_adlar_metinden(SENTETIK_KILIT)
    assert ti.kilit_suzgeci(["tmux", "Beta-Tools", "zeta", "temiz"], adlar) == ["Beta-Tools", "zeta"]
    assert ti.kilit_suzgeci(["tmux", "temiz"], adlar) == []


def test_gercek_kilit_belgeleri_bilinen_adlari_yakalar():
    """Kilit belgelerinin her bölümünden bir ad: test seti ana / yedek / stres, doğrulama seti ana /
    korumalı yedek / stres / stres yedeği, Debian paket adı."""
    adlar = ti.kilitli_adlar()
    ornek = ["unzip", "ag", "lynx", "wget", "lua", "liblua5.4-0", "openssh-client", "mosquitto", "zmap",
             "tin", "php", "datamash", "findutils", "nagios4-core", "gnome-builder"]
    assert ti.kilit_suzgeci(ornek, adlar) == sorted(ornek)


def test_gelistirme_paketleri_kilitli_degil():
    adlar = ti.kilitli_adlar()
    assert ti.kilit_suzgeci(list(ti.GELISTIRME_PAKETLERI), adlar) == []


def test_yakinlik_bilgisi():
    assert ti.kilit_yakinligi(["lua-socket", "tmux"], {"lua"}) == [("lua-socket", "lua")]


def test_sha256_dogrulama(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"karadul")
    h = hashlib.sha256(b"karadul").hexdigest()
    assert ti.sha256_dogrula(f, h, 7)["ok"]
    assert ti.sha256_dogrula(f, h.upper())["ok"]
    assert not ti.sha256_dogrula(f, h, 8)["ok"]
    assert not ti.sha256_dogrula(f, "0" * 64)["ok"]


def test_izinli_onekler():
    assert ti.izinli_mi("https://deb.debian.org/debian/pool/main/t/tmux/x.deb")
    assert ti.izinli_mi("http://ddebs.ubuntu.com/pool/main/c/x.ddeb")
    assert not ti.izinli_mi("https://deb.debian.org.example.com/debian/x.deb")
    assert not ti.izinli_mi("http://deb.debian.org/debian/x.deb")
    assert not ti.izinli_mi("https://example.com/x.deb")
    assert not ti.indir("https://example.com/x.deb", Path("/nonexistent/x"))["ok"]


@pytest.mark.parametrize("a,b,isaret", [
    ("1.0~rc1", "1.0", -1), ("1:1.0", "2.0", 1), ("3.5.7-1~deb13u2", "3.5.7-1~deb13u3", -1),
    ("3.5.7-1~deb13u3", "3.5.7-1", -1), ("5.2.37-2+b10", "5.2.37-2+b9", 1), ("1.0-1", "1.0-1", 0),
    ("9.4-3ubuntu6", "9.4-3ubuntu6.1", -1), ("2.2.1-1", "2.1.0-1", 1), ("1.0a", "1.0", 1),
])
def test_surum_sirasi(a, b, isaret):
    c = ti.surum_karsilastir(a, b)
    assert (c > 0) - (c < 0) == isaret


def test_kaynak_surumu():
    assert ti.kaynak_surumu({"Version": "5.2.37-2+b10", "Source": "bash (5.2.37-2)"}) == "5.2.37-2"
    assert ti.kaynak_surumu({"Version": "3.5a-3", "Source": "tmux"}) == "3.5a-3"
    assert ti.kaynak_surumu({"Version": "1.0-1"}) == "1.0-1"


def test_cift_sec_en_yuksek_esli_surum():
    ikili = [{"Package": "p", "Version": v, "Architecture": "amd64", "Filename": f"p_{v}.deb"}
             for v in ("1.0-1", "1.0-2", "1.0-3")]
    hata = [{"Package": "p-dbgsym", "Version": v, "Architecture": "amd64"} for v in ("1.0-1", "1.0-2")]
    c = ti.cift_sec(ikili, hata, "p", "p-dbgsym", "amd64")
    assert c["durum"] == "bulundu" and c["ikili"]["Version"] == "1.0-2"
    c = ti.cift_sec(ikili, hata, "p", "p-dbgsym", "amd64", kaynak_surum="1.0-1")
    assert c["ikili"]["Version"] == "1.0-1"
    assert ti.cift_sec(ikili, hata, "p", "p-dbgsym", "arm64")["durum"] == "eslesmedi"


def test_release_ve_imzali_govde():
    metin = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSuite: x\nSHA256:\n"
             " " + "a" * 64 + "  123 main/binary-arm64/Packages.xz\n"
             "-----BEGIN PGP SIGNATURE-----\nxx\n-----END PGP SIGNATURE-----\n")
    g = ti.imzali_govde(metin)
    assert g.startswith("Suite: x")
    assert ti.release_sha256(g) == {"main/binary-arm64/Packages.xz": (123, "a" * 64)}


def _deb(tmp: Path, uyeler: dict[str, bytes]) -> Path:
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as tf:
        for ad, veri in uyeler.items():
            bi = tarfile.TarInfo(ad)
            bi.size = len(veri)
            tf.addfile(bi, io.BytesIO(veri))
    data = lzma.compress(tbuf.getvalue())
    parcalar = [("debian-binary", b"2.0\n"), ("data.tar.xz", data)]
    out = b"!<arch>\n"
    for ad, veri in parcalar:
        bas = f"{ad + '/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(veri):<10}`\n".encode()
        out += bas + veri + (b"\n" if len(veri) % 2 else b"")
    yol = tmp / "p.deb"
    yol.write_bytes(out)
    return yol


def test_deb_ac_normal_ve_kacis(tmp_path):
    deb = _deb(tmp_path, {"./usr/bin/p": b"\x7fELFxx"})
    r = ti.deb_ac(deb, tmp_path / "x_p")
    assert (tmp_path / "x_p" / "usr" / "bin" / "p").read_bytes() == b"\x7fELFxx" and not r["atlandi"]
    assert ti.deb_ac(deb, tmp_path / "x_p")["atlandi"]          # dolu dizine yeniden açılmaz
    kotu = _deb(tmp_path, {"../kacis": b"x"})
    with pytest.raises(RuntimeError):
        ti.deb_ac(kotu, tmp_path / "x_kotu")
    assert not (tmp_path / "kacis").exists()


def test_mutant_suzgec_kirmizi(tmp_path):
    """P-Ö7 mutant (1 / 1): ``kilit_suzgeci`` boş liste döndürürse yukarıdaki süzgeç sınamaları kırmızı olmalı.

    Mutant, gerçek dosyanın geçici bir kopyasında üretilir; bu sınama yalnız gerçek modül sınanırken koşar.
    """
    if os.environ.get("TABAKA_INDIR_YOLU"):
        pytest.skip("mutant koşusunun içinde")
    import subprocess
    kaynak = GERCEK_TABAKA_INDIR.read_text(encoding="utf-8")
    bul = '    return sorted({a for a in adaylar if a.lower() in k})\n'
    assert kaynak.count(bul) == 1
    mutant = tmp_path / "tabaka_indir_mutant.py"
    mutant.write_text(kaynak.replace(bul, "    return []\n"), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", str(Path(__file__)),
                        "-k", "suzgec_kesisimi or bilinen_adlari"],
                       capture_output=True, text=True, cwd=str(GERCEK_TABAKA_INDIR.parents[3]),
                       env={**os.environ, "TABAKA_INDIR_YOLU": str(mutant), "PYTHONDONTWRITEBYTECODE": "1"})
    assert r.returncode != 0, r.stdout[-500:]
    assert "2 failed" in r.stdout, r.stdout[-500:]
