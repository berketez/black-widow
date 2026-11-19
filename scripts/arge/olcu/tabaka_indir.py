#!/usr/bin/env python3
"""ÖLÇÜ hattı P-Ö7 adım 1–3: tabaka A / B paketlerini resmî dizinlerden oku, süz, indir, doğrula.

Yalnız ``IZINLI_ONEKLER``'deki resmî arşivler kullanılır. İndirilen hiçbir dosya çalıştırılmaz:
``.deb`` / ``.ddeb`` yalnız açılır (``ar`` + ``tar``, Python içinde), her biri ayrı ve yeni boş
bir dizine. Açılan dosyaları okuyan bu betik ``python -I`` ile ve indirme dizininin dışından (depo
kökünden) koşulur. İstekler ``/usr/bin/curl`` ile atılır; User-Agent curl'ün öntanımlısıdır.

Doğrulama zinciri (her dizin için):
  1. ``InRelease`` indirilir; imzası ``gpgv`` ile dağıtımın kendi anahtar halkası paketine karşı
     doğrulanır (anahtar halkası paketi HTTPS ile aynı arşivden alınır, sha256'sı dizinle eşleşir).
     ddebs.ubuntu.com yalnız HTTP sunduğu için bu adım orada bütünlüğün tek dayanağıdır.
  2. ``Packages.xz``'in sha256'sı imzalı ``InRelease`` içeriğiyle karşılaştırılır.
  3. Her paket dosyasının sha256'sı ve boyutu ``Packages`` kaydıyla karşılaştırılır.
  4. İkili paketteki her ELF'in GNU BuildID'si hata ayıklama paketindeki
     ``usr/lib/debug/.build-id/xx/yyyy.debug`` dosyasının BuildID'siyle karşılaştırılır; eşleşen
     çiftlerde ``scripts/measurement/function_f1.py`` ``extract_gt`` koşulur (BuildID eşitliği ve
     soyulmuşluk denetimi onun içinde). Çıktıya yalnız sayılar yazılır, sembol adı yazılmaz.

Tabaka tanımı: ``docs/arge/2026-11-19_mythos/olcu/PLAN.md`` P-Ö7 ve §4. Sürüm kuralı: tabaka A'da
kaynak sürümü geliştirme setindeki arm64 sürümüyle aynı olmalı (künye:
``~/karadul_olcum/downloads/debian13/manifest.json``); dizinde yoksa snapshot.debian.org; orada da
yoksa paket tabakadan çıkar ve yazılır. Tabaka B'de dağıtımın hata ayıklama paketi bulunan en yüksek
sürümü alınır.

Kullanım (depo kökünden):
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py dizin \\
      --indir-kok ~/karadul_olcum/downloads/n2_tabaka --json ~/karadul_olcum/downloads/n2_tabaka/secim.json
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py indir \\
      --secim ~/karadul_olcum/downloads/n2_tabaka/secim.json --veri-kok ~/karadul_olcum/n2_tabaka \\
      --json ~/karadul_olcum/n2_tabaka/tabaka_veri.json
  PYTHONDONTWRITEBYTECODE=1 python -I scripts/arge/olcu/tabaka_indir.py rapor --veri ~/karadul_olcum/n2_tabaka/tabaka_veri.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import lzma
import os
import re
import string
import subprocess
import sys
import tarfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

REPO = Path(__file__).resolve().parents[3]
OLCUM = REPO / "scripts" / "measurement"
KILIT_BELGELERI = (REPO / "docs" / "arge" / "test_seti_kilidi.md",
                   REPO / "docs" / "arge" / "dogrulama_seti_kilidi.md")
GELISTIRME_KUNYESI = Path.home() / "karadul_olcum" / "downloads" / "debian13" / "manifest.json"
SEMA_SECIM = "karadul-tabaka-secim/1"
SEMA_VERI = "karadul-tabaka-veri/1"
CURL = "/usr/bin/curl"
GPGV = "/opt/homebrew/bin/gpgv"
TOPLAM_SINIR = 2 * 1024 ** 3        # A-4: toplam indirme 2 GiB'ı aşarsa dur
DENEME = 4                          # ağ hatasında deneme sayısı

# Resmî arşivler (A-4 ve paket brifi). Başka önek reddedilir; yönlendirme sonrası adres de denetlenir.
IZINLI_ONEKLER = (
    "https://deb.debian.org/debian/",
    "https://deb.debian.org/debian-debug/",
    "https://deb.debian.org/debian-security/",
    "https://deb.debian.org/debian-security-debug/",
    "https://snapshot.debian.org/",
    "https://ports.ubuntu.com/ubuntu-ports/",
    "http://ddebs.ubuntu.com/",      # HTTPS isteği 301 ile HTTP'ye dönüyor (2026-11-19); bütünlük gpgv ile
)

ARSIV_DEBIAN = IZINLI_ONEKLER[0]
ARSIV_DEBIAN_HATA = IZINLI_ONEKLER[1]
ARSIV_DEBIAN_GUVENLIK = IZINLI_ONEKLER[2]
ARSIV_DEBIAN_GUVENLIK_HATA = IZINLI_ONEKLER[3]
ARSIV_SNAPSHOT = IZINLI_ONEKLER[4]
ARSIV_UBUNTU_PORTS = IZINLI_ONEKLER[5]
ARSIV_UBUNTU_DDEBS = IZINLI_ONEKLER[6]

# Geliştirme setinin 8 paketi (BEKLENEN_ELF ile aynı birimler; ks1_olc.py).
GELISTIRME_PAKETLERI = ("tmux", "htop", "zstd", "sqlite3", "openssl", "redis-tools", "coreutils", "tree")


@dataclass(frozen=True)
class Dizin:
    """Tek bir ``Packages`` dizini."""
    etiket: str      # yerel alt dizin adı (ör. ``trixie-security_main``)
    taban: str       # arşiv kökü
    suite: str
    bilesen: str
    mimari: str
    tur: str         # "ikili" ya da "hata"


def _debian(kod: str, mimari: str) -> tuple[Dizin, ...]:
    return (
        Dizin(f"{kod}_main", ARSIV_DEBIAN, kod, "main", mimari, "ikili"),
        Dizin(f"{kod}-updates_main", ARSIV_DEBIAN, f"{kod}-updates", "main", mimari, "ikili"),
        Dizin(f"{kod}-security_main", ARSIV_DEBIAN_GUVENLIK, f"{kod}-security", "main", mimari, "ikili"),
        Dizin(f"{kod}-debug_main", ARSIV_DEBIAN_HATA, f"{kod}-debug", "main", mimari, "hata"),
        Dizin(f"{kod}-proposed-updates-debug_main", ARSIV_DEBIAN_HATA, f"{kod}-proposed-updates-debug", "main",
              mimari, "hata"),
        Dizin(f"{kod}-security-debug_main", ARSIV_DEBIAN_GUVENLIK_HATA, f"{kod}-security-debug", "main", mimari,
              "hata"),
    )


def _ubuntu(kod: str, mimari: str) -> tuple[Dizin, ...]:
    out = []
    for bil in ("main", "universe"):
        for s in (kod, f"{kod}-updates", f"{kod}-security"):
            out.append(Dizin(f"{s}_{bil}", ARSIV_UBUNTU_PORTS, s, bil, mimari, "ikili"))
        for s in (kod, f"{kod}-updates"):     # ddebs'te -security yok (404, 2026-11-19)
            out.append(Dizin(f"ddebs_{s}_{bil}", ARSIV_UBUNTU_DDEBS, s, bil, mimari, "hata"))
    return tuple(out)


DAGITIMLAR: dict[str, dict[str, Any]] = {
    "debian13_amd64": {"dizinler": _debian("trixie", "amd64"), "aile": "debian"},
    "debian13_arm64": {"dizinler": _debian("trixie", "arm64"), "aile": "debian"},
    "debian12_arm64": {"dizinler": _debian("bookworm", "arm64"), "aile": "debian"},
    "ubuntu2404_arm64": {"dizinler": _ubuntu("noble", "arm64"), "aile": "ubuntu"},
}
# Anahtar halkası paketleri: (paket, dizin etiketi) — aynı arşivden HTTPS ile, dizindeki sha256'yla.
ANAHTAR_PAKETLERI = {
    "debian": (("debian-archive-keyring", None),),
    "ubuntu": (("ubuntu-keyring", None), ("ubuntu-dbgsym-keyring", None)),
}

# Tabaka tanımı (PLAN P-Ö7 / §4): tabaka → [(dağıtım, alt etiket)]
TABAKALAR = {
    "a": (("debian13_amd64", "debian13_amd64"),),
    "b": (("debian12_arm64", "debian12_arm64"), ("ubuntu2404_arm64", "ubuntu2404_arm64")),
}


# ---------------------------------------------------------------------------
# Genel yardımcılar
# ---------------------------------------------------------------------------

def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def sha1_dosya(yol: Path) -> str:
    h = hashlib.sha1()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def izinli_mi(url: str) -> bool:
    return any(url.startswith(o) for o in IZINLI_ONEKLER)


def sha256_dogrula(yol: Path, beklenen_sha256: str, beklenen_boyut: Optional[int] = None) -> dict[str, Any]:
    """Dosyanın sha256'sı (ve verildiyse boyutu) beklenenle aynı mı."""
    gercek = sha256_dosya(yol)
    boyut = yol.stat().st_size
    ok = gercek == beklenen_sha256.lower() and (beklenen_boyut is None or boyut == int(beklenen_boyut))
    return {"ok": ok, "sha256": gercek, "boyut": boyut, "beklenen_sha256": beklenen_sha256.lower(),
            "beklenen_boyut": beklenen_boyut}


def indir(url: str, hedef: Path, *, beklenen_sha256: Optional[str] = None,
          beklenen_boyut: Optional[int] = None, deneme: int = DENEME) -> dict[str, Any]:
    """``url``'yi ``hedef``'e indir. Varsa ve sha256 tutuyorsa yeniden indirmez.

    Hata durumunda istisna atmaz; ``{"ok": False, "hata": ...}`` döner. Yalnız izinli önekler.
    """
    if not izinli_mi(url):
        return {"ok": False, "url": url, "hata": "izinsiz kaynak"}
    hedef.parent.mkdir(parents=True, exist_ok=True)
    if hedef.exists() and beklenen_sha256:
        d = sha256_dogrula(hedef, beklenen_sha256, beklenen_boyut)
        if d["ok"]:
            return {"ok": True, "url": url, "durum": "vardı", **d}
    gecici = hedef.with_name(hedef.name + ".part")
    son_hata = ""
    for i in range(deneme):
        r = subprocess.run([CURL, "-sS", "-f", "-L", "--max-redirs", "3", "--max-time", "1800",
                            "--connect-timeout", "30", "-o", str(gecici), "-w", "%{url_effective}", url],
                           capture_output=True, text=True)
        if r.returncode == 0:
            son_url = r.stdout.strip()
            if not izinli_mi(son_url):
                return {"ok": False, "url": url, "hata": f"yönlendirme izinsiz kaynağa: {son_url}"}
            os.replace(gecici, hedef)
            sonuc: dict[str, Any] = {"ok": True, "url": url, "durum": "indirildi", "deneme": i + 1}
            if beklenen_sha256:
                d = sha256_dogrula(hedef, beklenen_sha256, beklenen_boyut)
                sonuc.update(d)
                if not d["ok"]:
                    son_hata = "sha256/boyut eşleşmedi"
                    sonuc["ok"] = False
                    sonuc["hata"] = son_hata
                    continue          # bir daha dene (üstüne yazılır)
            else:
                sonuc["sha256"] = sha256_dosya(hedef)
                sonuc["boyut"] = hedef.stat().st_size
            return sonuc
        son_hata = (r.stderr.strip() or f"curl çıkış {r.returncode}")[:300]
        time.sleep(3 * (i + 1))
    return {"ok": False, "url": url, "hata": son_hata}


def _getir_metin(url: str) -> Optional[str]:
    """Küçük JSON / metin yanıtı (snapshot API). İzinli önek şart."""
    if not izinli_mi(url):
        raise ValueError(f"izinsiz kaynak: {url}")
    for i in range(DENEME):
        r = subprocess.run([CURL, "-sS", "-f", "--max-time", "120", "--connect-timeout", "30", url],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
        if "404" in r.stderr:
            return None
        time.sleep(3 * (i + 1))
    return None


# ---------------------------------------------------------------------------
# Debian sürüm karşılaştırması (dpkg verrevcmp)
# ---------------------------------------------------------------------------

def _sira(c: str) -> int:
    if not c or c in string.digits:
        return 0
    if c in string.ascii_letters:
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        ilk_fark = 0
        while (i < len(a) and a[i] not in string.digits) or (j < len(b) and b[j] not in string.digits):
            ac = _sira(a[i] if i < len(a) else "")
            bc = _sira(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and j < len(b) and a[i] in string.digits and b[j] in string.digits:
            if not ilk_fark:
                ilk_fark = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in string.digits:
            return 1
        if j < len(b) and b[j] in string.digits:
            return -1
        if ilk_fark:
            return ilk_fark
    return 0


def _parcala(v: str) -> tuple[int, str, str]:
    epoch, _, kalan = v.partition(":") if ":" in v else ("0", "", v)
    if "-" in kalan:
        ust, _, rev = kalan.rpartition("-")
    else:
        ust, rev = kalan, ""
    return int(epoch or 0), ust, rev


def surum_karsilastir(a: str, b: str) -> int:
    """dpkg sırası: <0 a<b, 0 eşit, >0 a>b."""
    ea, ua, ra = _parcala(a)
    eb, ub, rb = _parcala(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub)
    if c:
        return c
    return _verrevcmp(ra, rb)


def epochsuz(v: str) -> str:
    return v.split(":", 1)[1] if ":" in v else v


def kaynak_surumu(kayit: dict[str, str]) -> str:
    """``Source: ad (sürüm)`` varsa o sürüm; yoksa ikili sürüm (binNMU'da Source alanı sürüm taşır)."""
    m = re.match(r"^\S+\s+\(([^)]+)\)", kayit.get("Source", ""))
    return m.group(1) if m else kayit["Version"]


def kaynak_adi(kayit: dict[str, str]) -> str:
    s = kayit.get("Source", "").split()
    return s[0] if s else kayit["Package"]


# ---------------------------------------------------------------------------
# Dizinler: InRelease, imza, Packages
# ---------------------------------------------------------------------------

def release_sha256(metin: str) -> dict[str, tuple[int, str]]:
    """Release / InRelease içeriğinin ``SHA256:`` bölümü → {yol: (boyut, sha256)}."""
    out: dict[str, tuple[int, str]] = {}
    icinde = False
    for satir in metin.splitlines():
        if not satir.startswith(" "):
            icinde = satir.strip() == "SHA256:"
            continue
        if icinde:
            p = satir.split()
            if len(p) == 3:
                out[p[2]] = (int(p[1]), p[0].lower())
    return out


def imzali_govde(inrelease: str) -> str:
    """Açık imzalı (clearsigned) metnin gövdesi (imza doğrulaması ayrı yapılır)."""
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in inrelease:
        return inrelease
    bas = inrelease.index("\n\n", inrelease.index("-----BEGIN PGP SIGNED MESSAGE-----")) + 2
    son = inrelease.index("-----BEGIN PGP SIGNATURE-----")
    govde = inrelease[bas:son]
    return "\n".join(s[2:] if s.startswith("- ") else s for s in govde.splitlines())


def packages_oku(metin: str) -> list[dict[str, str]]:
    """Packages metnini kayıtlara ayır (yalnız tek satırlık alanlar)."""
    alanlar = ("Package", "Version", "Architecture", "Source", "Filename", "Size", "SHA256", "SHA1",
               "Build-Ids", "Installed-Size")
    out: list[dict[str, str]] = []
    kayit: dict[str, str] = {}
    for satir in metin.splitlines():
        if not satir.strip():
            if "Package" in kayit:
                out.append(kayit)
            kayit = {}
            continue
        if satir[0] in " \t" or ":" not in satir:
            continue
        k, v = satir.split(":", 1)
        if k in alanlar:
            kayit[k] = v.strip()
    if "Package" in kayit:
        out.append(kayit)
    return out


def gpgv_dogrula(inrelease: Path, anahtarlar: list[Path], ev: Path) -> dict[str, Any]:
    """``gpgv`` ile açık imzalı InRelease'i doğrula. Dönen ``govde`` gpgv'nin verdiği imzalı içeriktir."""
    ev.mkdir(parents=True, exist_ok=True)
    os.chmod(ev, 0o700)
    komut = [GPGV, "--homedir", str(ev), "--status-fd", "2"]
    for a in anahtarlar:
        komut += ["--keyring", str(a)]
    komut += ["--output", "-", str(inrelease)]
    r = subprocess.run(komut, capture_output=True, env={**os.environ, "GNUPGHOME": str(ev)})
    hata_metni = r.stderr.decode("utf-8", "replace")
    durum = [s for s in hata_metni.splitlines() if s.startswith("[GNUPG:]")]
    iyi = [s for s in durum if " GOODSIG " in s]
    validsig = [s.split()[2] for s in durum if " VALIDSIG " in s]
    ok = r.returncode == 0 and bool(iyi) and bool(validsig)
    return {"ok": ok, "parmak_izi": validsig, "govde": r.stdout.decode("utf-8", "replace") if ok else "",
            "hata": "" if ok else hata_metni.strip()[-300:]}


def dizin_getir(d: Dizin, kok: Path) -> dict[str, Any]:
    """InRelease ve Packages.xz'i indir; Packages.xz'in sha256'sını InRelease ile doğrula."""
    yer = kok / d.etiket / f"binary-{d.mimari}"
    inr_url = f"{d.taban}dists/{d.suite}/InRelease"
    inr = indir(inr_url, yer / "InRelease")
    if not inr["ok"]:
        return {"dizin": asdict(d), "ok": False, "hata": f"InRelease: {inr.get('hata')}"}
    metin = (yer / "InRelease").read_text(encoding="utf-8", errors="replace")
    hashler = release_sha256(imzali_govde(metin))
    goreli = f"{d.bilesen}/binary-{d.mimari}/Packages.xz"
    if goreli not in hashler:
        return {"dizin": asdict(d), "ok": False, "hata": f"InRelease'te {goreli} yok"}
    boyut, sha = hashler[goreli]
    pk = indir(f"{d.taban}dists/{d.suite}/{goreli}", yer / "Packages.xz", beklenen_sha256=sha,
               beklenen_boyut=boyut)
    if not pk["ok"]:
        return {"dizin": asdict(d), "ok": False, "hata": f"Packages.xz: {pk.get('hata')}"}
    return {"dizin": asdict(d), "ok": True, "inrelease": str(yer / "InRelease"),
            "inrelease_sha256": sha256_dosya(yer / "InRelease"), "packages": str(yer / "Packages.xz"),
            "packages_sha256": sha, "packages_boyut": boyut}


def dizin_kayitlari(bilgi: dict[str, Any]) -> list[dict[str, str]]:
    with lzma.open(bilgi["packages"], "rt", encoding="utf-8", errors="replace") as f:
        return packages_oku(f.read())


# ---------------------------------------------------------------------------
# Kilitli ad süzgeci
# ---------------------------------------------------------------------------

_AD_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*$")
_GERI_TIRNAK_RE = re.compile(r"`([^`]+)`")
_HUCRE_PROGRAM_RE = re.compile(r"^([A-Za-z0-9][\w.+-]*)(?:\s+—\s+ek)?\s+\((.*)\)\s*$")
_HUCRE_PAKET_SURUM_RE = re.compile(r"^`?([A-Za-z0-9][A-Za-z0-9.+-]*)`?\s+(?:\d+:)?\d")
_MADDE_RE = re.compile(r"^\s*(?:-\s+)?\*{0,2}(küçük|orta|büyük|Stres yedek sırası)\*{0,2}:\*{0,2}\s*(.*)$")


def _ad_ekle(kume: set[str], aday: str) -> None:
    a = aday.strip().strip("`").strip().lower()
    if _AD_RE.match(a) and any(c in string.ascii_lowercase for c in a):   # yalın sayı / sürüm ad değil
        kume.add(a)


def kilitli_adlar_metinden(metin: str) -> set[str]:
    """Kilit belgesindeki program / paket / ikili adları (tablolar ve yedek listeleri).

    Okunan yerler: (1) ``ad (`ikili`; Debian `paket`)`` biçimli tablo hücreleri; (2) ``paket sürüm``
    biçimli hücreler (Homebrew ve Debian sütunları); (3) başlığı ``Program`` olan tabloların ilk
    sütunundaki yalın adlar; (4) ``küçük / orta / büyük / Stres yedek sırası:`` maddelerindeki
    virgüllü listeler (korumalı ve sonraki yedekler, kurada dışarıda kalanlar).
    """
    adlar: set[str] = set()
    program_tablosu = False
    for satir in metin.splitlines():
        s = satir.strip()
        if s.startswith("|"):
            hucreler = [h.strip() for h in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", h) for h in hucreler if h):
                continue
            if hucreler and hucreler[0] in ("Program", "#"):
                program_tablosu = hucreler[0] == "Program"
                continue
            for h in hucreler:
                m = _HUCRE_PROGRAM_RE.match(h)
                if m:
                    _ad_ekle(adlar, m.group(1))
                    for g in _GERI_TIRNAK_RE.findall(m.group(2)):
                        _ad_ekle(adlar, g)
                    continue
                m = _HUCRE_PAKET_SURUM_RE.match(h)
                if m:
                    _ad_ekle(adlar, m.group(1))
            if program_tablosu and hucreler and _AD_RE.match(hucreler[0].lower()):
                _ad_ekle(adlar, hucreler[0])
            continue
        program_tablosu = False
        m = _MADDE_RE.match(s)
        if m:
            govde = re.sub(r"\*\*?[^*]*?:\*\*?", " ", m.group(2))
            govde = govde.replace("korumalı:", " ").replace("Sonrası:", " ")
            for parca in re.split(r"[,.;]\s+|[,;]|\s+ve\s+", govde):
                parca = parca.strip().rstrip(".").strip()
                if not parca:
                    continue
                for g in _GERI_TIRNAK_RE.findall(parca) or [parca]:
                    _ad_ekle(adlar, g)
    return adlar


def kilitli_adlar(belgeler: Iterable[Path] = KILIT_BELGELERI) -> set[str]:
    adlar: set[str] = set()
    for b in belgeler:
        adlar |= kilitli_adlar_metinden(Path(b).read_text(encoding="utf-8"))
    return adlar


def kilit_suzgeci(adaylar: Iterable[str], kilitli: set[str]) -> list[str]:
    """Aday adlarından kilitli kümede olanlar (büyük / küçük harf duyarsız). Boşsa liste temiz."""
    k = {a.lower() for a in kilitli}
    return sorted({a for a in adaylar if a.lower() in k})


def kilit_yakinligi(adaylar: Iterable[str], kilitli: set[str]) -> list[tuple[str, str]]:
    """Bilgi için: adayın ``-`` ile ayrılmış bir parçası kilitli bir adla aynıysa (ör. ``lua-x`` ↔ ``lua``)."""
    k = {a.lower() for a in kilitli}
    out = []
    for a in adaylar:
        for p in a.lower().split("-"):
            if p in k and p != a.lower():
                out.append((a, p))
    return sorted(set(out))


# ---------------------------------------------------------------------------
# Paket seçimi
# ---------------------------------------------------------------------------

def hata_paketi_adi(paket: str, aile: str) -> str:
    return f"{paket}-dbgsym"


def cift_sec(ikili: list[dict[str, Any]], hata: list[dict[str, Any]], paket: str, dbg_adi: str,
             mimari: str, kaynak_surum: Optional[str] = None) -> dict[str, Any]:
    """En yüksek sürümlü (ikili, hata ayıklama) çifti. Kayıtlar ``_dizin`` alanını taşır.

    ``kaynak_surum`` verilirse yalnız o kaynak sürümünden derlenmiş ikililer aday olur.
    """
    adaylar = [k for k in ikili if k["Package"] == paket and k.get("Architecture") == mimari]
    if kaynak_surum is not None:
        adaylar = [k for k in adaylar if epochsuz(kaynak_surumu(k)) == epochsuz(kaynak_surum)]
    dbg = [k for k in hata if k["Package"] == dbg_adi and k.get("Architecture") == mimari]
    ciftler = []
    for k in adaylar:
        es = [h for h in dbg if h["Version"] == k["Version"]]
        if es:
            ciftler.append((k, es[0]))
    if ciftler:
        best = ciftler[0]
        for c in ciftler[1:]:
            if surum_karsilastir(c[0]["Version"], best[0]["Version"]) > 0:
                best = c
        return {"durum": "bulundu", "ikili": best[0], "hata": best[1],
                "dizin_surumleri": sorted({k["Version"] for k in adaylar}),
                "hata_surumleri": sorted({h["Version"] for h in dbg})}
    return {"durum": "eslesmedi", "ikili": None, "hata": None,
            "dizin_surumleri": sorted({k["Version"] for k in adaylar}),
            "hata_surumleri": sorted({h["Version"] for h in dbg}),
            "tum_ikili_surumleri": sorted({k["Version"] for k in ikili if k["Package"] == paket
                                           and k.get("Architecture") == mimari})}


def dagitim_dizinleri(dagitim: str, kok: Path) -> dict[str, Any]:
    """Dağıtımın bütün dizinlerini getir; kayıtları ``_dizin`` etiketiyle birleştir."""
    tanim = DAGITIMLAR[dagitim]
    bilgiler, ikili, hata = [], [], []
    for d in tanim["dizinler"]:
        b = dizin_getir(d, kok / dagitim)
        bilgiler.append(b)
        if not b["ok"]:
            continue
        for k in dizin_kayitlari(b):
            k["_dizin"] = d.etiket
            k["_taban"] = d.taban
            (ikili if d.tur == "ikili" else hata).append(k)
    return {"bilgiler": bilgiler, "ikili": ikili, "hata": hata}


def anahtar_halkasi(dagitim: str, kok: Path, ikili: list[dict[str, Any]]) -> dict[str, Any]:
    """Dağıtımın anahtar halkası paketlerini (HTTPS, dizin sha256'sı) indir, aç, halka dosyalarını döndür."""
    aile = DAGITIMLAR[dagitim]["aile"]
    halkalar: list[Path] = []
    kayit = []
    for paket, _ in ANAHTAR_PAKETLERI[aile]:
        adaylar = [k for k in ikili if k["Package"] == paket and k["_taban"].startswith("https://")]
        if not adaylar:
            kayit.append({"paket": paket, "ok": False, "hata": "dizinde yok"})
            continue
        best = adaylar[0]
        for k in adaylar[1:]:
            if surum_karsilastir(k["Version"], best["Version"]) > 0:
                best = k
        hedef = kok / dagitim / "anahtar" / Path(best["Filename"]).name
        s = indir(best["_taban"] + best["Filename"], hedef, beklenen_sha256=best["SHA256"],
                  beklenen_boyut=int(best["Size"]))
        if not s["ok"]:
            kayit.append({"paket": paket, "ok": False, "hata": s.get("hata")})
            continue
        ac = kok / dagitim / "anahtar" / f"x_{paket}"
        deb_ac(hedef, ac)
        for y in sorted((ac / "usr" / "share" / "keyrings").glob("*")):
            if y.suffix in (".gpg", ".pgp") and "removed" not in y.name and y.is_file():
                halkalar.append(y)
        kayit.append({"paket": paket, "surum": best["Version"], "sha256": s["sha256"], "ok": True,
                      "url": best["_taban"] + best["Filename"]})
    return {"halkalar": [str(h) for h in halkalar], "paketler": kayit}


def imzalari_dogrula(dagitim: str, kok: Path, bilgiler: list[dict[str, Any]], halkalar: list[str]) -> None:
    """Her dizinin InRelease imzasını doğrula; imzalı gövdedeki Packages.xz sha256'sını yeniden denetle."""
    ev = kok / dagitim / "anahtar" / "gnupg_ev"
    for b in bilgiler:
        if not b.get("ok"):
            continue
        g = gpgv_dogrula(Path(b["inrelease"]), [Path(h) for h in halkalar], ev)
        b["imza_ok"] = g["ok"]
        b["imza_parmak_izi"] = g["parmak_izi"]
        if not g["ok"]:
            b["imza_hata"] = g["hata"]
            continue
        d = b["dizin"]
        goreli = f"{d['bilesen']}/binary-{d['mimari']}/Packages.xz"
        hs = release_sha256(g["govde"])
        b["imzali_sha256_tutuyor"] = hs.get(goreli, (None, None))[1] == b["packages_sha256"]


# ---------------------------------------------------------------------------
# Snapshot (dizinde bulunamayan sürüm)
# ---------------------------------------------------------------------------

def snapshot_bul(arsiv_adaylari: tuple[str, ...], kaynak: str, kaynak_surum: str, paket: str,
                 ikili_surum_adaylari: Iterable[str], mimari: str) -> Optional[dict[str, Any]]:
    """snapshot.debian.org makine okunur API'siyle (kaynak, sürüm, ikili) dosyasını bul.

    Döner: {"hash" (sha1), "archive_name", "first_seen", "path", "name", "size", "binary_version"}.
    """
    for bv in ikili_surum_adaylari:
        url = (f"{ARSIV_SNAPSHOT}mr/package/{kaynak}/{kaynak_surum}/binfiles/{paket}/{bv}?fileinfo=1")
        metin = _getir_metin(url)
        if not metin:
            continue
        veri = json.loads(metin)
        for r in veri.get("result", []):
            if r.get("architecture") != mimari:
                continue
            for fi in veri.get("fileinfo", {}).get(r["hash"], []):
                if fi.get("archive_name") in arsiv_adaylari:
                    return {"hash": r["hash"], "binary_version": bv, **fi}
    return None


def snapshot_dizinle_dogrula(bulgu: dict[str, Any], suite_adaylari: tuple[str, ...], bilesen: str,
                             mimari: str, kok: Path, paket: str) -> Optional[dict[str, Any]]:
    """Dosyanın ilk görüldüğü andaki snapshot ``Packages`` dizininde kaydını bul (sha256 için)."""
    zaman = bulgu["first_seen"]
    arsiv = bulgu["archive_name"]
    taban = f"{ARSIV_SNAPSHOT}archive/{arsiv}/{zaman}/"
    for suite in suite_adaylari:
        d = Dizin(f"snapshot_{arsiv}_{zaman}_{suite}_{bilesen}", taban, suite, bilesen, mimari, "ikili")
        b = dizin_getir(d, kok)
        if not b["ok"]:
            continue
        for k in dizin_kayitlari(b):
            if k["Package"] == paket and k.get("Architecture") == mimari \
                    and Path(k["Filename"]).name == bulgu["name"]:
                k["_dizin"] = d.etiket
                k["_taban"] = taban
                return {"kayit": k, "dizin": b}
    return None


# ---------------------------------------------------------------------------
# .deb açma ve ELF / BuildID
# ---------------------------------------------------------------------------

def ar_uyeleri(yol: Path) -> dict[str, bytes]:
    veri = Path(yol).read_bytes()
    if veri[:8] != b"!<arch>\n":
        raise ValueError(f"{yol}: ar arşivi değil")
    off, out = 8, {}
    while off + 60 <= len(veri):
        bas = veri[off:off + 60]
        ad = bas[:16].decode("ascii", "replace").strip().rstrip("/")
        boy = int(bas[48:58].decode("ascii").strip())
        out[ad] = veri[off + 60: off + 60 + boy]
        off += 60 + boy + (boy & 1)
    return out


def _suzgec(uye: tarfile.TarInfo, yol: str) -> Optional[tarfile.TarInfo]:
    try:
        return tarfile.data_filter(uye, yol)
    except tarfile.FilterError:
        return None


def deb_ac(deb: Path, hedef: Path) -> dict[str, Any]:
    """``.deb`` / ``.ddeb``'in ``data.tar.*`` üyesini ``hedef``'e aç (yeni boş dizin; yol kaçışı yok).

    Dizin varsa ve boş değilse dokunulmaz (önceki açma); dönüşte ``atlandi`` işaretlenir.
    """
    if hedef.exists() and any(hedef.iterdir()):
        return {"atlandi": True, "hedef": str(hedef)}
    hedef.mkdir(parents=True, exist_ok=True)
    uyeler = ar_uyeleri(deb)
    ad = next(n for n in uyeler if n.startswith("data.tar"))
    blob = uyeler[ad]
    if ad.endswith(".xz"):
        blob = lzma.decompress(blob)
    elif ad.endswith(".zst"):
        import zstandard
        blob = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(blob)).read()
    elif ad.endswith(".gz"):
        import gzip
        blob = gzip.decompress(blob)
    kok = hedef.resolve()
    atlanan = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
        uyeler_ = tf.getmembers()
        for m in uyeler_:
            hedef_yol = (kok / m.name).resolve()
            if hedef_yol != kok and not str(hedef_yol).startswith(str(kok) + os.sep):
                raise RuntimeError(f"{deb}: tehlikeli yol")
        for m in uyeler_:
            if _suzgec(m, str(kok)) is None:
                atlanan += 1
        tf.extractall(kok, filter=_suzgec)
    return {"atlandi": False, "hedef": str(hedef), "data_uyesi": ad, "uye": len(uyeler_),
            "suzgecte_atlanan": atlanan}


def elf_bilgisi(yol: Path) -> Optional[dict[str, Any]]:
    """ELF ise: tip, makine, BuildID, PT_INTERP, .symtab ve hata ayıklama bölümü var mı. Sembol okunmaz."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection

    with open(yol, "rb") as f:
        if f.read(4) != b"\x7fELF":
            return None
        f.seek(0)
        try:
            elf = ELFFile(f)
            bid = None
            symtab = False
            hata_bolumu = False
            for sec in elf.iter_sections():
                if isinstance(sec, NoteSection):
                    for n in sec.iter_notes():
                        # yalnız sahibi "GNU" olan not: pyelftools SystemTap (``stapsdt``) notlarını da
                        # tür numarası 3 olduğu için NT_GNU_BUILD_ID diye etiketliyor (postgres'te görüldü)
                        if n["n_type"] == "NT_GNU_BUILD_ID" and n["n_name"] == "GNU" and isinstance(n["n_desc"], str):
                            bid = n["n_desc"]
                if sec.name == ".symtab":
                    symtab = True
                if sec.name.startswith((".debug_", ".zdebug_")):
                    hata_bolumu = True
            interp = any(seg["p_type"] == "PT_INTERP" for seg in elf.iter_segments())
            return {"tip": elf["e_type"], "makine": elf["e_machine"], "build_id": bid, "interp": interp,
                    "symtab": symtab, "hata_bolumu": hata_bolumu}
        except (ELFError, Exception) as e:  # bozuk ELF: kayda geçer
            return {"tip": "bozuk", "hata": type(e).__name__, "build_id": None}


def elf_envanteri(kok: Path) -> list[dict[str, Any]]:
    """``kok`` altındaki düzenli ELF dosyaları (sembolik bağlar atlanır)."""
    out = []
    for yol in sorted(kok.rglob("*")):
        if yol.is_symlink() or not yol.is_file():
            continue
        b = elf_bilgisi(yol)
        if b is None:
            continue
        b["yol"] = str(yol.relative_to(kok))
        b["boyut"] = yol.stat().st_size
        b["sha256"] = sha256_dosya(yol)
        out.append(b)
    return out


def hata_dosyalari(dbg_kok: Path) -> dict[str, Path]:
    """Hata ayıklama ağacındaki ``.build-id/xx/yyyy.debug`` → {build_id: yol}."""
    out = {}
    for yol in dbg_kok.glob("usr/lib/debug/.build-id/*/*.debug"):
        if yol.is_symlink():
            continue
        out[yol.parent.name + yol.name[:-len(".debug")]] = yol
    return out


def _f1_modulu():
    if str(OLCUM) not in sys.path:
        sys.path.insert(0, str(OLCUM))
    spec = importlib.util.spec_from_file_location("function_f1", OLCUM / "function_f1.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("function_f1", m)
    spec.loader.exec_module(m)
    return m


def buildid_eslestir(ikili_kok: Path, dbg_kok: "Path | list[Path]", *, gt_say: bool = True) -> dict[str, Any]:
    """İkili paketteki her ELF ↔ hata ayıklama dosyası. Yalnız sayılar ve sha256 / BuildID döner.

    ``dbg_kok`` tek dizin ya da dizin listesi olabilir (ör. hata ayıklama dosyaları birden çok pakette).
    """
    elfler = elf_envanteri(ikili_kok)
    kokler = [dbg_kok] if isinstance(dbg_kok, Path) else list(dbg_kok)
    dbg: dict[str, Path] = {}
    kok_of: dict[str, Path] = {}
    for k in kokler:
        for bid, y in hata_dosyalari(k).items():
            dbg.setdefault(bid, y)
            kok_of.setdefault(bid, k)
    f1 = _f1_modulu() if gt_say else None
    satirlar = []
    for e in elfler:
        s = {"yol": e["yol"], "boyut": e["boyut"], "sha256": e["sha256"], "build_id": e["build_id"],
             "tip": e["tip"], "makine": e.get("makine"), "interp": e.get("interp")}
        dy = dbg.get(e["build_id"] or "")
        if dy is None:
            s["eslesme"] = "hata ayıklama dosyası yok"
        else:
            db = elf_bilgisi(dy) or {}
            s["debug_kok"] = kok_of[e["build_id"]].name
            s["debug_yol"] = str(dy.relative_to(kok_of[e["build_id"]]))
            s["debug_sha256"] = sha256_dosya(dy)
            s["debug_build_id"] = db.get("build_id")
            if db.get("build_id") != e["build_id"]:
                s["eslesme"] = "BuildID farklı"
            elif f1 is not None:
                try:
                    gt = f1.extract_gt(dy, ikili_kok / e["yol"])
                    s["eslesme"] = "eşleşti"
                    s["gt_sayilari"] = gt["counts"]
                except Exception as ex:  # extract_gt'nin reddi (ör. .symtab yok) kayda geçer
                    s["eslesme"] = f"extract_gt reddetti: {type(ex).__name__}"
                    s["extract_gt_hata"] = str(ex)[:200].replace(str(ikili_kok), "<ikili>")
            else:
                s["eslesme"] = "eşleşti"
        satirlar.append(s)
    dwz = sorted(f"{k.name}/{p.relative_to(k)}" for k in kokler for p in k.glob("usr/lib/debug/.dwz/**/*")
                 if p.is_file())
    return {"elf": len(elfler), "eslesen": sum(1 for s in satirlar if s["eslesme"] == "eşleşti"),
            "satirlar": satirlar, "dwz": dwz, "hata_dosyasi": len(dbg)}


# ---------------------------------------------------------------------------
# Tabaka: dizin → seçim
# ---------------------------------------------------------------------------

def gelistirme_surumleri(kunye: Path = GELISTIRME_KUNYESI) -> dict[str, str]:
    veri = json.loads(kunye.read_text(encoding="utf-8"))
    return {p: veri["paketler"][p]["surum"] for p in GELISTIRME_PAKETLERI}


def _tabaka_paket_secimi(dagitim: str, alt: str, d: dict[str, Any], kok: Path, gel: dict[str, str],
                         tabaka: str) -> list[dict[str, Any]]:
    tanim = DAGITIMLAR[dagitim]
    mimari = tanim["dizinler"][0].mimari
    out = []
    for p in GELISTIRME_PAKETLERI:
        dbg_adi = hata_paketi_adi(p, tanim["aile"])
        ks = None
        if tabaka == "a":
            # geliştirme setindeki arm64 kaydının kaynak sürümü (binNMU eki kaynak sürümünde yok)
            ks = re.sub(r"\+b\d+$", "", epochsuz(gel[p]))
        c = cift_sec(d["ikili"], d["hata"], p, dbg_adi, mimari, ks)
        satir: dict[str, Any] = {"tabaka": tabaka, "alt": alt, "dagitim": dagitim, "paket": p,
                                 "hata_paketi": dbg_adi, "mimari": mimari, "kaynak_surum_kosulu": ks,
                                 "dizin_surumleri": c["dizin_surumleri"], "hata_surumleri": c["hata_surumleri"]}
        if c["durum"] == "bulundu":
            satir.update(_dosya_satiri(c["ikili"], "ikili"))
            satir.update(_dosya_satiri(c["hata"], "hata"))
            satir["kaynak"] = "dizin"
        elif tabaka == "a":
            satir.update(_snapshot_cifti(p, dbg_adi, ks, mimari, kok / dagitim, gel[p]))
        else:
            satir["kaynak"] = "yok"
            satir["neden"] = (f"dizinde {p} sürümleri {c.get('tum_ikili_surumleri')}, {dbg_adi} sürümleri "
                              f"{c['hata_surumleri']}: aynı sürümde çift yok")
        out.append(satir)
    return out


def _dosya_satiri(k: dict[str, Any], on: str) -> dict[str, Any]:
    return {f"{on}_surum": k["Version"], f"{on}_url": k["_taban"] + k["Filename"],
            f"{on}_dosya": Path(k["Filename"]).name, f"{on}_boyut": int(k["Size"]),
            f"{on}_sha256": k["SHA256"].lower(), f"{on}_dizin": k["_dizin"],
            f"{on}_kaynak_surum": kaynak_surumu(k), f"{on}_build_ids": k.get("Build-Ids", "")}


def _snapshot_cifti(p: str, dbg_adi: str, ks: str, mimari: str, kok: Path, gel_surum: str) -> dict[str, Any]:
    """Tabaka A: dizinde olmayan kaynak sürümünü snapshot.debian.org'da ara."""
    kaynak = {"openssl": "openssl", "redis-tools": "redis", "sqlite3": "sqlite3", "coreutils": "coreutils",
              "zstd": "libzstd", "tmux": "tmux", "htop": "htop", "tree": "tree"}[p]
    epoch = gel_surum.split(":", 1)[0] + ":" if ":" in gel_surum else ""
    kaynak_tam = epoch + ks
    ikili_adaylar = [kaynak_tam] + [f"{kaynak_tam}+b{i}" for i in range(1, 6)]
    out: dict[str, Any] = {"kaynak": "snapshot"}
    for on, ad, arsivler, suiteler in (
            ("ikili", p, ("debian", "debian-security"),
             ("trixie", "trixie-proposed-updates", "trixie-updates", "trixie-security")),
            ("hata", dbg_adi, ("debian-debug", "debian-security-debug"),
             ("trixie-debug", "trixie-proposed-updates-debug", "trixie-security-debug"))):
        b = snapshot_bul(arsivler, kaynak, kaynak_tam, ad, ikili_adaylar, mimari)
        if b is None:
            out["kaynak"] = "yok"
            out["neden"] = f"snapshot.debian.org'da {ad} {kaynak_tam} {mimari} bulunamadı"
            return out
        v = snapshot_dizinle_dogrula(b, suiteler, "main", mimari, kok, ad)
        if v is None:
            out["kaynak"] = "yok"
            out["neden"] = (f"snapshot dosyası bulundu ({b['name']}, {b['first_seen']}) ama o anki "
                            f"Packages dizininde kaydı yok; sha256 dizinle doğrulanamadı")
            return out
        k = v["kayit"]
        out.update(_dosya_satiri(k, on))
        out[f"{on}_snapshot_sha1"] = b["hash"]
        out[f"{on}_snapshot_dizin_sha256"] = v["dizin"]["packages_sha256"]
        out[f"{on}_snapshot_inrelease"] = v["dizin"]["inrelease"]
    return out


def secim_yap(indir_kok: Path) -> dict[str, Any]:
    gel = gelistirme_surumleri()
    kilitli = kilitli_adlar()
    paketler, dizinler, anahtarlar = [], {}, {}
    for tabaka, dagitimlar in TABAKALAR.items():
        for dagitim, alt in dagitimlar:
            d = dagitim_dizinleri(dagitim, indir_kok / "indeks")
            a = anahtar_halkasi(dagitim, indir_kok / "indeks", d["ikili"])
            imzalari_dogrula(dagitim, indir_kok / "indeks", d["bilgiler"], a["halkalar"])
            dizinler[dagitim] = d["bilgiler"]
            anahtarlar[dagitim] = a
            paketler += _tabaka_paket_secimi(dagitim, alt, d, indir_kok / "indeks", gel, tabaka)
    # snapshot dizinlerinin imzası (tabaka A)
    for s in paketler:
        for on in ("ikili", "hata"):
            inr = s.get(f"{on}_snapshot_inrelease")
            if inr:
                g = gpgv_dogrula(Path(inr), [Path(h) for h in anahtarlar[s["dagitim"]]["halkalar"]],
                                 indir_kok / "indeks" / s["dagitim"] / "anahtar" / "gnupg_ev")
                s[f"{on}_snapshot_imza_ok"] = g["ok"]
                s[f"{on}_snapshot_imza_parmak_izi"] = g["parmak_izi"]
    adlar = set(GELISTIRME_PAKETLERI) | {s["hata_paketi"] for s in paketler}
    toplam = sum(s.get("ikili_boyut", 0) + s.get("hata_boyut", 0) for s in paketler)
    return {"sema": SEMA_SECIM, "tarih_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "gelistirme_kunyesi": str(GELISTIRME_KUNYESI), "gelistirme_surumleri": gel,
            "kilit_belgeleri": {str(b.relative_to(REPO)): sha256_dosya(b) for b in KILIT_BELGELERI},
            "kilitli_ad_sayisi": len(kilitli), "kilit_kesisimi": kilit_suzgeci(adlar, kilitli),
            "kilit_yakinligi": kilit_yakinligi(adlar, kilitli),
            "dizinler": dizinler, "anahtarlar": anahtarlar, "paketler": paketler,
            "toplam_paket_bayt": toplam}


# ---------------------------------------------------------------------------
# Tabaka: indir → doğrula → aç → BuildID
# ---------------------------------------------------------------------------

def tabaka_indir(secim: dict[str, Any], indir_kok: Path, veri_kok: Path) -> dict[str, Any]:
    if secim["kilit_kesisimi"]:
        raise SystemExit(f"kilitli ad kesişimi boş değil: {secim['kilit_kesisimi']}")
    if secim["toplam_paket_bayt"] > TOPLAM_SINIR:
        raise SystemExit(f"toplam {secim['toplam_paket_bayt']} bayt > 2 GiB; dur")
    out = []
    for s in secim["paketler"]:
        r = {k: s[k] for k in ("tabaka", "alt", "dagitim", "paket", "hata_paketi", "kaynak") if k in s}
        if s.get("kaynak") == "yok":
            r["durum"] = "bulunamadı"
            r["neden"] = s.get("neden")
            out.append(r)
            continue
        alt_indir = indir_kok / s["alt"]
        alt_veri = veri_kok / s["tabaka"] / (s["alt"] if s["tabaka"] == "b" else "")
        dosyalar = {}
        hata = None
        for on in ("ikili", "hata"):
            hedef = alt_indir / s[f"{on}_dosya"]
            d = indir(s[f"{on}_url"], hedef, beklenen_sha256=s[f"{on}_sha256"], beklenen_boyut=s[f"{on}_boyut"])
            if True:   # her iki dosya da kayda geçer
                dosyalar[on] = {"surum": s[f"{on}_surum"], "dosya": s[f"{on}_dosya"], "url": s[f"{on}_url"],
                                "boyut": s[f"{on}_boyut"], "sha256_dizin": s[f"{on}_sha256"],
                                "sha256_dosya": d.get("sha256"), "sha256_tuttu": bool(d.get("ok")),
                                "indirme": d.get("durum"), "dizin": s[f"{on}_dizin"]}
                if s.get(f"{on}_snapshot_sha1"):
                    dosyalar[on]["snapshot_sha1"] = s[f"{on}_snapshot_sha1"]
                    dosyalar[on]["sha1_tuttu"] = d.get("ok") and sha1_dosya(hedef) == s[f"{on}_snapshot_sha1"]
            if not d["ok"]:
                hata = f"indirilemedi: {s[f'{on}_dosya']}: {d.get('hata')}"
                break
        r["dosyalar"] = dosyalar
        if hata:
            r["durum"] = hata
            out.append(r)
            continue
        ac_i = deb_ac(alt_indir / s["ikili_dosya"], alt_veri / f"x_{s['paket']}")
        ac_h = deb_ac(alt_indir / s["hata_dosya"], alt_veri / f"x_{s['hata_paketi']}")
        r["acma"] = {"ikili": ac_i, "hata": ac_h}
        e = buildid_eslestir(alt_veri / f"x_{s['paket']}", alt_veri / f"x_{s['hata_paketi']}")
        r["buildid"] = e
        r["durum"] = "tamam" if e["elf"] and e["eslesen"] == e["elf"] else "eksik eşleşme"
        out.append(r)
    return {"sema": SEMA_VERI, "tarih_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "secim_sha256": None, "paketler": out}


def rapor(veri: dict[str, Any]) -> str:
    """TABAKA_VERI.md tablosu (betik çıktısı)."""
    satirlar = ["| tabaka | dağıtım | paket | sürüm (.deb / dbgsym) | kaynak | .deb bayt | dbgsym bayt | "
                ".deb sha256 | dbgsym sha256 | sha256 = dizin | ELF | BuildID eşleşen | extract_gt FUNC (toplam) | durum |",
                "|---|---|---|---|---|---:|---:|---|---|---|---:|---:|---:|---|"]
    top_i = top_h = 0
    for r in veri["paketler"]:
        ds = r.get("dosyalar", {})
        i, h = ds.get("ikili", {}), ds.get("hata", {})
        b = r.get("buildid", {})
        fn = sum((s.get("gt_sayilari") or {}).get("functions", 0) for s in b.get("satirlar", []))
        top_i += i.get("boyut", 0) if i.get("sha256_tuttu") else 0
        top_h += h.get("boyut", 0) if h.get("sha256_tuttu") else 0
        tut = "evet / evet" if i.get("sha256_tuttu") and h.get("sha256_tuttu") else (
            "—" if not ds else f"{'evet' if i.get('sha256_tuttu') else 'HAYIR'} / {'evet' if h.get('sha256_tuttu') else 'HAYIR'}")
        satirlar.append(
            f"| {r['tabaka'].upper()} | {r['dagitim']} | {r['paket']} | "
            f"{i.get('surum', '—')} / {h.get('surum', '—')} | {r.get('kaynak', '—')} | "
            f"{i.get('boyut', '—')} | {h.get('boyut', '—')} | "
            f"`{(i.get('sha256_dosya') or '—')}` | `{(h.get('sha256_dosya') or '—')}` | {tut} | "
            f"{b.get('elf', '—')} | {b.get('eslesen', '—')} | {fn if b else '—'} | {r['durum']} |")
    satirlar.append("")
    satirlar.append(f"İndirilen ve sha256'sı tutan: .deb {top_i} bayt, dbgsym {top_h} bayt, toplam {top_i + top_h} bayt "
                    f"({(top_i + top_h) / 1048576:.2f} MiB).")
    return "\n".join(satirlar)


GELISTIRME_KOSU_KOKU = Path.home() / "karadul_olcum" / "n1_debian13"


def derleyici_izleri(yol: Path) -> list[str]:
    """Derleyici izi: ``.comment`` satırları; yoksa DWARF'ta ilk derleme biriminin ``DW_AT_producer``'ı
    (yalnız ilk üç sözcük: dil, derleyici, sürüm; bayraklar atılır).

    Yalnız geliştirme setinin programlarında kullanılır (kör nüfusta dizgi okunmaz)."""
    from elftools.elf.elffile import ELFFile
    with open(yol, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".comment")
        if sec is not None and sec.header["sh_type"] != "SHT_NOBITS":
            satir = sorted({x.decode("utf-8", "replace") for x in sec.data().split(b"\0") if x})
            if satir:
                return satir
        if not elf.has_dwarf_info():
            return []
        try:
            for cu in elf.get_dwarf_info().iter_CUs():
                at = cu.get_top_DIE().attributes.get("DW_AT_producer")
                if at is not None:
                    v = at.value.decode("utf-8", "replace") if isinstance(at.value, bytes) else str(at.value)
                    return [" ".join(v.split()[:3])]
        except Exception:   # DWARF okunamadı: iz yok
            return []
    return []


def gelistirme_kiyasi(veri: dict[str, Any], veri_kok: Path,
                      kosu_koku: Path = GELISTIRME_KOSU_KOKU) -> list[dict[str, Any]]:
    """Tabaka ELF adları ↔ geliştirme seti birim dizinleri; makine; derleyici; function_f1 BuildID sapması."""
    f1 = _f1_modulu()
    out = []
    for r in veri["paketler"]:
        if "buildid" not in r:
            continue
        alt = veri_kok / r["tabaka"] / (r["alt"] if r["tabaka"] == "b" else "")
        xi = alt / f"x_{r['paket']}"
        adlar = {Path(s["yol"]).name for s in r["buildid"]["satirlar"]}
        gel = {d.name for d in (kosu_koku / r["paket"]).iterdir() if d.is_dir()} if (kosu_koku / r["paket"]).is_dir() else set()
        sapma = 0
        derleyici: set[str] = set()
        xh = alt / f"x_{r['hata_paketi']}"
        for s in r["buildid"]["satirlar"]:
            i = f1.read_elf_info(xi / s["yol"])
            if not isinstance(i["build_id"], str) or i["build_id"] != s["build_id"]:
                sapma += 1
        for s in r["buildid"]["satirlar"][:3]:      # derleyici izi: paket başına ilk üç ELF'in .debug'ı
            if s.get("debug_yol"):
                derleyici.update(derleyici_izleri(xh / s["debug_yol"]))
        out.append({"tabaka": r["tabaka"], "dagitim": r["dagitim"], "paket": r["paket"], "elf": len(adlar),
                    "gelistirme_elf": len(gel), "eksik": sorted(gel - adlar), "fazla": sorted(adlar - gel),
                    "makine": sorted({str(s["makine"]) for s in r["buildid"]["satirlar"]}),
                    "derleyici": sorted(derleyici), "f1_buildid_sapmasi": sapma})
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    a1 = alt.add_parser("dizin", help="dizinleri getir, doğrula, sürüm seç (paket indirmez)")
    a1.add_argument("--indir-kok", type=Path, required=True)
    a1.add_argument("--json", type=Path, required=True)
    a2 = alt.add_parser("indir", help="seçilen paketleri indir, doğrula, aç, BuildID eşleştir")
    a2.add_argument("--secim", type=Path, required=True)
    a2.add_argument("--indir-kok", type=Path, required=True)
    a2.add_argument("--veri-kok", type=Path, required=True)
    a2.add_argument("--json", type=Path, required=True)
    a3 = alt.add_parser("rapor", help="TABAKA_VERI.md tablosu")
    a3.add_argument("--veri", type=Path, required=True)
    a5 = alt.add_parser("kiyas", help="tabaka ELF adları ↔ geliştirme seti; makine; derleyici; BuildID sapması")
    a5.add_argument("--veri", type=Path, required=True)
    a5.add_argument("--veri-kok", type=Path, required=True)
    a4 = alt.add_parser("kilit", help="kilit belgelerinden okunan ad sayısı ve verilen adların kesişimi")
    a4.add_argument("adlar", nargs="*")
    ns = ap.parse_args(argv)

    if ns.komut == "dizin":
        s = secim_yap(ns.indir_kok.expanduser())
        ns.json.parent.mkdir(parents=True, exist_ok=True)
        ns.json.write_text(json.dumps(s, ensure_ascii=False, indent=1), encoding="utf-8")
        for p in s["paketler"]:
            print(f"{p['tabaka']} {p['dagitim']:18s} {p['paket']:12s} {p.get('kaynak'):9s} "
                  f"{p.get('ikili_surum', '—'):24s} {p.get('ikili_boyut', 0):>9} {p.get('hata_boyut', 0):>10} "
                  f"{p.get('neden', '')}")
        for dag, bl in s["dizinler"].items():
            for b in bl:
                print(f"dizin {dag} {b['dizin']['etiket']}: ok={b['ok']} imza={b.get('imza_ok')} "
                      f"imzalı_sha256={b.get('imzali_sha256_tutuyor')} {b.get('hata', '')}")
        print(f"kilitli ad: {s['kilitli_ad_sayisi']}; kesişim: {s['kilit_kesisimi']}; yakınlık: {s['kilit_yakinligi']}")
        print(f"toplam paket baytı: {s['toplam_paket_bayt']} ({s['toplam_paket_bayt'] / 1048576:.2f} MiB)")
        return 0
    if ns.komut == "indir":
        secim = json.loads(ns.secim.read_text(encoding="utf-8"))
        v = tabaka_indir(secim, ns.indir_kok.expanduser(), ns.veri_kok.expanduser())
        v["secim_sha256"] = sha256_dosya(ns.secim)
        ns.json.parent.mkdir(parents=True, exist_ok=True)
        ns.json.write_text(json.dumps(v, ensure_ascii=False, indent=1), encoding="utf-8")
        print(rapor(v))
        return 0
    if ns.komut == "rapor":
        print(rapor(json.loads(ns.veri.read_text(encoding="utf-8"))))
        return 0
    if ns.komut == "kiyas":
        k = gelistirme_kiyasi(json.loads(ns.veri.read_text(encoding="utf-8")), ns.veri_kok.expanduser())
        print("| tabaka | dağıtım | paket | ELF | geliştirme setindeki ELF | ad farkı (eksik / fazla) | makine | derleyici (`.comment`) | `function_f1` BuildID sapması |")
        print("|---|---|---|---:|---:|---|---|---|---:|")
        for x in k:
            print(f"| {x['tabaka'].upper()} | {x['dagitim']} | {x['paket']} | {x['elf']} | {x['gelistirme_elf']} | "
                  f"{len(x['eksik'])} / {len(x['fazla'])} | {', '.join(x['makine'])} | {'; '.join(x['derleyici'])} | "
                  f"{x['f1_buildid_sapmasi']} |")
        print(f"\nToplam ELF: {sum(x['elf'] for x in k)}; ad farkı olan paket: "
              f"{sum(1 for x in k if x['eksik'] or x['fazla'])}; BuildID sapması: {sum(x['f1_buildid_sapmasi'] for x in k)}")
        return 0
    if ns.komut == "kilit":
        k = kilitli_adlar()
        print(f"kilitli ad sayısı: {len(k)}")
        print(f"kesişim: {kilit_suzgeci(ns.adlar, k)}")
        print(f"yakınlık: {kilit_yakinligi(ns.adlar, k)}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
