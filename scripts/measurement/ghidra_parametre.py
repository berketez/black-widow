#!/usr/bin/env python3
"""Ghidra parametre dışa aktarımı (plan v2.2 T0b): her fonksiyonun iki parametre kümesi.

K1 kapısı Ghidra'nın gördüğü parametreler (decompile edilmiş C'deki ``param_1..N``) üstünde
çalışır; gerçeği DWARF verir (``dwarf_tip.py``). Karadul'un kendi dışa aktarımı
(``ghidra_functions.json``) parametre için yalnız ad, tip ve ordinal tutar; yazmaç ya da yığın
konumu yoktur. Bu betik aynı ikiliyi Karadul'un ayarlarıyla analiz eder ve her fonksiyon için
şunları yazar:

- giriş adresi, gövde aralıkları, girişteki ilk 16 bayt (PIE taban doğrulaması için);
- **liste imzası** (``Function.getParameters()``): Karadul'un ``ghidra_functions.json``'ı buradan
  okur; sıra, ad, tip, boyut, depolama;
- **decompiler parametreleri** (``HighFunction`` yerel sembol haritasının parametreleri): C'deki
  ``param_N``'ler; sıra, ad, tip, boyut, depolama; prototip modeli, değişken argüman bayrağı,
  C imzası ve C metni.

Depolama parçaları: ``{"tur": "yazmac", "ad": "w0", "boyut": 4}``,
``{"tur": "yigin", "ofset": 8, "boyut": 8}`` ya da adres uzayının adı (``unique``, ``ram``…).

Karadul ayarlarının taklidi (``karadul/ghidra/headless.py``, ``GhidraHeadless._analyze_pyghidra``)
------------------------------------------------------------------------------------------------
- Kurulum ``karadul.config.GHIDRA_PINNED_DIR`` (sürüm ``application.properties``'ten doğrulanır,
  ``GHIDRA_PINNED_VERSION`` değilse durulur). Karadul önce ``GHIDRA_INSTALL_DIR``/``GHIDRA_HOME``
  ortam değişkenine bakar; bu betik bakmaz, sabitlenen kurulumu kullanır.
- JVM ``karadul.ghidra.headless._ensure_pyghidra_started`` ile başlar: aynı
  ``HeadlessPyGhidraLauncher`` ve aynı VM argümanları.
- İçe aktarma ve analiz ``pyghidra.open_program(binary_path, project_location, project_name,
  analyze=True)``: Ghidra'nın varsayılan analizörleri; Karadul analiz seçeneği değiştirmiyor,
  analize zaman aşımı koymuyor. Açık/kapalı analizörler belgeye yazılır.
- GDT arşivleri ``Config().binary_reconstruction.ghidra_data_type_archives`` (varsayılan boş)
  Karadul'un kendi yöntemiyle (``GhidraHeadless._load_gdt_archives_pyghidra``) yüklenir. PDB
  yalnız PE'de denendiği için ELF'te yoktur.
- Liste imzası decompile'dan önce okunur (Karadul'un ``_extract_functions`` sırası).
- Decompile: iş parçacığı başına ``DecompInterface`` + ``DecompileOptions()`` (varsayılan;
  ``grabFromProgram`` yok) + ``openProgram``; ``decompileFunction(f, 30, ConsoleTaskMonitor())``.
  İş parçacığı sayısı ``CPU_PERF_CORES``, parça boyu ``max(1, n // CPU_PERF_CORES)``, toplam
  zaman aşımı ``Config().timeouts.ghidra`` (100 MB'den büyük ikilide ×4), Karadul'daki gibi.
- Karadul'un decompile sırasında ve sonrasında yaptığı ek çıkarımlar (disassembly, xref, yığın
  çerçevesi, seçici p-code, dizgiler, çağrı grafı, tipler, CFG, FunctionID) salt okunurdur ve
  decompiler sonucunu etkilemez; burada yapılmaz. BSim alımı ve sorgusu (Karadul'da varsayılan
  açık, ``~/.cache/karadul/bsim``'e YAZAR) decompile'dan sonradır; burada yapılmaz.
- Doğrulama (2026-10-21, tree 2.2.1-1): Karadul'un kendi ``GhidraHeadless.analyze``'ıyla aynı
  ikilide 250/250 fonksiyonda ad, liste imzası (``functions.json``) ve decompile edilmiş C metni
  (``decompiled/*.c``, başlık ve disassembly dışında) bayt bayt aynı.

Alt komutlar
------------
    cikar <ikili> -o <json> [--proje-kok <dizin>]
    toplu <liste> -o <çıktı dizini> [--zaman-asimi S] [--proje-kok <dizin>]
          (liste: satır başına bir ikili yolu, JSON dizi ya da ``parametre_hizala.py secim``
          çıktısı; her ikili ayrı süreçte, ayrı JVM'de; çıktısı olan ikili atlanır)
    ozet  <json ya da dizin...>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

SEMA = "karadul-ghidra-parametre/1"
GHIDRA_TOPLU_SEMA = "karadul-ghidra-parametre-toplu/1"
FONKSIYON_ZAMAN_ASIMI_S = 30       # headless.py _decompile_functions: FUNC_TIMEOUT = 30
ILK_BAYT = 16
TOPLU_ZAMAN_ASIMI_S = 3600         # ikili başına süreç zaman aşımı (toplu)
GHIDRA_PROJE_ADI = "karadul_t0b"


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _git_head() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent,
                              capture_output=True, text=True, timeout=10,
                              check=False).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _yaz_json(yol: Path, veri: Any) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    gecici = yol.with_suffix(yol.suffix + ".yaziliyor")
    gecici.write_text(json.dumps(veri, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    gecici.replace(yol)


def elf_build_id(yol: Path) -> Optional[str]:
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import NoteSection
        with open(yol, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return None
            f.seek(0)
            for sec in ELFFile(f).iter_sections():
                if isinstance(sec, NoteSection) and sec["sh_type"] != "SHT_NOBITS":
                    for n in sec.iter_notes():
                        if n["n_type"] == "NT_GNU_BUILD_ID":
                            return str(n["n_desc"])
    except Exception:       # noqa: BLE001 - yoklama: bozuk ya da ELF olmayan dosya
        return None
    return None


# ---------------------------------------------------------------------------
# Karadul ayarları
# ---------------------------------------------------------------------------

def karadul_ayarlari() -> dict[str, Any]:
    """Taklit edilen Karadul ayarları (künyeye yazılır)."""
    from karadul.config import (CPU_PERF_CORES, GHIDRA_HEAP_MB, GHIDRA_PINNED_DIR,
                                GHIDRA_PINNED_VERSION, Config, ghidra_install_info)
    kurulum = Path(os.path.expanduser(GHIDRA_PINNED_DIR)).resolve()
    bilgi = ghidra_install_info(kurulum)
    cfg = Config()
    br = cfg.binary_reconstruction
    return {
        "ghidra_kurulum": str(kurulum), "ghidra_surumu": bilgi.get("version"),
        "ghidra_sabit_surum": GHIDRA_PINNED_VERSION,
        "cpu_perf_cores": CPU_PERF_CORES, "ghidra_heap_mb": GHIDRA_HEAP_MB,
        "toplam_zaman_asimi_s": int(cfg.timeouts.ghidra),
        "buyuk_ikili_esigi_mb": br.large_binary_threshold_mb,
        "buyuk_ikili_carpani": br.large_binary_timeout_multiplier,
        "gdt_arsivleri": list(br.ghidra_data_type_archives),
        "pdb_auto_load": br.pdb_auto_load,
        "fonksiyon_zaman_asimi_s": FONKSIYON_ZAMAN_ASIMI_S,
    }


def arac_kunyesi(ayarlar: dict[str, Any]) -> dict[str, Any]:
    try:
        import pyghidra
        pyg = getattr(pyghidra, "__version__", None)
    except ImportError:
        pyg = None
    return {"betik": "scripts/measurement/ghidra_parametre.py",
            "betik_sha256": sha256_dosya(Path(__file__).resolve()), "git_head": _git_head(),
            "pyghidra": pyg, "python": platform.python_version(), "karadul_ayarlari": ayarlar}


# ---------------------------------------------------------------------------
# Ghidra tarafı (JVM gerekir; yalnız ``cikar`` çağırır)
# ---------------------------------------------------------------------------

def _depolama(prog: Any, st: Any) -> dict[str, Any]:
    """VariableStorage -> {"metin", "parcalar", "ozel"}."""
    if st is None:
        return {"metin": None, "parcalar": [], "ozel": "yok"}
    ozel = None
    for ad, yontem in (("bos", "isVoidStorage"), ("atanmamis", "isUnassignedStorage"),
                       ("bozuk", "isBadStorage"), ("karma", "isHashStorage"),
                       ("unique", "isUniqueStorage")):
        try:
            if getattr(st, yontem)():
                ozel = ad
                break
        except Exception:       # noqa: BLE001 - eski sürümlerde yöntem yok
            continue
    parcalar: list[dict[str, Any]] = []
    for vn in st.getVarnodes() or []:
        adr = vn.getAddress()
        boyut = int(vn.getSize())
        if adr.isRegisterAddress():
            r = prog.getRegister(adr, boyut)
            if r is None:
                r = prog.getRegister(adr)
            parcalar.append({"tur": "yazmac", "ad": str(r.getName()) if r is not None else None,
                             "boyut": boyut})
        elif adr.isStackAddress():
            parcalar.append({"tur": "yigin", "ofset": int(adr.getOffset()), "boyut": boyut})
        else:
            parcalar.append({"tur": str(adr.getAddressSpace().getName()),
                             "ofset": int(adr.getOffset()), "boyut": boyut})
    return {"metin": str(st), "parcalar": parcalar, "ozel": ozel}


def _liste_parametreleri(prog: Any, f: Any) -> list[dict[str, Any]]:
    sonuc = []
    for p in f.getParameters():
        sonuc.append({"sira": int(p.getOrdinal()) + 1, "ad": str(p.getName()),
                      "tip": str(p.getDataType()), "boyut": int(p.getLength()),
                      "depolama": _depolama(prog, p.getVariableStorage()),
                      "otomatik": bool(p.isAutoParameter())})
    return sonuc


def _ilk_baytlar(prog: Any, adr: Any) -> Optional[str]:
    from jpype import JArray, JByte
    try:
        tampon = JArray(JByte)(ILK_BAYT)
        n = int(prog.getMemory().getBytes(adr, tampon))
        return bytes((int(b) & 0xFF) for b in tampon[:n]).hex()
    except Exception:           # noqa: BLE001 - başlatılmamış bellek
        return None


def _fonksiyon_kaydi(prog: Any, f: Any) -> dict[str, Any]:
    giris = f.getEntryPoint()
    govde = [[int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset())]
             for r in f.getBody().getAddressRanges()]
    kayit: dict[str, Any] = {
        "ad": str(f.getName()), "giris": f"0x{int(giris.getOffset()):x}",
        "govde": govde, "boyut": int(f.getBody().getNumAddresses()),
        "thunk": bool(f.isThunk()), "harici": bool(f.isExternal()),
        "sembol_kaynagi": str(f.getSymbol().getSource()),
        "imza_kaynagi": str(f.getSignatureSource()),
        "cagri_kurali": str(f.getCallingConventionName()),
        "degisken_arguman": bool(f.hasVarArgs()),
        "ozel_depolama": bool(f.hasCustomVariableStorage()),
        "parametre_sayisi": int(f.getParameterCount()),
        "donus_tipi": str(f.getReturnType()),
        "ilk_baytlar": _ilk_baytlar(prog, giris),
        "liste_parametreleri": _liste_parametreleri(prog, f),
    }
    if f.isThunk():
        hedef = f.getThunkedFunction(False)
        kayit["thunk_hedefi"] = (f"0x{int(hedef.getEntryPoint().getOffset()):x}"
                                 if hedef is not None else None)
    return kayit


def _decompile_kaydi(prog: Any, decomp: Any, f: Any, monitor: Any) -> dict[str, Any]:
    """Karadul'un ``_decompile_single_function`` çağrısıyla aynı: decompileFunction(f, 30, m)."""
    try:
        sonuc = decomp.decompileFunction(f, FONKSIYON_ZAMAN_ASIMI_S, monitor)
    except Exception as h:      # noqa: BLE001 - Karadul da yakalayıp başarısız sayıyor
        return {"basarili": False, "hata": str(h)}
    if sonuc is None:
        return {"basarili": False, "hata": "None result"}
    df = sonuc.getDecompiledFunction()
    hf = sonuc.getHighFunction()
    if df is None or hf is None or not df.getC():
        return {"basarili": False, "hata": str(sonuc.getErrorMessage() or "Empty result"),
                "zaman_asimi": bool(sonuc.isTimedOut())}
    proto = hf.getFunctionPrototype()
    lsm = hf.getLocalSymbolMap()
    parametreler = []
    for i in range(int(lsm.getNumParams())):
        s = lsm.getParamSymbol(i)
        parametreler.append({
            "sira": i + 1, "indeks": int(s.getCategoryIndex()), "ad": str(s.getName()),
            "tip": str(s.getDataType()), "boyut": int(s.getSize()),
            "depolama": _depolama(prog, s.getStorage()),
            "tip_kilitli": bool(s.isTypeLocked()), "ad_kilitli": bool(s.isNameLocked())})
    try:
        donus_dep = _depolama(prog, proto.getReturnStorage())
    except Exception:           # noqa: BLE001
        donus_dep = None
    return {"basarili": True, "hata": None, "model": str(proto.getModelName()),
            "degisken_arguman": bool(proto.isVarArg()), "donus_tipi": str(proto.getReturnType()),
            "donus_depolama": donus_dep, "imza": str(df.getSignature()), "c": str(df.getC()),
            "parametreler": parametreler}


def _paralel_decompile(prog: Any, fonksiyonlar: list[Any], is_parcacigi: int,
                       toplam_zaman_asimi: int) -> dict[str, dict[str, Any]]:
    """headless.py ``_parallel_decompile_java_threads`` düzeni: aynı parça boyu ve iş parçacığı."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    n = len(fonksiyonlar)
    parca_boyu = max(1, n // is_parcacigi)
    parcalar = [fonksiyonlar[i:i + parca_boyu] for i in range(0, n, parca_boyu)]

    def isle(parca: list[Any]) -> dict[str, dict[str, Any]]:
        decomp = DecompInterface()
        decomp.setOptions(DecompileOptions())
        decomp.openProgram(prog)
        monitor = ConsoleTaskMonitor()
        cikti = {}
        try:
            for f in parca:
                cikti[f"0x{int(f.getEntryPoint().getOffset()):x}"] = _decompile_kaydi(
                    prog, decomp, f, monitor)
        finally:
            decomp.dispose()
        return cikti

    sonuc: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=is_parcacigi) as havuz:
        isler = {havuz.submit(isle, p): i for i, p in enumerate(parcalar)}
        for gelecek in as_completed(isler):
            i = isler[gelecek]
            try:
                sonuc.update(gelecek.result(timeout=toplam_zaman_asimi))
            except Exception as h:      # noqa: BLE001 - Karadul parçayı başarısız sayıyor
                for f in parcalar[i]:
                    sonuc[f"0x{int(f.getEntryPoint().getOffset()):x}"] = {
                        "basarili": False, "hata": f"parça hatası: {h}"}
    return sonuc


def _analizorler(prog: Any) -> dict[str, list[str]]:
    opts = prog.getOptions("Analyzers")
    acik, kapali = [], []
    for ad in sorted(str(x) for x in opts.getOptionNames()):
        if "." in ad:
            continue                    # alt seçenek
        try:
            (acik if opts.getBoolean(ad, False) else kapali).append(ad)
        except Exception:               # noqa: BLE001 - boolean olmayan seçenek
            continue
    return {"acik": acik, "kapali": kapali}


def _decompiler_varsayilanlari() -> dict[str, Any]:
    from ghidra.app.decompiler import DecompileOptions
    o = DecompileOptions()
    sonuc: dict[str, Any] = {}
    for ad, yontem in (("varsayilan_zaman_asimi", "getDefaultTimeout"),
                       ("en_cok_yuk_mb", "getMaxPayloadMBytes"),
                       ("en_cok_komut", "getMaxInstructions"),
                       ("prototip_modeli", "getProtoEvalModel"),
                       ("erisilmezi_ele", "isEliminateUnreachable")):
        try:
            v = getattr(o, yontem)()
            sonuc[ad] = v if isinstance(v, (bool, int)) else str(v)
        except Exception:               # noqa: BLE001
            sonuc[ad] = None
    return sonuc


def cikar(ikili: Path, cikti: Path, *, proje_kok: Optional[Path] = None,
          is_parcacigi: Optional[int] = None) -> dict[str, Any]:
    from karadul.config import Config
    from karadul.ghidra.headless import GhidraHeadless, _ensure_pyghidra_started

    ayarlar = karadul_ayarlari()
    if ayarlar["ghidra_surumu"] != ayarlar["ghidra_sabit_surum"]:
        raise RuntimeError(f"Ghidra {ayarlar['ghidra_surumu']} ({ayarlar['ghidra_kurulum']}); "
                           f"sabitlenen {ayarlar['ghidra_sabit_surum']}")
    kurulum = Path(ayarlar["ghidra_kurulum"])
    ikili = ikili.resolve()
    toplam_za = ayarlar["toplam_zaman_asimi_s"]
    if ikili.stat().st_size > ayarlar["buyuk_ikili_esigi_mb"] * 1024 * 1024:
        toplam_za = int(toplam_za * ayarlar["buyuk_ikili_carpani"])
    n_is = is_parcacigi or ayarlar["cpu_perf_cores"]
    sureler: dict[str, float] = {}
    t0 = time.monotonic()
    _ensure_pyghidra_started(kurulum)
    import pyghidra
    sureler["jvm"] = round(time.monotonic() - t0, 3)
    if proje_kok is not None:
        proje_kok.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="karadul-t0b-",
                                     dir=str(proje_kok) if proje_kok else None) as proje:
        t1 = time.monotonic()
        with pyghidra.open_program(binary_path=str(ikili), project_location=proje,
                                   project_name=GHIDRA_PROJE_ADI, analyze=True) as api:
            prog = api.getCurrentProgram()
            sureler["ice_aktarma_ve_analiz"] = round(time.monotonic() - t1, 3)
            gdt = ayarlar["gdt_arsivleri"]
            gdt_yuklenen = (GhidraHeadless._load_gdt_archives_pyghidra(prog, kurulum, gdt)
                            if gdt else 0)
            t2 = time.monotonic()
            fm = prog.getFunctionManager()
            fonks = []
            it = fm.getFunctions(True)
            while it.hasNext():
                fonks.append(it.next())
            kayitlar = [_fonksiyon_kaydi(prog, f) for f in fonks]     # decompile'dan ÖNCE
            sureler["liste_imzasi"] = round(time.monotonic() - t2, 3)
            t3 = time.monotonic()
            dec = _paralel_decompile(prog, fonks, n_is, toplam_za)
            sureler["decompile"] = round(time.monotonic() - t3, 3)
            for k in kayitlar:
                k["decompile"] = dec.get(k["giris"], {"basarili": False, "hata": "sonuç yok"})
            bloklar = [{"ad": str(b.getName()), "bas": f"0x{int(b.getStart().getOffset()):x}",
                        "son": f"0x{int(b.getEnd().getOffset()):x}", "boyut": int(b.getSize()),
                        "izin": ("r" if b.isRead() else "-") + ("w" if b.isWrite() else "-")
                                + ("x" if b.isExecute() else "-"),
                        "baslatilmis": bool(b.isInitialized())}
                       for b in prog.getMemory().getBlocks()]
            program = {"ad": str(prog.getName()),
                       "image_base": f"0x{int(prog.getImageBase().getOffset()):x}",
                       "dil": str(prog.getLanguageID()),
                       "derleyici": str(prog.getCompilerSpec().getCompilerSpecID()),
                       "bicim": str(prog.getExecutableFormat()),
                       "bloklar": bloklar, "analizorler": _analizorler(prog),
                       "gdt_yuklenen": gdt_yuklenen,
                       "decompiler_varsayilanlari": _decompiler_varsayilanlari()}
    basarili = sum(1 for k in kayitlar if k["decompile"]["basarili"])
    belge = {
        "sema": SEMA, "arac": arac_kunyesi(ayarlar),
        "girdi": {"ikili": str(ikili), "ad": ikili.name, "sha256": sha256_dosya(ikili),
                  "build_id": elf_build_id(ikili), "boyut": ikili.stat().st_size},
        "program": program,
        "decompile": {"deneme": len(kayitlar), "basarili": basarili,
                      "basarisiz": len(kayitlar) - basarili, "is_parcacigi": n_is,
                      "fonksiyon_zaman_asimi_s": FONKSIYON_ZAMAN_ASIMI_S,
                      "toplam_zaman_asimi_s": toplam_za},
        "sureler": sureler,
        "fonksiyonlar": kayitlar,
    }
    _yaz_json(cikti, belge)
    return belge


# ---------------------------------------------------------------------------
# Toplu koşu ve özet (JVM gerekmez)
# ---------------------------------------------------------------------------

def liste_oku(yol: Path) -> list[Path]:
    """Satır başına bir yol, JSON dizi ya da ``parametre_hizala.py secim`` çıktısı."""
    metin = yol.read_text(encoding="utf-8")
    if metin.lstrip().startswith("["):
        return [Path(os.path.expanduser(x)) for x in json.loads(metin)]
    if metin.lstrip().startswith("{"):
        return [Path(os.path.expanduser(x["ikili"])) for x in json.loads(metin)["ikililer"]]
    return [Path(os.path.expanduser(s.strip())) for s in metin.splitlines()
            if s.strip() and not s.lstrip().startswith("#")]


def cikti_adi(ikili: Path) -> str:
    return ikili.name + ".json"


def toplu(ikililer: list[Path], cikti: Path, *, zaman_asimi: int = TOPLU_ZAMAN_ASIMI_S,
          proje_kok: Optional[Path] = None) -> dict[str, Any]:
    """Her ikili ayrı süreçte (ayrı JVM; Karadul da ikili başına bir süreç). Var olan çıktı atlanır."""
    cikti.mkdir(parents=True, exist_ok=True)
    satirlar = []
    for ikili in ikililer:
        hedef = cikti / cikti_adi(ikili)
        satir: dict[str, Any] = {"ikili": str(ikili), "cikti": hedef.name}
        if hedef.is_file():
            satir["durum"] = "vardi"
        else:
            komut = [sys.executable, "-I", str(Path(__file__).resolve()), "cikar", str(ikili),
                     "-o", str(hedef)]
            if proje_kok is not None:
                komut += ["--proje-kok", str(proje_kok)]
            t0 = time.monotonic()
            gunluk = cikti / (ikili.name + ".log")
            with open(gunluk, "w", encoding="utf-8") as g:
                try:
                    rc = subprocess.run(komut, stdout=g, stderr=subprocess.STDOUT,
                                        timeout=zaman_asimi, check=False).returncode
                except subprocess.TimeoutExpired:
                    rc = 124
            satir.update(durum="tamam" if rc == 0 and hedef.is_file() else f"hata:{rc}",
                         sure_s=round(time.monotonic() - t0, 1), gunluk=gunluk.name)
        satirlar.append(satir)
        print(f"{ikili.name}: {satir['durum']}", flush=True)
    indeks = {"sema": GHIDRA_TOPLU_SEMA, "betik_sha256": sha256_dosya(Path(__file__).resolve()),
              "git_head": _git_head(), "ikililer": satirlar}
    _yaz_json(cikti / "toplu.json", indeks)
    return indeks


def depolama_turu(parametre: dict[str, Any]) -> str:
    """Bir parametrenin depolama özeti: yazmac | yigin | parcali | <özel> | <uzay>."""
    dep = parametre.get("depolama") or {}
    parcalar = dep.get("parcalar") or []
    if dep.get("ozel") and dep["ozel"] not in ("unique",):
        return dep["ozel"]
    if len(parcalar) > 1:
        return "parcali"
    if not parcalar:
        return dep.get("ozel") or "bos"
    return parcalar[0]["tur"]


def ozetle(belgeler: list[dict[str, Any]]) -> dict[str, Any]:
    satirlar = []
    for b in belgeler:
        sayac: Counter = Counter()
        dep_liste: Counter = Counter()
        dep_dec: Counter = Counter()
        imza: Counter = Counter()
        for f in b["fonksiyonlar"]:
            sayac["fonksiyon"] += 1
            sayac["thunk"] += f["thunk"]
            imza[f["imza_kaynagi"]] += 1
            sayac["liste_parametre"] += len(f["liste_parametreleri"])
            sayac["liste_parametreli_fonksiyon"] += bool(f["liste_parametreleri"])
            for p in f["liste_parametreleri"]:
                dep_liste[depolama_turu(p)] += 1
            d = f["decompile"]
            if d["basarili"]:
                sayac["decompile_basarili"] += 1
                sayac["decompile_parametre"] += len(d["parametreler"])
                sayac["degisken_arguman"] += d["degisken_arguman"]
                for p in d["parametreler"]:
                    dep_dec[depolama_turu(p)] += 1
        satirlar.append({"ikili": b["girdi"]["ad"], "image_base": b["program"]["image_base"],
                         **dict(sayac), "imza_kaynagi": dict(sorted(imza.items())),
                         "liste_depolama": dict(sorted(dep_liste.items())),
                         "decompile_depolama": dict(sorted(dep_dec.items())),
                         "sureler": b.get("sureler")})
    return {"dosyalar": satirlar}


def belgeleri_topla(girdiler: list[Path]) -> list[dict[str, Any]]:
    sonuc = []
    for g in girdiler:
        yollar = sorted(g.glob("*.json")) if g.is_dir() else [g]
        for y in yollar:
            b = json.loads(y.read_text(encoding="utf-8"))
            if b.get("sema") == SEMA:
                sonuc.append(b)
    return sonuc


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    c = sub.add_parser("cikar", help="bir ikiliyi Karadul ayarlarıyla analiz et, parametreleri yaz")
    c.add_argument("ikili", type=Path)
    c.add_argument("-o", "--out", type=Path, required=True)
    c.add_argument("--proje-kok", type=Path, default=None,
                   help="geçici Ghidra projesinin açılacağı dizin (iş bitince silinir)")
    c.add_argument("--is-parcacigi", type=int, default=None,
                   help="decompile iş parçacığı (varsayılan Karadul'un CPU_PERF_CORES'u)")
    t = sub.add_parser("toplu", help="liste dosyasındaki ikililer, her biri ayrı süreçte")
    t.add_argument("liste", type=Path)
    t.add_argument("-o", "--out", type=Path, required=True)
    t.add_argument("--zaman-asimi", type=int, default=TOPLU_ZAMAN_ASIMI_S)
    t.add_argument("--proje-kok", type=Path, default=None)
    o = sub.add_parser("ozet", help="fonksiyon, decompile ve depolama sayımları")
    o.add_argument("girdiler", nargs="+", type=Path)
    a = ap.parse_args(argv)
    if a.komut == "cikar":
        b = cikar(a.ikili, a.out, proje_kok=a.proje_kok, is_parcacigi=a.is_parcacigi)
        print(f"{a.out}: fonksiyon={b['decompile']['deneme']} "
              f"decompile={b['decompile']['basarili']} süreler={b['sureler']}")
        return 0
    if a.komut == "toplu":
        indeks = toplu(liste_oku(a.liste), a.out, zaman_asimi=a.zaman_asimi,
                       proje_kok=a.proje_kok)
        hata = [s for s in indeks["ikililer"] if not s["durum"] in ("tamam", "vardi")]
        return 1 if hata else 0
    for s in ozetle(belgeleri_topla(a.girdiler))["dosyalar"]:
        print(json.dumps(s, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
