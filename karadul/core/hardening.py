"""Motor koruma — çalışma-zamanı anti-tamper (Faz C, güvenli varyant).

Amaç
----
Paketlenmiş Black Widow.app'i tersine mühendislikle inceleyeni yavaşlat: hata
ayıklayıcı (debugger) / dinamik enstrümantasyon (frida) / kütüphane enjeksiyonu
tespit edilirse analizi SESSİZCE BOZMAK yerine NET bir mesajla REDDET.

Tasarım ilkeleri (Berke 2026-07-18 — "güvenli varyant, meşru kullanıcıyı bozma"):

1. **Yalnız paketlenmiş .app içinde aktif.** Geliştirme/repo (``.py``) veya test
   ortamında ``_is_hardened_context()`` False -> tüm kontroller İNERT. Berke
   karadul'u dev'de lldb ile debug ederken tetiklenmez.
2. **Fail-open.** Herhangi bir tespit KODU hata verirse (ctypes yok, sysctl
   değişti, sürüm farkı) -> "tehdit yok" varsayılır, analiz DEVAM eder. Yanlış
   pozitif meşru kullanıcıyı ASLA bloklamaz. (Fail-closed olsaydı bir ctypes
   sürprizi tüm kullanıcıları bloklardı.)
3. **Sessiz bozma YOK.** İşi doğruluk olan bir araç, "debug ediliyorum" sanınca
   sessizce yanlış sonuç ÜRETMEZ (yanlış pozitifte felaket). Tespit -> açık
   mesaj + ``os._exit`` ile temiz ret.
4. Bu modül ``--protect`` build'de ``.so``'ya derlenir + string'leri şifrelenir
   (``_ENCRYPT_PATHS``) -> RE'ci markerları (``frida``, mesaj) statikçe göremez,
   kontrolü ``.so`` makine kodundan bulup patch'lemesi gerekir.
"""
from __future__ import annotations

import os
import struct
import sys

__all__ = ["check_anti_tamper", "warmup_native_modules"]

_warmed = False


def warmup_native_modules() -> None:
    """Bundle'da TÜM karadul modüllerini ANA THREAD'de önceden import et.

    Neden (ölçülmüş SIGSEGV): pipeline'ın step-registry runner'ı bağımsız step'leri
    ``ThreadPoolExecutor`` ile PARALEL çalıştırır. Bir step ``run()`` içinde lazy
    import yapıp henüz-init-olmamış bir Nuitka ``.so`` modülünü İLK KEZ init ederse,
    Nuitka'nın init kodu (``makeCodeObject`` -> ``PyObject_GetAttrString``) worker
    thread'de (JVM/jpype aktifken) çöker -> tüm analizi öldürür. Geliştirmede
    (düz ``.py``) init crash'i YOK, o yüzden bu yalnız ``.so`` build'de görülür.

    Çözüm: modülleri ana thread'de önceden init et; worker'daki ``import`` artık
    ``sys.modules`` cache'inden döner (init yok) -> crash yok. Yalnız hardened
    (bundle) bağlamda koşar; dev/test'te gereksiz olduğundan atlanır. Best-effort:
    opsiyonel-dep / Ghidra-script modülleri import edilemez -> yutulur (onlar zaten
    worker'da da import edilmez)."""
    global _warmed
    if _warmed or not _is_hardened_context():
        return
    _warmed = True
    try:
        import importlib
        import pkgutil

        import karadul

        for m in pkgutil.walk_packages(karadul.__path__, "karadul."):
            try:
                importlib.import_module(m.name)
            except Exception:
                pass  # opsiyonel dep / ghidra jython script -> zararsız
    except Exception:
        pass  # warmup best-effort; başarısızlığı analizi bloklamasın

_P_TRACED = 0x00000800  # <sys/proc.h> — process is being traced


def _is_hardened_context() -> bool:
    """Yalnız paketlenmiş .app içinde True. Env DEĞİL (env unset ile bypass edilir);
    bundle yolu intrinsik -> kontrol .so'da, dışarıdan kapatılamaz."""
    marker = ".app/Contents/"
    return marker in (sys.prefix or "") or marker in (sys.executable or "")


def _extern_proc_p_flag_offset() -> int:
    """``struct kinfo_proc.kp_proc.p_flag`` byte offset'ini ctypes ile HESAPLA
    (hardcode etme -> mimari/hizalama farkında kaymaz). 64-bit'te 32 çıkar.

    ``struct extern_proc`` (<sys/proc.h>): union p_un (16) -> p_vmspace (8) ->
    p_sigacts (8) -> **p_flag** (offset 32). lldb altında P_TRACED (0x800) biti
    burada set olur (ölçüldü: normal 0x4004 -> lldb 0x5804)."""
    import ctypes

    class _ExternProc(ctypes.Structure):
        _fields_ = [
            ("p_un", ctypes.c_ubyte * 16),   # union {2 ptr | timeval} = 16 (64-bit)
            ("p_vmspace", ctypes.c_void_p),  # -> offset 16
            ("p_sigacts", ctypes.c_void_p),  # -> offset 24
            ("p_flag", ctypes.c_int),        # -> offset 32
        ]

    return _ExternProc.p_flag.offset


def _debugger_present() -> bool:
    """macOS: sysctl KERN_PROC ile mevcut sürecin P_TRACED bayrağını oku.
    Apple QA1361'in kanonik yöntemi. Diğer platformlarda False (kapsam dışı)."""
    if sys.platform != "darwin":
        return False
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    CTL_KERN, KERN_PROC, KERN_PROC_PID = 1, 14, 1
    mib = (ctypes.c_int * 4)(CTL_KERN, KERN_PROC, KERN_PROC_PID, os.getpid())
    # İki aşamalı sysctl: önce gereken boyutu al (buffer taşmasın), sonra doldur.
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 4, None, ctypes.byref(size), None, 0) != 0 or size.value == 0:
        return False
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 4, buf, ctypes.byref(size), None, 0) != 0:
        return False
    off = _extern_proc_p_flag_offset()
    if off + 4 > len(buf.raw):
        return False
    (p_flag,) = struct.unpack_from("i", buf.raw, off)
    return bool(p_flag & _P_TRACED)


def _frida_present() -> bool:
    """Dinamik enstrümantasyon (frida) / enjeksiyon izleri. Yüksek güvenilir,
    düşük yanlış-pozitif: frida kendi dylib'lerini sürece YÜKLER."""
    markers = ("frida", "gum-js", "gadget", "cynject", "linjector")
    # 1) DYLD enjeksiyon env'i frida işaret ediyor mu
    for k, v in os.environ.items():
        if k.startswith("DYLD_") and v:
            low = v.lower()
            if any(m in low for m in markers):
                return True
    # 2) yüklü dylib taraması (macOS): _dyld image listesi
    if sys.platform == "darwin":
        try:
            import ctypes

            libc = ctypes.CDLL(None)
            libc._dyld_get_image_name.restype = ctypes.c_char_p
            libc._dyld_image_count.restype = ctypes.c_uint32
            for i in range(libc._dyld_image_count()):
                raw = libc._dyld_get_image_name(i)
                if not raw:
                    continue
                low = raw.decode("utf-8", "ignore").lower()
                if any(m in low for m in markers):
                    return True
        except Exception:
            return False
    return False


def _refuse(threats: list[str]) -> None:
    banner = (
        "\n"
        "  ┌─────────────────────────────────────────────────────────────┐\n"
        "  │  Black Widow — çalışma-zamanı bütünlük kontrolü               │\n"
        "  │                                                               │\n"
        "  │  Bir analiz/enstrümantasyon ortamı tespit edildi:             │\n"
        "  │    {threats:<58} │\n"
        "  │                                                               │\n"
        "  │  Motoru bu koşulda çalıştırmayı reddediyorum. Bu araç         │\n"
        "  │  tersine mühendisliği KOLAYLAŞTIRIR; kendisinin sökülmesini   │\n"
        "  │  ise kolaylaştırmaz. İyi denemeydi.                           │\n"
        "  └─────────────────────────────────────────────────────────────┘\n"
    ).format(threats=", ".join(threats)[:58])
    try:
        sys.stderr.write(banner)
        sys.stderr.flush()
    except Exception:
        pass
    # os._exit: atexit/finally çalıştırmadan ANINDA çık (analiz akışına dönme yok).
    os._exit(3)


def check_anti_tamper() -> None:
    """Ana giriş. Bundle bağlamında değilse HİÇBİR ŞEY yapmaz (dev/test inert).
    Tespit -> net mesaj + ret. Tespit kodunun kendi hatası -> fail-open (devam)."""
    try:
        if not _is_hardened_context():
            return
        threats: list[str] = []
        if _debugger_present():
            threats.append("hata ayıklayıcı (debugger)")
        if _frida_present():
            threats.append("dinamik enstrümantasyon (frida)")
    except Exception:
        return  # fail-open: tespit hatası meşru kullanıcıyı bloklamasın
    if threats:
        _refuse(threats)
