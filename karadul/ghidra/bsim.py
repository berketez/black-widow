"""BSim fonksiyon benzerlik analiz modulu.

Ghidra'nin BSim altyapisini kullanarak fonksiyon hash'leri olusturur
ve cross-binary benzerlik sorgusu yapar. H2 file-based veritabani
kullanir, harici DB sunucusu gerektirmez.

Iki mod destekler:
  1. BSim native: Ghidra BSim API (ghidra.features.bsim) erisilebiliyorsa
     gercek feature vector hash'leri kullanir.
  2. BSim lite (fallback): API yoksa decompiled C kodu + opcode histogram
     uzerinden SHA256 hash'i hesaplayarak JSON-based basit benzerlik
     index'i tutar.

Depo (P16b, GHIDRA-01/02/03):
  - Depo dizini (``config.bsim.db_path`` ya da ``resolve_cache_root()/bsim``)
    birden cok surec tarafindan paylasilir. Ingest + sorgu oturumu dizin
    kilidini (``fcntl.flock``) alir; alamazsa sinirli sure bekler, sure
    dolarsa BSim ATLANIR ve bu durum sonuca yazilir. Kilit / mesgul H2
    yuzunden lite'a dusulmez. Oturum sonunda Ghidra'nin H2 baglanti havuzu
    kapatilir (``release``); kapatilmazsa H2 dosyasi surec bitene dek acik
    kalir ve kilit tek basina yetmez.
  - Her ingest edilen ikilinin kimligi (md5, sha256, ELF build-id / Mach-O
    LC_UUID) ``<db>.provenance.json`` kaynak kaydina yazilir. Sorguda
    kendisi, ayni dosya ve ayni yapi (ayni build-id / UUID: ornegin ayni
    ikilinin sembollu kopyasi) aday olamaz; kalan her aday kaynagini tasir.
  - Lite dizini kilit altinda, diskteki son halle birlestirilip gecici dosya
    + ``os.replace`` ile yazilir; okunamayan dizin ezilmez, yedege tasinir.

Kullanim:
    bsim = BSimDatabase(config)
    bsim.ingest_program(program, "my_db")
    result = bsim.query_all_functions(program, min_similarity=0.7, db_name="my_db")
    payload = result.to_payload()     # bsim_matches.json
    bsim.close()
"""

from __future__ import annotations

import datetime as _dt
import errno
import hashlib
import json
import logging
import os
import re
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

try:  # POSIX surec-arasi kilit; Windows'ta yok
    import fcntl
except ImportError:  # pragma: no cover - platforma bagli
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    pass  # Ghidra type'lari runtime'da import edilir

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Depo sabitleri (P16b)
# ---------------------------------------------------------------------------

# Dizin kilidi: depo dizinindeki BUTUN BSim dosyalarini (H2, lite dizini,
# kaynak kayitlari) korur. H2 dosya kipinde ayni anda tek surec acabilir;
# kilitsiz ikinci surec "Database already in use" alip eskiden sessizce
# lite'a dusuyordu (GHIDRA-01).
_LOCK_FILE_NAME = ".karadul_bsim.lock"
# Kilit icin en uzun bekleme (sn). BSimConfig'de alan yok (config.py baska
# paketin); ``bsim.lock_timeout_s`` sonradan eklenirse getattr ile okunur.
_LOCK_WAIT_S = 1800.0
_LOCK_POLL_S = 1.0
# Kilidi bilmeyen bir surec (eski surum, Ghidra arayuzu) H2'yi tutuyorsa
# yeniden deneme araligi (sn); toplam sure kilit bekleme suresinden duser.
_BUSY_RETRY_S = 5.0
# H2'nin "baska surec kullaniyor" iletisi (kucuk harfle aranir).
_H2_BUSY_MARKERS = ("already in use",)
_LITE_INDEX_NAME = "bsim_lite_index.json"
_PROVENANCE_SUFFIX = ".provenance.json"
_QUARANTINE_INFIX = ".bozuk-"
# Yeni JSON dosyalarının izni (eski write_text davranışı: 0644, umask 022).
_NEW_FILE_MODE = 0o644

# Kimlik okuma sinirlari (guvenilmeyen ikili; yalniz basliklar okunur).
_NOTE_READ_CAP = 1 << 20
_MACHO_CMDS_CAP = 16 << 20
_MAX_FAT_ARCHS = 64
_MAX_ELF_HEADERS = 4096
_ELF_MAGIC = b"\x7fELF"
_PT_NOTE = 4
_SHT_NOTE = 7
_NT_GNU_BUILD_ID = 3
_LC_UUID = 0x1B
_MACHO_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xfe\xed\xfa\xce": (">", 28),
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
    b"\xcf\xfa\xed\xfe": ("<", 32),
}
_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_FAT_MAGIC64 = b"\xca\xfe\xba\xbf"

# Sonuc durumlari (bsim_matches.json "bsim_status").
STATUS_OK = "ok"
STATUS_FALLBACK_LITE = "fallback_lite"
STATUS_SKIPPED_BUSY = "skipped_busy"
STATUS_FAILED = "failed"
STATUS_NOT_RUN = "not_run"
# ÖL-2: depoda bu programdan (ve aynı kimlikli kopyalarından) başka program yokken sorgu
# koşmaz (kendi kendine eşleşirdi ve dışlanırdı); ingest / sorgu bütçesi dolarsa kısmi.
STATUS_ATLANDI = "atlandi"
STATUS_KISMI = "kismi"
BOS_DEPO_NEDENI = "depoda başka program yok; sorgu kendi kendine eşleşirdi ve dışlanırdı"
# HZ-2: tarama yolu (``bsim_detail.scan_mode``; yalnız ``bsim.paralel_tarama`` açıkken yazılır).
SCAN_PARALLEL = "parallel"
SCAN_SERIAL_FALLBACK = "serial_fallback"

# Aday kaynagi (bsim_matches.json "matched_source").
SOURCE_RECORDED = "recorded"        # kaynak kaydi var (md5 + sha256 + build-id)
SOURCE_UNRECORDED = "unrecorded"    # eski kayit ya da kimligi okunamayan ikili

_HEX_RE = re.compile(r"^[0-9a-f]+$")

# ---------------------------------------------------------------------------
# BSim API kullanilabilirlik kontrolu (graceful degradation)
# ---------------------------------------------------------------------------
_BSIM_AVAILABLE: Optional[bool] = None


def _check_bsim() -> bool:
    """Ghidra BSim API'sinin erisilebilir olup olmadigini kontrol et.

    Sonuc cache'lenir — modül omru boyunca bir kez kontrol edilir.
    PyGhidra disinda calisiyorsak veya BSim modulleri yuklenmemisse
    False doner ve bsim_lite moduna dusulur.
    """
    global _BSIM_AVAILABLE
    if _BSIM_AVAILABLE is None:
        try:
            from ghidra.features.bsim.query import BSimServerInfo  # noqa: F401
            _BSIM_AVAILABLE = True
        except (ImportError, Exception):
            _BSIM_AVAILABLE = False
    return _BSIM_AVAILABLE


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------

@dataclass
class BSimMatch:
    """Tek bir fonksiyon eslesmesi."""
    query_function: str       # Sorgulanan fonksiyon adi
    query_address: str        # Sorgulanan fonksiyon adresi (hex)
    matched_function: str     # Eslesen fonksiyon adi
    matched_program: str      # Eslesen program/binary adi
    similarity: float         # Benzerlik skoru [0.0, 1.0]
    # KISIT: significance [0,1] DEGILDIR -- 0.0'dan baslar, UST SINIRI YOK
    # (olculdu: /bin/zsh'de 8.23..6262.77). Fonksiyon boyutuyla olceklenir.
    # Iki modun degerleri AYNI OLCEKTE DEGIL: native gercek BSim skoru
    # (sinirsiz), lite ise elle atanmis 0.5/0.8/1.0 sabitleri. Iki modun
    # significance'ini KARSILASTIRMA / esikleme.
    significance: float
    # Adayin kaynagi (GHIDRA-02): hangi ikiliden geldigi. Bos = bilinmiyor.
    matched_address: str = ""
    matched_exe_md5: str = ""
    matched_exe_sha256: str = ""
    matched_source: str = ""  # SOURCE_RECORDED | SOURCE_UNRECORDED | ""

    def to_dict(self) -> dict[str, Any]:
        """bsim_matches.json kaydi (eski bes alan + kaynak alanlari)."""
        return {
            "query_function": self.query_function,
            "query_address": self.query_address,
            "matched_function": self.matched_function,
            "matched_program": self.matched_program,
            "similarity": self.similarity,
            "matched_address": self.matched_address,
            "matched_exe_md5": self.matched_exe_md5,
            "matched_exe_sha256": self.matched_exe_sha256,
            "matched_source": self.matched_source,
        }


@dataclass
class BSimResult:
    """Toplu sorgu sonucu."""
    total_queries: int        # Sorgulanan fonksiyon sayisi
    total_matches: int        # Bulunan esleme sayisi
    matches: list[BSimMatch]  # Esleme listesi
    database_name: str        # Kullanilan veritabani adi
    query_duration: float     # Sorgu suresi (saniye)
    # Hangi kipte, hangi durumla uretildi (GHIDRA-01). Bos = bilinmiyor.
    mode: str = ""
    status: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """``bsim_matches.json`` icerigi: eski alanlar + kip, durum, kaynak.

        ``bsim_status`` ``ok`` disindaysa (yedek, atlandi, hata) eslesme
        sayisi "bulunamadi" degil "bu kipte / bu durumda" okunmalidir.
        """
        status = dict(self.status) if self.status else {}
        return {
            "total_matches": self.total_matches,
            "database": self.database_name,
            "total_queries": self.total_queries,
            "query_duration": self.query_duration,
            "bsim_mode": self.mode or status.get("mode") or None,
            "bsim_status": status.get("status") or None,
            "bsim_detail": status or None,
            "matches": [m.to_dict() for m in self.matches],
        }


# ---------------------------------------------------------------------------
# Ikili kimligi (GHIDRA-02): md5, sha256, build-id / LC_UUID
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExeIdentity:
    """Bir ikilinin depodaki kimligi.

    ``build_ids``: ELF ``NT_GNU_BUILD_ID`` (``elf:<hex>``) ve Mach-O
    ``LC_UUID`` (``macho:<hex>``; evrensel ikilide her dilim). ``strip``
    ikisini de korur: soyulmus ikili ile sembollu kopyasi ayni yapidir.
    """
    md5: str = ""
    sha256: str = ""
    build_ids: tuple[str, ...] = ()
    name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "md5": self.md5,
            "sha256": self.sha256,
            "build_ids": list(self.build_ids),
            "name": self.name,
        }


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _gnu_build_ids_in_notes(fh: Any, offset: int, size: int, align: int, e: str) -> list[str]:
    """Bir not bolgesindeki GNU build-id'leri."""
    if size <= 0 or offset < 0:
        return []
    fh.seek(offset)
    blob = fh.read(min(size, _NOTE_READ_CAP))
    pad = 8 if align == 8 else 4
    out: list[str] = []
    pos = 0
    while pos + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from(e + "III", blob, pos)
        if namesz > len(blob) or descsz > len(blob):
            break
        pos += 12
        name = blob[pos:pos + namesz]
        pos += _align(namesz, pad)
        desc = blob[pos:pos + descsz]
        pos += _align(descsz, pad)
        if pos > len(blob) + pad:
            break
        if ntype == _NT_GNU_BUILD_ID and name.rstrip(b"\0") == b"GNU" and desc:
            out.append("elf:" + desc.hex())
    return out


def _elf_build_ids(fh: Any) -> list[str]:
    fh.seek(0)
    ident = fh.read(16)
    cls, data = ident[4], ident[5]
    if cls not in (1, 2) or data not in (1, 2):
        return []
    e = "<" if data == 1 else ">"
    if cls == 2:
        (_t, _m, _v, _entry, phoff, shoff, _f, _eh, phentsize, phnum,
         shentsize, shnum, _shstr) = struct.unpack(e + "HHIQQQIHHHHHH", fh.read(48))
        ph_fmt, ph_len = e + "IIQQQQQQ", 56
        sh_fmt, sh_len = e + "IIQQQQIIQQ", 64
    else:
        (_t, _m, _v, _entry, phoff, shoff, _f, _eh, phentsize, phnum,
         shentsize, shnum, _shstr) = struct.unpack(e + "HHIIIIIHHHHHH", fh.read(36))
        ph_fmt, ph_len = e + "IIIIIIII", 32
        sh_fmt, sh_len = e + "IIIIIIIIII", 40
    ids: list[str] = []
    if phoff and phentsize >= ph_len:
        for i in range(min(phnum, _MAX_ELF_HEADERS)):
            fh.seek(phoff + i * phentsize)
            raw = fh.read(ph_len)
            if len(raw) < ph_len:
                break
            f = struct.unpack(ph_fmt, raw)
            if cls == 2:
                p_type, p_offset, p_filesz, p_align = f[0], f[2], f[5], f[7]
            else:
                p_type, p_offset, p_filesz, p_align = f[0], f[1], f[4], f[7]
            if p_type == _PT_NOTE:
                ids += _gnu_build_ids_in_notes(fh, p_offset, p_filesz, p_align, e)
    if not ids and shoff and shentsize >= sh_len:
        for i in range(min(shnum, _MAX_ELF_HEADERS)):
            fh.seek(shoff + i * shentsize)
            raw = fh.read(sh_len)
            if len(raw) < sh_len:
                break
            f = struct.unpack(sh_fmt, raw)
            sh_type, sh_offset, sh_size, sh_align = f[1], f[4], f[5], f[8]
            if sh_type == _SHT_NOTE:
                ids += _gnu_build_ids_in_notes(fh, sh_offset, sh_size, sh_align, e)
    return ids


def _macho_uuids(fh: Any, base: int) -> list[str]:
    fh.seek(base)
    magic = fh.read(4)
    spec = _MACHO_MAGICS.get(magic)
    if spec is None:
        return []
    e, hsize = spec
    fh.seek(base)
    hdr = fh.read(hsize)
    if len(hdr) < hsize:
        return []
    _mg, _cpu, _sub, _ft, ncmds, sizeofcmds, _fl = struct.unpack_from(e + "IiiIIII", hdr, 0)
    blob = fh.read(min(sizeofcmds, _MACHO_CMDS_CAP))
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(blob):
            break
        cmd, cmdsize = struct.unpack_from(e + "II", blob, pos)
        if cmdsize < 8:
            break
        if cmd == _LC_UUID and cmdsize >= 24 and pos + 24 <= len(blob):
            return ["macho:" + blob[pos + 8:pos + 24].hex()]
        pos += cmdsize
    return []


def _fat_uuids(fh: Any, is64: bool) -> list[str]:
    fh.seek(4)
    (narch,) = struct.unpack(">I", fh.read(4))
    if narch == 0 or narch > _MAX_FAT_ARCHS:  # Java .class da cafebabe ile baslar
        return []
    entries = []
    for _ in range(narch):
        if is64:
            raw = fh.read(32)
            if len(raw) < 32:
                break
            _c, _s, offset, _size, _a, _r = struct.unpack(">iiQQII", raw)
        else:
            raw = fh.read(20)
            if len(raw) < 20:
                break
            _c, _s, offset, _size, _a = struct.unpack(">iiIII", raw)
        entries.append(offset)
    ids: list[str] = []
    for offset in entries:
        ids += _macho_uuids(fh, offset)
    return ids


def read_build_ids(path: Any) -> tuple[str, ...]:
    """Dosyanin yapi kimlikleri (ELF build-id, Mach-O LC_UUID). Okunamazsa ``()``.

    Yalniz basliklar ve not / yukleme komutu bolgeleri okunur; boyutlar
    sinirlidir (guvenilmeyen girdi). PE icin bos doner (kimlik md5 + sha256).
    """
    if not path:
        return ()
    try:
        p = Path(str(path))
        if not p.is_file():
            return ()
        with open(p, "rb") as fh:
            head = fh.read(4)
            if head == _ELF_MAGIC:
                ids = _elf_build_ids(fh)
            elif head in _MACHO_MAGICS:
                ids = _macho_uuids(fh, 0)
            elif head in (_FAT_MAGIC, _FAT_MAGIC64):
                ids = _fat_uuids(fh, head == _FAT_MAGIC64)
            else:
                ids = []
    except (OSError, struct.error, ValueError, IndexError, OverflowError):
        return ()
    return tuple(dict.fromkeys(ids))


def _hex_or_empty(value: Any, length: int) -> str:
    """Ghidra'dan gelen ozet degerini dogrula (mock / bos degeri ele)."""
    if value is None:
        return ""
    try:
        s = str(value).strip().lower()
    except Exception:  # noqa: BLE001
        return ""
    return s if len(s) == length and _HEX_RE.match(s) else ""


def _call_str(fn: Callable[[], Any]) -> str:
    try:
        v = fn()
    except Exception:  # noqa: BLE001
        return ""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    # JPype java.lang.String; mock nesneleri metin degil
    if type(v).__module__.startswith("unittest"):
        return ""
    try:
        return str(v)
    except Exception:  # noqa: BLE001
        return ""


def program_identity(program: Any) -> ExeIdentity:
    """Ghidra programinin kimligi: Ghidra'nin md5 / sha256'si + dosyadan build-id."""
    md5 = _hex_or_empty(_call_str(lambda: program.getExecutableMD5()), 32)
    sha256 = _hex_or_empty(_call_str(lambda: program.getExecutableSHA256()), 64)
    name = _call_str(lambda: program.getName())
    path = _call_str(lambda: program.getExecutablePath())
    build_ids = read_build_ids(path) if path else ()
    return ExeIdentity(md5=md5, sha256=sha256, build_ids=build_ids, name=name)


# ---------------------------------------------------------------------------
# Kilit ve atomik yazim (GHIDRA-01, GHIDRA-03)
# ---------------------------------------------------------------------------

class _DirLock:
    """Depo dizini icin surecler arasi ozel kilit (``fcntl.flock``).

    Ayni iplikte yeniden girilebilir (oturum kilidi tutarken lite dizini /
    kaynak kaydi yazimi ayni kilidi yeniden ister). Farkli iplikler ve
    surecler birbirini bekler. Surec olurse isletim sistemi kilidi birakir.
    ``fcntl`` olmayan platformda kilit yoktur; ``mechanism`` bunu soyler.
    """

    _held: dict[tuple[str, int], list[Any]] = {}
    _guard = threading.Lock()

    def __init__(self, directory: Path) -> None:
        self.path = str(Path(directory) / _LOCK_FILE_NAME)
        self.waited_s = 0.0
        self.acquired = False
        self.mechanism = "flock" if fcntl is not None else "none"

    def _key(self) -> tuple[str, int]:
        return (self.path, threading.get_ident())

    def acquire(
        self,
        timeout_s: float,
        poll_s: float = _LOCK_POLL_S,
        on_wait: Optional[Callable[[], None]] = None,
    ) -> bool:
        if self.acquired:
            return True
        key = self._key()
        with _DirLock._guard:
            held = _DirLock._held.get(key)
            if held is not None:
                held[1] += 1
                self.acquired = True
                return True
        fd: Optional[int] = None
        start = time.monotonic()
        if fcntl is not None:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
            warned = False
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                        os.close(fd)
                        raise
                    waited = time.monotonic() - start
                    if waited >= timeout_s:
                        os.close(fd)
                        self.waited_s = waited
                        return False
                    if not warned and on_wait is not None:
                        on_wait()
                        warned = True
                    time.sleep(max(0.0, min(poll_s, timeout_s - waited)))
        self.waited_s = time.monotonic() - start
        with _DirLock._guard:
            _DirLock._held[key] = [fd, 1]
        self.acquired = True
        return True

    def release(self) -> None:
        if not self.acquired:
            return
        self.acquired = False
        key = self._key()
        with _DirLock._guard:
            held = _DirLock._held.get(key)
            if held is None:
                return
            held[1] -= 1
            if held[1] > 0:
                return
            del _DirLock._held[key]
        fd = held[0]
        if fd is not None and fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                logger.debug("BSim kilidi birakilamadi", exc_info=True)
            os.close(fd)


class _BSimBusy(RuntimeError):
    """Depo kilidi / H2 sure icinde alinamadi."""


def _is_busy_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _H2_BUSY_MARKERS)


def _atomic_write_json(path: Path, data: Any, indent: Optional[int] = 2) -> None:
    """Gecici dosyaya yaz + ``os.replace``: okuyan hicbir zaman yarim dosya gormez."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp 0600 açar; var olan dosyanın izinleri korunur (yoksa 0644).
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = _NEW_FILE_MODE
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json_dict(path: Path) -> tuple[Optional[dict[str, Any]], str]:
    """(veri, hata). Dosya yoksa (None, ""). Okunamazsa (None, neden); dosyaya dokunulmaz."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        return None, f"okunamadi: {exc}"
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"bozuk JSON: {exc}"
    if not isinstance(data, dict):
        return None, "bozuk JSON: kok sozluk degil"
    return data, ""


def _quarantine(path: Path) -> Optional[Path]:
    """Okunamayan dosyayi ezmeden yedege tasi (kilit altinda cagrilir)."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}{_QUARANTINE_INFIX}{stamp}-{os.getpid()}")
    try:
        os.replace(path, backup)
    except FileNotFoundError:
        return None
    logger.warning("BSim: okunamayan dosya ezilmedi, yedege tasindi: %s -> %s", path, backup)
    return backup


# ---------------------------------------------------------------------------
# Kaynak kaydi (GHIDRA-02)
# ---------------------------------------------------------------------------

class _ProvenanceStore:
    """``<db_path>/<db_name>.provenance.json``: md5 -> {ad, sha256, build_ids, ...}.

    Yerel dosyadir; ikili yolu YAZILMAZ (onceki vakalarin yollari baska
    vakanin raporuna tasinmasin). Yazim depo kilidi altinda yapilir.
    """

    def __init__(self, db_path: Path, db_name: str) -> None:
        self.path = Path(db_path) / f"{db_name}{_PROVENANCE_SUFFIX}"
        self.load_error = ""

    def load(self) -> dict[str, dict[str, Any]]:
        data, err = _read_json_dict(self.path)
        self.load_error = err
        if err:
            logger.warning("BSim kaynak kaydi okunamadi (%s): %s", self.path, err)
        exes = (data or {}).get("executables")
        return dict(exes) if isinstance(exes, dict) else {}

    def record(self, identity: ExeIdentity, mode: str,
               kismi: Optional[dict[str, int]] = None, tam: bool = False) -> None:
        """Kaydı yaz. HZ-2: ingest bütçeyle kesildiyse ``kismi`` (``{islenen, toplam}``)
        kayda işlenir; aynı md5 sonra TAM ingest edilirse (``tam``) işaret kalkar. Depoda zaten
        olan md5 (ingest atlandı) işarete dokunmaz: eksik fonksiyonlar hâlâ eksiktir."""
        if not identity.md5:
            return
        data, err = _read_json_dict(self.path)
        if err and self.path.exists():
            _quarantine(self.path)
        if data is None or not isinstance(data.get("executables"), dict):
            data = {"version": 1, "executables": {}}
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        rec = data["executables"].get(identity.md5) or {"first_seen": now}
        rec.update({
            "name": identity.name,
            "sha256": identity.sha256,
            "build_ids": list(identity.build_ids),
            "mode": mode,
            "last_seen": now,
        })
        if kismi:
            rec["kismi"] = {k: int(v) for k, v in kismi.items() if v is not None}
        elif tam:
            rec.pop("kismi", None)
        data["executables"][identity.md5] = rec
        _atomic_write_json(self.path, data)


class _Exclusion:
    """Sorgulanan ikilinin kendisini ve ayni yapisini aday disinda tutar."""

    def __init__(self, own: ExeIdentity, provenance: dict[str, dict[str, Any]]) -> None:
        self.own = own
        self.provenance = provenance
        self.counts: dict[str, int] = {"self": 0, "same_file": 0, "same_build": 0}
        self.unrecorded_candidates = 0

    def classify(self, md5: str, sha256: str = "", build_ids: Any = ()) -> str:
        """'' (aday olabilir) | 'self' | 'same_file' | 'same_build'."""
        rec = self.provenance.get(md5) if md5 else None
        sha = sha256 or (rec or {}).get("sha256") or ""
        bids = tuple(build_ids or ()) or tuple((rec or {}).get("build_ids") or ())
        if self.own.md5 and md5 and md5 == self.own.md5:
            return "self"
        if self.own.sha256 and sha and sha == self.own.sha256:
            return "same_file"
        if self.own.build_ids and bids and set(bids) & set(self.own.build_ids):
            return "same_build"
        return ""

    def extra_slots(self) -> int:
        """Dislanacak adaylar sonuc yuvasini yemesin: kendisi + ayni kimlikli kayitlar."""
        n = 1
        for md5 in self.provenance:
            if md5 != self.own.md5 and self.classify(md5):
                n += 1
        return n


# ---------------------------------------------------------------------------
# BSim Lite: fallback hash + JSON index
# ---------------------------------------------------------------------------

class _BSimLiteIndex:
    """BSim API yokken kullanilan basit benzerlik index'i.

    Her fonksiyon icin iki hash uretir:
      - structural_hash: Decompiled C kodunun normalize edilmis SHA256'si.
        Degisken isimleri, bosluklar ve yorumlar temizlendikten sonra
        hash'lenir.
      - opcode_hash: Instruction opcode histograminin SHA256'si.
        Benzer algoritmalar benzer opcode dagilimlarina sahip olur.

    Benzerlik hesabi:
      - Iki hash de eslesirse similarity = 1.0
      - Sadece structural eslesirse similarity = 0.85
      - Sadece opcode eslesirse similarity = 0.65
      - Hicbiri eslesmezse sorgu sonucuna dahil edilmez

    Programlar ikilinin md5'iyle anahtarlanir (bilinmiyorsa adiyla): ayni
    adli farkli ikililer (Debian htop / Mac htop) birbirini ezmez.
    Yazim (GHIDRA-03): yalniz bu surecin degistirdigi program kayitlari,
    depo kilidi altinda diskteki son hale islenir; gecici dosya + rename.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.index_file = self.db_path / _LITE_INDEX_NAME
        self.load_error = ""
        self.quarantined: Optional[Path] = None
        self._touched: set[tuple[str, str]] = set()
        self._created: set[str] = set()
        self._index: dict[str, Any] = self._load_index()

    def _load_index(self) -> dict[str, Any]:
        """Mevcut JSON index'i yukle (salt okur). Okunamazsa bos; dosya EZILMEZ."""
        data, err = _read_json_dict(self.index_file)
        self.load_error = err
        if err:
            logger.warning(
                "BSim lite index okunamadi (%s); dosya ezilmeyecek, ilk kayitta yedege tasinacak",
                err,
            )
        if data is None or not isinstance(data.get("databases"), dict):
            return {"version": 1, "databases": {}}
        return data

    @property
    def dirty(self) -> bool:
        return bool(self._touched or self._created)

    def _save_index(self, timeout_s: float = _LOCK_WAIT_S) -> None:
        """Degisiklikleri kilit altinda diskteki son hale isle (atomik)."""
        if not self.dirty:
            return
        lock = _DirLock(self.db_path)
        if not lock.acquire(timeout_s):
            raise _BSimBusy(f"BSim lite dizini kilidi {timeout_s:.0f} sn icinde alinamadi")
        try:
            disk, err = _read_json_dict(self.index_file)
            if err and self.index_file.exists():
                self.quarantined = _quarantine(self.index_file)
            if disk is None or not isinstance(disk.get("databases"), dict):
                disk = {"version": 1, "databases": {}}
            dbs = disk["databases"]
            mine = self._index["databases"]
            for name in sorted(self._created):
                if name in mine:
                    entry = dbs.setdefault(name, {"programs": {}})
                    entry.setdefault("created", mine[name].get("created", time.time()))
                    entry.setdefault("programs", {})
            for db_name, key in sorted(self._touched):
                prog = mine.get(db_name, {}).get("programs", {}).get(key)
                if prog is None:
                    continue
                entry = dbs.setdefault(db_name, {"programs": {}, "created": time.time()})
                entry.setdefault("programs", {})[key] = prog
            _atomic_write_json(self.index_file, disk)
            self._index = disk
            self._touched.clear()
            self._created.clear()
        finally:
            lock.release()

    def create_database(self, name: str) -> None:
        """Yeni bos veritabani girisi olustur."""
        if name not in self._index["databases"]:
            self._index["databases"][name] = {"programs": {}, "created": time.time()}
            self._created.add(name)
            self._save_index()

    def has_database(self, name: str) -> bool:
        return name in self._index["databases"]

    def list_databases(self) -> list[dict[str, Any]]:
        """Mevcut veritabanlarini listele."""
        result = []
        for db_name, db_data in self._index["databases"].items():
            program_count = len(db_data.get("programs", {}))
            total_functions = sum(
                len(prog.get("functions", {}))
                for prog in db_data.get("programs", {}).values()
            )
            result.append({
                "name": db_name,
                "program_count": program_count,
                "function_count": total_functions,
                "created": db_data.get("created", 0),
                "mode": "bsim_lite",
            })
        return result

    @staticmethod
    def _normalize_code(code: str) -> str:
        """Decompiled C kodunu normalize et.

        Degisken isimlerini (local_X, param_X, FUN_XXX, DAT_XXX),
        bosluklari, yorumlari ve satir numaralarini temizleyerek
        yapisi ayni ama isimleri farkli fonksiyonlarin eslesebilmesini saglar.
        """
        # Yorum temizle
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # Ghidra otomatik isimleri normalize et
        code = re.sub(r'\blocal_[0-9a-fA-F]+\b', 'LOCAL', code)
        code = re.sub(r'\bparam_\d+\b', 'PARAM', code)
        code = re.sub(r'\bFUN_[0-9a-fA-F]+\b', 'FUNC', code)
        code = re.sub(r'\bDAT_[0-9a-fA-F]+\b', 'DATA', code)
        code = re.sub(r'\buVar\d+\b', 'VAR', code)
        code = re.sub(r'\biVar\d+\b', 'VAR', code)
        code = re.sub(r'\blVar\d+\b', 'VAR', code)
        code = re.sub(r'\bsVar\d+\b', 'VAR', code)
        code = re.sub(r'\bcVar\d+\b', 'VAR', code)
        code = re.sub(r'\bpuVar\d+\b', 'VAR', code)
        # Hex sabitleri normalize et
        code = re.sub(r'0x[0-9a-fA-F]+', 'HEX', code)
        # Bosluk normalize et
        code = re.sub(r'\s+', ' ', code).strip()
        return code

    @staticmethod
    def _compute_structural_hash(code: str) -> str:
        """Normalize edilmis C kodundan yapisal hash uret."""
        normalized = _BSimLiteIndex._normalize_code(code)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_opcode_hash(instructions: list[dict[str, Any]]) -> str:
        """Instruction listesinden opcode histogram hash'i uret.

        Her instruction'in mnemonic'ini sayar, siralayip hash'ler.
        Benzer algoritmalar benzer opcode dagilimi gosterir.
        """
        histogram: dict[str, int] = {}
        for instr in instructions:
            mnemonic = instr.get("mnemonic", instr.get("op", "UNK"))
            histogram[mnemonic] = histogram.get(mnemonic, 0) + 1
        # Siralanmis histogram string'i
        hist_str = "|".join(f"{k}:{v}" for k, v in sorted(histogram.items()))
        return hashlib.sha256(hist_str.encode("utf-8")).hexdigest()

    def ingest_function(
        self,
        db_name: str,
        program_name: str,
        func_name: str,
        func_address: str,
        decompiled_code: str = "",
        instructions: Optional[list[dict[str, Any]]] = None,
        identity: Optional[ExeIdentity] = None,
    ) -> dict[str, Any]:
        """Tek bir fonksiyonu veritabanina ekle (bellekte; ``save`` diske yazar)."""
        if db_name not in self._index["databases"]:
            self.create_database(db_name)

        db = self._index["databases"][db_name]
        key = identity.md5 if identity is not None and identity.md5 else program_name
        prog = db["programs"].setdefault(key, {"functions": {}})
        prog.setdefault("functions", {})
        prog["name"] = program_name
        if identity is not None and identity.md5:
            prog["md5"] = identity.md5
            prog["sha256"] = identity.sha256
            prog["build_ids"] = list(identity.build_ids)

        entry: dict[str, Any] = {
            "name": func_name,
            "address": func_address,
        }
        if decompiled_code:
            entry["structural_hash"] = self._compute_structural_hash(decompiled_code)
        if instructions:
            entry["opcode_hash"] = self._compute_opcode_hash(instructions)

        prog["functions"][func_address] = entry
        self._touched.add((db_name, key))
        return entry

    def save(self, timeout_s: float = _LOCK_WAIT_S) -> None:
        """Degisiklikleri diske yaz (degisiklik yoksa dosyaya dokunmaz)."""
        self._save_index(timeout_s)

    def build_lookup(self, db_name: str) -> dict[str, dict[str, list[tuple[str, str]]]]:
        """Hash -> [(program anahtari, adres)]: toplu sorguda dizini bir kez tara."""
        lookup: dict[str, dict[str, list[tuple[str, str]]]] = {"s": {}, "o": {}}
        db = self._index["databases"].get(db_name)
        if not db:
            return lookup
        for key, prog in db.get("programs", {}).items():
            for addr, fe in prog.get("functions", {}).items():
                sh = fe.get("structural_hash")
                oh = fe.get("opcode_hash")
                if sh:
                    lookup["s"].setdefault(sh, []).append((key, addr))
                if oh:
                    lookup["o"].setdefault(oh, []).append((key, addr))
        return lookup

    def query_function(
        self,
        db_name: str,
        func_address: str,
        structural_hash: str = "",
        opcode_hash: str = "",
        exclude_program: str = "",
        min_similarity: float = 0.7,
        max_results: int = 5,
        *,
        query_name: str = "",
        exclusion: Optional[_Exclusion] = None,
        lookup: Optional[dict[str, dict[str, list[tuple[str, str]]]]] = None,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin benzer fonksiyonlari ara.

        ``exclusion`` verilip sorgulanan ikilinin md5'i biliniyorsa dislama
        kimlikten yapilir (kendisi, ayni dosya, ayni build-id); bilinmiyorsa
        eski davranis: ``exclude_program`` adini tasiyan program dislanir.
        """
        if db_name not in self._index["databases"]:
            return []

        programs = self._index["databases"][db_name].get("programs", {})
        by_identity = exclusion is not None and bool(exclusion.own.md5)

        if lookup is not None:
            pairs = set(lookup["s"].get(structural_hash, ())) if structural_hash else set()
            if opcode_hash:
                pairs |= set(lookup["o"].get(opcode_hash, ()))
            candidates = sorted(pairs)
        else:
            candidates = [
                (key, addr)
                for key, prog in programs.items()
                for addr in prog.get("functions", {})
            ]

        matches: list[BSimMatch] = []
        excluded_reason: dict[str, str] = {}
        for key, addr in candidates:
            prog = programs.get(key) or {}
            func_entry = prog.get("functions", {}).get(addr)
            if func_entry is None:
                continue
            prog_name = str(prog.get("name") or key)
            md5 = str(prog.get("md5") or "")
            if by_identity:
                if key not in excluded_reason:
                    excluded_reason[key] = exclusion.classify(  # type: ignore[union-attr]
                        md5, str(prog.get("sha256") or ""), prog.get("build_ids") or (),
                    )
                reason = excluded_reason[key]
            else:
                reason = "self" if (exclude_program and prog_name == exclude_program) else ""

            entry_struct = func_entry.get("structural_hash", "")
            entry_opcode = func_entry.get("opcode_hash", "")
            struct_match = bool(structural_hash and entry_struct and structural_hash == entry_struct)
            opcode_match = bool(opcode_hash and entry_opcode and opcode_hash == entry_opcode)

            if struct_match and opcode_match:
                sim, sig = 1.0, 1.0
            elif struct_match:
                sim, sig = 0.85, 0.8
            elif opcode_match:
                sim, sig = 0.65, 0.5
            else:
                continue
            if sim < min_similarity:
                continue
            if reason:
                if exclusion is not None:
                    exclusion.counts[reason] = exclusion.counts.get(reason, 0) + 1
                continue

            matches.append(BSimMatch(
                query_function=query_name or func_address,
                query_address=func_address,
                matched_function=func_entry.get("name", addr),
                matched_program=prog_name,
                similarity=sim,
                significance=sig,
                matched_address=str(addr),
                matched_exe_md5=md5,
                matched_exe_sha256=str(prog.get("sha256") or ""),
                matched_source=SOURCE_RECORDED if md5 else SOURCE_UNRECORDED,
            ))

        # Benzerlige gore sirala (esitlikte belirlenimci), max_results kadar dondur
        matches.sort(key=lambda m: (
            -m.similarity, -m.significance, m.matched_program,
            m.matched_exe_md5, m.matched_address, m.matched_function,
        ))
        out = matches[:max_results]
        if exclusion is not None:
            exclusion.unrecorded_candidates += sum(
                1 for m in out if m.matched_source == SOURCE_UNRECORDED
            )
        return out


# ---------------------------------------------------------------------------
# BSim Native: Ghidra BSim API wrapper
# ---------------------------------------------------------------------------

# Ghidra 12.1.2 BSim ayar sablonu. Ghidra/Features/BSim/data/ altindaki
# medium_*.xml dosyalarindan biri olmali; isim degil DOSYA ADI (uzantisiz)
# beklenir. "nosize" varyanti fonksiyon boyutunu feature'a katmaz -> ayni
# algoritmanin farkli optimizasyon seviyelerindeki halleri eslesebilir.
_BSIM_CONFIG_TEMPLATE = "medium_nosize"

# significance ESIGI -- DIKKAT, OLCEK SEZGISEL DEGIL.
#
# Ghidra javadoc'u (SimilarityNote.getSignificance): deger 0.0'dan baslar ve
# UST SINIRI YOKTUR. similarity [0,1] arasidir, significance DEGILDIR.
# Kucuk fonksiyonlar dusuk significance alir cunku cok sayida kucuk fonksiyonun
# tesaduefen benzer vektor uretme ihtimali yuksektir. Filtrenin amaci bu
# tesadueffi eslesmeleri elemektir.
#
# OLCUM (2026-07-16, /bin/zsh, 1073 fonksiyon, self-match significance):
#   min/maks        : 8.23 / 6262.77
#   <32 byte fonks. : en fazla 45.06
#   esik 0.5        -> 1073/1073 kalir  (yani 0.5 HICBIR SEY elemez!)
#   esik 20.0       ->  883/1073 kalir
#   esik 40.0       ->  657/1073 kalir
#
# Bu yuzden varsayilan Ghidra'nin kendi degeri olan 0.0'da BIRAKILDI: uydurma
# bir sayi koymaktansa Ghidra ile ayni davranmak durust. Anlamli bir esik
# secmek icin cross-binary ground-truth (precision/recall) deneyi gerekir --
# yukaridaki olcum SELF-match'tir, yani her fonksiyonun alabilecegi EN YUKSEK
# significance'tir; cop eslesmelerin dagilimini GOSTERMEZ.
# Cagiran taraf query_similar(significance_threshold=...) ile yukseltebilir.
_DEFAULT_SIGNIFICANCE_THRESHOLD = 0.0


# ---------------------------------------------------------------------------
# HZ-2: paralel tarama (GenSignatures.scanFunctions) yardımcıları
# ---------------------------------------------------------------------------
# Ghidra 12.1.2 (javap + BSim-src.zip / Generic-src.zip, yerel kurulum; HZ2.md kalem 1):
#   GenSignatures.scanFunctions(java.util.Iterator<Function>, int, TaskMonitor)
#       throws DecompileException
#   -> ParallelDecompileTask(program, monitor, SignatureTask).decompile(iter, n)
#   -> DecompilerConcurrentQ (AutoAnalysisManager'ın ortak çözümleme havuzu); her iş bittiğinde
#      izleyiciye ``setProgress(tamamlanan_ya_da_iptal_edilen)``; izleyici iptal edilince
#      (``addCancelledListener``) bekleyen işler kuyruktan atılır, koşanlar kesilir; iptal
#      edilen iş yöneticiye yazılmaz (``SignatureTask.decompile`` iptali iki kez denetler).
#   -> imzalar ``writeToManager`` (synchronized) ile TEK DescriptionManager'a yazılır
#      (TreeSet: içerik ve sıra tarama sırasından bağımsız).
#   TimeoutTaskMonitor.timeoutIn(long, TimeUnit, TaskMonitor): süre dolunca temsilcinin
#   ``cancel()``'ı; ``getProgress()`` temsilciye gider. TaskMonitorAdapter ilerlemeyi
#   SAKLAMAZ; ilerlemeyi saklayan ve iptal dinleyicisi kabul eden tek sınıf paket-içi
#   ``ghidra.util.task.BasicTaskMonitor`` (Docking.jar; GTaskMonitor ``addCancelledListener``'da
#   UnsupportedOperationException atar, ConcurrentQ onu kullanamaz).


def _kalan_butce_sn(denetci: Any) -> Optional[float]:
    """Adım denetçisinin bütçesinden kalan süre (sn); bütçe yoksa None (ÖL-2 sözleşmesi)."""
    if denetci is None:
        return None
    son_an = getattr(denetci, "_son_an", None)
    if son_an is None:
        return None
    return float(son_an) - time.monotonic()


def _butce_doldu(denetci: Any, islenen: int, toplam: Optional[int]) -> None:
    """Denetçiye kesildiği andaki GERÇEK sayaçları yaz (``_AdimDenetcisi.denetle`` gibi)."""
    if denetci is None:
        return
    denetci.doldu = True
    denetci.islenen = int(islenen)
    denetci.toplam = toplam


def _java_iterator(funcs: list[Any]) -> Any:
    """``funcs`` ile aynı küme ve sırada ``java.util.Iterator`` (JVM yoksa Python yineleyicisi)."""
    try:
        import jpype

        if jpype.isJVMStarted():
            liste = jpype.JClass("java.util.ArrayList")(len(funcs))
            for func in funcs:
                liste.add(func)
            return liste.iterator()
    except ImportError:
        pass
    return iter(funcs)


def _jvm_ayril() -> None:
    """Okuyucu iş parçacığı JVM'e bağlandıysa ayır (JPype kendiliğinden ayırmaz)."""
    try:
        import jpype

        if jpype.isJVMStarted() and jpype.isThreadAttachedToJVM():
            jpype.JClass("java.lang.Thread").detach()
    except Exception:  # noqa: BLE001
        logger.debug("BSim okuyucu iş parçacığı JVM'den ayrılamadı", exc_info=True)


def _imzali_fonksiyon_sayisi(manager: Any) -> int:
    """Yöneticide imzası (``SignatureRecord``) olan fonksiyon sayısı: depoya giren gerçek iş."""
    # JPype Java yineleyicisi Python'da yinelenebilir (ingest'in sortCallgraph döngüsü gibi).
    return sum(1 for fdesc in manager.listAllFunctions() if fdesc.getSignatureRecord() is not None)


class _TaramaIzleyicisi:
    """HZ-2: paralel taramada izleyicinin GERÇEK ilerleme sayacını aralıkla okuyan iş parçacığı.

    Tarama Java iş parçacıklarında koşar; Python döngüsü yoktur. Okuyucu her
    ``denetci.aralik_sn``'de izleyicinin ``getProgress()``'ini (ConcurrentQ'nun tamamlanan iş
    sayısı) okur ve ÖL-2'nin denetim noktasına verir (``denetci.denetle``): olay oradan
    ``durum=suruyor islenen=… toplam=…`` diye çıkar; bütçe dolduysa izleyici iptal edilir
    (zaman aşımı izleyicisi de aynı anda keser). Sayaç okunamıyorsa (sayaçlı izleyici
    kurulamadı, okuma düştü ya da negatif) olay ÜRETİLMEZ, sayılır.
    """

    def __init__(self, monitor: Any, denetci: Any, toplam: int, sayac_okunur: bool) -> None:
        self.monitor = monitor
        self.denetci = denetci
        self.toplam = int(toplam)
        self.sayac_okunur = bool(sayac_okunur)
        self.okuma = 0
        self.okunamayan = 0
        self.son_hata = ""
        self._aralik = 0.0
        if denetci is not None:
            try:
                self._aralik = max(0.0, float(getattr(denetci, "aralik_sn", 0) or 0))
            except (TypeError, ValueError):
                self._aralik = 0.0
        self._dur = threading.Event()
        self._is: Optional[threading.Thread] = None

    def oku(self) -> bool:
        """Tek okuma; bütçe dolduysa ``True`` (okuyucu durur)."""
        try:
            n = int(self.monitor.getProgress())
        except Exception as exc:  # noqa: BLE001
            self.okunamayan += 1
            self.son_hata = "%s: %s" % (type(exc).__name__, exc)
            return False
        if n < 0:  # TaskMonitor.NO_PROGRESS_VALUE: sayaç yok
            self.okunamayan += 1
            self.son_hata = "izleyici sayaç vermiyor (%d)" % n
            return False
        self.okuma += 1
        if self.denetci.denetle(min(n, self.toplam), self.toplam):
            self.monitor.cancel()
            return True
        return False

    def _dongu(self) -> None:
        try:
            while not self._dur.wait(self._aralik):
                if self.oku():
                    break
        finally:
            _jvm_ayril()

    def baslat(self) -> bool:
        """Okuyucuyu başlat; sayaç yok, denetçi yok ya da olay aralığı 0 ise başlamaz."""
        if self.denetci is None or not self.sayac_okunur or self._aralik <= 0:
            return False
        self._is = threading.Thread(target=self._dongu, name="karadul-bsim-tarama-okuyucu",
                                    daemon=True)
        self._is.start()
        return True

    def durdur(self) -> None:
        self._dur.set()
        if self._is is not None:
            self._is.join(self._aralik + 1.0)


class _BSimNativeWrapper:
    """Ghidra BSim API'si uzerinde wrapper.

    PyGhidra icinden calistiginda Ghidra'nin gercek BSim feature
    vector engine'ini kullanir. H2 file-based veritabani ile calısır.

    NOT: Bu sinif sadece PyGhidra JVM icinde import edilebilir.
    Dogrudan Python'dan calistirilirsa ImportError verir.

    KISIT (Ghidra 12.1.2, javap ile dogrulandi): `FunctionDatabase` bir
    INTERFACE'tir ve `openDatabase(...)` diye bir static metodu YOKTUR.
    Istemci `BSimClientFactory.buildClient(BSimServerInfo, boolean)` ile
    kurulur. Ayni sekilde `GenSignatures`'ta `setProgram`/`openDatabase`/
    `flush` YOKTUR; dogrusu `openProgram(...)` + `scanFunction(...)` +
    `getDescriptionManager()`, ve yazma `InsertRequest.execute(db)` ile olur.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._database = None
        self.last_ingest_already = False
        # ÖL-2: köprünün adım denetçisi (``headless._AdimDenetcisi``; None = bütçe / olay yok);
        # bütçe dolunca son çağrının sayaçları (``islenen``, ``toplam``), dolmadıysa None.
        self.denetci: Any = None
        self.last_ingest_kismi: Optional[dict[str, int]] = None
        self.last_query_kismi: Optional[dict[str, int]] = None
        # HZ-2: ``BSimDatabase`` ``bsim.paralel_tarama``'yı öznitelikle verir (False = bugünkü
        # tekli yol). Son taramanın yolu (``parallel`` / ``serial_fallback``; tekli yolda None),
        # düşüşün nedeni ve sayaç okunamadıysa nedeni.
        self.paralel_tarama = False
        self.last_scan_mode: Optional[str] = None
        self.last_scan_hatasi = ""
        self.last_scan_sayac = ""
        # HZ-2: bu oturumda TAM ingest edilen programın yöneticisi (sorgu yeniden taramasın):
        # (program, fonksiyon sayısı, DescriptionManager).
        self._ingest_yoneticisi: Optional[tuple[Any, int, Any]] = None

    # -- HZ-2: paralel tarama -------------------------------------------

    def _izleyici_olustur(self, kalan_sn: Optional[float]) -> tuple[Any, str]:
        """Sayaçlı, iptal edilebilir izleyici (+ bütçe varsa ``TimeoutTaskMonitor``).

        Returns:
            (izleyici, sayaç okunamıyorsa nedeni; okunuyorsa "").
        """
        import math

        import jpype
        from java.util.concurrent import TimeUnit
        from ghidra.util.task import TaskMonitor, TaskMonitorAdapter, TimeoutTaskMonitor

        neden = ""
        try:
            yukleyici = TaskMonitorAdapter.class_.getClassLoader()
            sinif = jpype.JClass("java.lang.Class").forName(
                "ghidra.util.task.BasicTaskMonitor", True, yukleyici)
            kurucu = sinif.getDeclaredConstructor()
            kurucu.setAccessible(True)
            temsilci = jpype.JObject(kurucu.newInstance(), TaskMonitor)
        except Exception as exc:  # noqa: BLE001
            temsilci = TaskMonitorAdapter(True)
            neden = "sayaçlı izleyici kurulamadı (%s: %s)" % (type(exc).__name__, exc)
        if kalan_sn is None:
            return temsilci, neden
        ms = max(1, int(math.ceil(kalan_sn * 1000.0)))
        return TimeoutTaskMonitor.timeoutIn(ms, TimeUnit.MILLISECONDS, temsilci), neden

    def _paralel_tara(self, gen: Any, funcs: list[Any], denetci: Any,
                      kalan_sn: Optional[float]) -> bool:
        """``gen.scanFunctions`` ile paralel tarama; bütçe izleyicide. İptal edildiyse ``True``.

        İptal dışındaki istisna yukarı atılır (çağıran tekli yola düşer).
        """
        monitor, neden = self._izleyici_olustur(kalan_sn)
        self.last_scan_sayac = neden
        if neden:
            logger.warning("BSim paralel tarama: ilerleme sayacı okunamadı (%s); "
                           "adım içi olay üretilmeyecek", neden)
        okuyucu = _TaramaIzleyicisi(monitor, denetci, len(funcs), not neden)
        okuyucu.baslat()
        hata: Optional[BaseException] = None
        try:
            gen.scanFunctions(_java_iterator(funcs), len(funcs), monitor)
        except Exception as exc:  # noqa: BLE001
            hata = exc
        finally:
            okuyucu.durdur()
        iptal = bool(monitor.isCancelled())
        if not iptal and hasattr(monitor, "didTimeout"):
            # Bitmiş taramanın zaman aşımı sayacını bırak (sonradan boşa tetiklenmesin).
            try:
                monitor.cancel()
            except Exception:  # noqa: BLE001
                logger.debug("BSim izleyici zamanlayıcısı bırakılamadı", exc_info=True)
        if okuyucu.okunamayan and not self.last_scan_sayac:
            self.last_scan_sayac = "sayaç %d okumada okunamadı (%s)" % (
                okuyucu.okunamayan, okuyucu.son_hata)
        if hata is not None and not iptal:
            raise hata
        return iptal

    def _tara(self, gen: Any, database: Any, program: Any, funcs: list[Any],
              denetci: Any) -> tuple[Optional[int], Any]:
        """HZ-2: ``funcs``'u paralel tara. Döner: (taranan, gen).

        ``taranan`` None → paralel tarama istisna attı; yeni bir ``gen`` ile TEKLİ yol
        koşulmalı (``last_scan_mode = serial_fallback``, düşüş günlükte ve durumda). Bütçe
        taramadan önce ya da tarama içinde dolarsa ``taranan`` imzası yöneticiye giren
        fonksiyon sayısıdır (gerçek; denetçiye de o yazılır).
        """
        self.last_scan_mode = SCAN_PARALLEL
        kalan = _kalan_butce_sn(denetci)
        if kalan is not None and kalan <= 0:
            _butce_doldu(denetci, 0, len(funcs))
            return 0, gen
        try:
            iptal = self._paralel_tara(gen, funcs, denetci, kalan)
        except Exception as exc:  # noqa: BLE001
            self.last_scan_mode = SCAN_SERIAL_FALLBACK
            self.last_scan_hatasi = "%s: %s" % (type(exc).__name__, exc)
            logger.warning("BSim paralel tarama basarisiz, tekli taramaya dusuluyor: %s", exc)
            try:
                gen.dispose()
            except Exception:  # noqa: BLE001
                logger.debug("GenSignatures dispose basarisiz", exc_info=True)
            return None, self._gen_signatures(database, program)
        if iptal:
            taranan = _imzali_fonksiyon_sayisi(gen.getDescriptionManager())
            _butce_doldu(denetci, taranan, len(funcs))
            return taranan, gen
        return len(funcs), gen

    def hazir_yonetici(self, program: Any, funcs: list[Any]) -> Any:
        """Bu oturumda aynı program TAM ingest edildiyse onun yöneticisi (yoksa None)."""
        kayit = getattr(self, "_ingest_yoneticisi", None)
        if kayit is None:
            return None
        prog, toplam, manager = kayit
        if prog is not program or toplam != len(funcs):
            return None
        return manager

    # -- yardimcilar --------------------------------------------------

    def _server_info(self, name: str) -> Any:
        """H2 dosya-tabanli BSimServerInfo uret.

        KISIT: tek-String ctor DBType.file secer ve cleanupFilename() ile
        yolu dogrular. Yol MUTLAK olmali ("/" ile baslamali), "/" ile
        BITMEMELI ve "file:" prefix'i ICERMEMELI -> aksi halde
        "Invalid absolute file path". ".mv.db" uzantisini Ghidra KENDI
        ekler, biz eklemiyoruz (iki kez eklenmesin).
        """
        from ghidra.features.bsim.query import BSimServerInfo

        return BSimServerInfo((self.db_path / name).resolve().as_posix())

    def _last_error(self, database: Any) -> str:
        """FunctionDatabase.getLastError()'dan okunabilir mesaj cikar."""
        try:
            err = database.getLastError()
            if err is not None:
                return str(err.message)
        except Exception:  # noqa: BLE001
            pass
        return "bilinmeyen BSim hatasi"

    def _build_client(self, name: str, initialize: bool = True) -> Any:
        """BSimClientFactory ile istemci kur (openDatabase DEGIL).

        initialize=False sadece CreateDatabase icin: DB dosyasi henuz yokken
        initialize() basarisiz olur, once CreateDatabase.execute() calismali.
        """
        from ghidra.features.bsim.query import BSimClientFactory

        # async=False -> sorgular cagiran thread'de calisir. PyGhidra tek
        # JVM thread'inde ilerledigi icin async kuyruk gereksiz.
        database = BSimClientFactory.buildClient(self._server_info(name), False)
        if initialize and not database.initialize():
            msg = self._last_error(database)
            try:
                database.close()
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f"BSim DB initialize basarisiz ({name}): {msg}")
        return database

    def release(self, name: str) -> bool:
        """Bu JVM'deki H2 baglanti havuzunu kapat: H2 dosyasi baska surece acilsin.

        KISIT (Ghidra 12.1.2, ``BSimH2FileDBConnectionManager``, BSim-src.zip):
        ``FunctionDatabase.close()`` baglantiyi havuza geri verir; havuz
        (commons-dbcp2 ``BasicDataSource``) acik kaldikca H2 dosyasi bu surecte
        acik kalir ve baska surec "Database already in use" alir -- surec
        bitene kadar. Havuz yalniz ``BSimH2FileDataSource.dispose()`` ile (ya
        da JVM kapanirken) kapanir. Eski kodda paralel kosudaki dususun koku bu.
        """
        try:
            from ghidra.features.bsim.query.file import BSimH2FileDBConnectionManager
        except Exception:  # noqa: BLE001
            return False
        target = os.path.realpath(str(self.db_path / name))
        released = False
        for ds in list(BSimH2FileDBConnectionManager.getAllDataSources()):
            try:
                db_file = str(ds.getServerInfo().getDBName())
            except Exception:  # noqa: BLE001
                continue
            if db_file.endswith(".mv.db"):
                db_file = db_file[: -len(".mv.db")]
            if os.path.realpath(db_file) != target:
                continue
            try:
                ds.dispose()
                released = True
            except Exception:  # noqa: BLE001
                logger.warning("BSim H2 havuzu kapatilamadi: %s", db_file, exc_info=True)
        return released

    def open_client(self, name: str) -> Any:
        """Oturum boyunca acik kalacak istemci (DB yoksa once olusturulur).

        TUZAK: headless.py (asil app yolu) create_database'i HIC cagirmaz.
        DB dosyasi yoksa initialize() basarisiz olur; bu yuzden eksikse burada
        olusturuyoruz (idempotent).
        """
        if not (self.db_path / f"{name}.mv.db").exists():
            logger.info("BSim DB yok, olusturuluyor: %s", name)
            self.create_database(name)
        return self._build_client(name)

    def _gen_signatures(self, database: Any, program: Any) -> Any:
        """Program icin GenSignatures kur.

        KISIT: setVectorFactory() DB'nin LSHVectorFactory'si ile cagrilmali,
        yoksa uretilen vektorler DB'nin ayarlariyla uyusmaz ve insert/query
        "settings" hatasi verir.
        """
        from ghidra.features.bsim.query import GenSignatures

        gen = GenSignatures(True)
        gen.setVectorFactory(database.getLSHVectorFactory())
        # Kanonik cagri (SimilarFunctionQueryService ile birebir ayni):
        # openProgram(prog, nmover, archover, compover, repo, path)
        # nmover/archover/compover None -> Ghidra degerleri program'dan okur
        # (override etmiyoruz). repo/path None -> yerel dosya, repo yok.
        gen.openProgram(program, None, None, None, None, None)
        return gen

    @staticmethod
    def _iter_real_functions(program: Any) -> list[Any]:
        """Thunk/external olmayan fonksiyonlari topla."""
        funcs = []
        func_iter = program.getFunctionManager().getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            if func.isThunk() or func.isExternal():
                continue
            funcs.append(func)
        return funcs

    def _exe_already_ingested(self, database: Any, program: Any) -> bool:
        """Bu programin md5'i BSim DB'sinde ZATEN kayitli mi? (idempotent guard)

        R2: ayni exe her koşumda kör kör yeniden ingest edilince Ghidra
        InsertRequest, ayni md5'i (workspace yolu degistigi icin) farkli program
        adiyla ikinci kez eklemeye calisir ve ``already ingested with a
        different name`` FATAL hatasi verir -> native yol coker, lite moda
        duser (feature vector kaybi). Ingest'ten ONCE md5'i sorgulayip zaten
        varsa taramayi/insert'i atlariz; sorgu dogrudan mevcut DB'den calisir.

        QueryExeInfo.filterMd5 ile executable tablosu sorgulanir. Sorgu API'si
        yok/hata verirse ``False`` doner (guvenli: eski kor-ingest davranisi
        korunur, en fazla eski hata yolu tekrarlanir).
        """
        try:
            from ghidra.features.bsim.query.protocol import QueryExeInfo
        except Exception:  # noqa: BLE001
            logger.debug("QueryExeInfo import edilemedi, idempotent kontrol atlaniyor", exc_info=True)
            return False
        try:
            md5 = program.getExecutableMD5()
        except Exception:  # noqa: BLE001
            logger.debug("program.getExecutableMD5() basarisiz, idempotent kontrol atlaniyor", exc_info=True)
            return False
        if not md5:
            return False
        try:
            query = QueryExeInfo()
            query.filterMd5 = str(md5)
            query.limit = 1
            response = query.execute(database)
            if response is None:
                logger.debug(
                    "BSim QueryExeInfo None dondu (%s), ingest'e devam ediliyor",
                    self._last_error(database),
                )
                return False
            records = response.records
            return bool(records) and len(records) > 0
        except Exception:  # noqa: BLE001
            logger.debug("BSim exe md5 kontrolu basarisiz, ingest'e devam ediliyor", exc_info=True)
            return False

    # -- public -------------------------------------------------------

    def create_database(self, name: str) -> Path:
        """H2 file-based BSim veritabani olustur."""
        from ghidra.features.bsim.query.description import DatabaseInformation
        from ghidra.features.bsim.query.protocol import CreateDatabase

        db_file = self.db_path / f"{name}.mv.db"
        # DB dosyasi henuz yok -> initialize() etme, CreateDatabase halleder.
        database = self._build_client(name, initialize=False)
        try:
            cmd = CreateDatabase()
            cmd.info = DatabaseInformation()
            # None birakilan alanlari config template dolduruyor.
            cmd.info.databasename = name
            cmd.info.owner = "karadul"
            cmd.info.description = "Karadul BSim fonksiyon benzerlik veritabani"
            cmd.info.trackcallgraph = True
            cmd.config_template = _BSIM_CONFIG_TEMPLATE

            # KISIT: execute() hata halinde exception ATMAZ, None doner.
            # Gercek sebep getLastError()'dadir.
            if cmd.execute(database) is None:
                raise RuntimeError(
                    f"BSim CreateDatabase basarisiz ({name}): {self._last_error(database)}"
                )
            logger.info("BSim native DB olusturuldu: %s", db_file)
        except Exception as exc:
            logger.warning("BSim native DB olusturulamadi: %s", exc)
            raise
        finally:
            try:
                database.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)
            self.release(name)

        return db_file

    def ingest_program(self, program: Any, db_name: str, database: Any = None) -> int:
        """Programdaki fonksiyonlari BSim veritabanina ekle.

        ``database`` verilirse (oturum istemcisi) o kullanilir ve kapatilmaz.
        """
        from ghidra.features.bsim.query.protocol import InsertRequest

        own_client = database is None
        if own_client:
            database = self.open_client(db_name)
        gen = None
        self.last_ingest_already = False
        self.last_ingest_kismi = None
        self._ingest_yoneticisi = None
        self.last_scan_mode, self.last_scan_hatasi, self.last_scan_sayac = None, "", ""
        denetci = getattr(self, "denetci", None)
        paralel = bool(getattr(self, "paralel_tarama", False))
        try:
            # R2 (idempotent ingest): bu exe (md5) DB'de zaten varsa YENIDEN
            # ekleme -> "already ingested with a different name" fatal hatasini
            # ve lite'a dusmeyi onler. Sorgu zaten mevcut kayittan calisir.
            if self._exe_already_ingested(database, program):
                existing = len(self._iter_real_functions(program))
                self.last_ingest_already = True
                logger.info(
                    "BSim: exe zaten ingest edilmis (md5 eslesme), yeniden "
                    "eklenmiyor; sorguya geciliyor (%s, %d fonksiyon)",
                    db_name, existing,
                )
                return existing

            gen = self._gen_signatures(database, program)

            func_count = 0
            # ÖL-2: tarama döngüsü aynı; yalnız fonksiyon başına bütçe / olay denetimi ve sayaç.
            # Bütçe dolunca tarama durur, taranan kısım eklenir (sonraki koşuların sorgusu için).
            gercek = self._iter_real_functions(program)
            taranan = 0
            paralel_taranan: Optional[int] = None
            if paralel:
                # HZ-2: Ghidra'nın paralel taraması; bütçe izleyicide (kalan süreyle zaman aşımı).
                paralel_taranan, gen = self._tara(gen, database, program, gercek, denetci)
                if paralel_taranan is not None:
                    func_count = paralel_taranan
                    if denetci is not None and denetci.doldu:
                        self.last_ingest_kismi = {"islenen": paralel_taranan,
                                                  "toplam": len(gercek)}
            for func in (gercek if paralel_taranan is None else ()):
                if denetci is not None and denetci.denetle(taranan, len(gercek)):
                    self.last_ingest_kismi = {"islenen": taranan, "toplam": len(gercek)}
                    break
                taranan += 1
                try:
                    gen.scanFunction(func)
                    func_count += 1
                except Exception:
                    logger.debug(
                        "BSim fonksiyon taramasi basarisiz, atlaniyor", exc_info=True
                    )

            if func_count == 0:
                logger.warning("BSim ingest: taranabilen fonksiyon yok (%s)", db_name)
                return 0

            manager = gen.getDescriptionManager()

            # TUZAK (canli testte yakalandi, Ghidra 12.1.2):
            # callgraphtable'da (src,dest) PRIMARY KEY'dir. Bir fonksiyon ayni
            # hedefi birden fazla kez cagiriyorsa GenSignatures AYNI kenari
            # tekrar tekrar kaydeder ve insert
            #   "Unique index or primary key violation: PRIMARY_KEY_50
            #    ON public.callgraphtable(src, dest)"
            # ile patlar.
            # Bu kenarlari tekillestiren tek yer FunctionDescription.
            # sortCallgraph()'tir ve Ghidra onu SADECE DescriptionManager.
            # saveXml() icinden cagirir. Ghidra'nin kanonik ingest yolu
            # (BulkSignatures) imzalari once XML'e yazip geri okudugu icin
            # dedup'i "bedava" alir; biz DescriptionManager'i dogrudan
            # InsertRequest'e verdigimiz icin XML round-trip'i yok ->
            # dedup'i ELIMIZLE yapmak ZORUNDAYIZ.
            for fdesc in manager.listAllFunctions():
                fdesc.sortCallgraph()

            # Uretilen imzalar GenSignatures'in DescriptionManager'inda birikir;
            # DB'ye yazan sey InsertRequest.
            req = InsertRequest()
            req.manage = manager
            if req.execute(database) is None:
                raise RuntimeError(
                    f"BSim InsertRequest basarisiz ({db_name}): {self._last_error(database)}"
                )
            if paralel and self.last_ingest_kismi is None:
                # HZ-2: sorgu aynı imzaları yeniden üretmesin (yönetici dispose'dan etkilenmez).
                self._ingest_yoneticisi = (program, len(gercek), manager)
            return func_count
        finally:
            if gen is not None:
                try:
                    gen.dispose()
                except Exception:  # noqa: BLE001
                    logger.debug("GenSignatures dispose basarisiz", exc_info=True)
            if own_client:
                try:
                    database.close()
                except Exception:  # noqa: BLE001
                    logger.debug("BSim DB close basarisiz", exc_info=True)
                self.release(db_name)

    def query_function(
        self,
        database: Any,
        program: Any,
        func: Any,
        min_similarity: float = 0.7,
        max_results: int = 5,
        significance_threshold: float = _DEFAULT_SIGNIFICANCE_THRESHOLD,
        exclusion: Optional[_Exclusion] = None,
        extra_slots: int = 0,
    ) -> list[BSimMatch]:
        """Tek fonksiyon nesnesi icin acik istemciyle sorgu.

        Dislanacak adaylar (kendisi, ayni yapi) sonuc yuvasini yemesin diye
        Ghidra'dan ``max_results + extra_slots`` aday istenir, dislama sonrasi
        ``max_results``'a kirpilir.
        """
        from ghidra.features.bsim.query.protocol import QueryNearest

        gen = self._gen_signatures(database, program)
        try:
            try:
                gen.scanFunction(func)
            except Exception:
                logger.debug("BSim sorgu fonksiyonu taranamadi", exc_info=True)
                return []

            query = QueryNearest()
            query.manage = gen.getDescriptionManager()
            query.thresh = float(min_similarity)
            query.signifthresh = float(significance_threshold)
            query.max = int(max_results + max(0, extra_slots))

            response = query.execute(database)
            if response is None:
                raise RuntimeError(
                    f"BSim QueryNearest basarisiz: {self._last_error(database)}"
                )

            # ResponseNearest.result -> List<SimilarityResult>
            # SimilarityResult iterable -> SimilarityNote (similarity+significance)
            notes = [note for sim_result in response.result for note in sim_result]
            return self._matches_from_notes(
                str(func.getName()), str(func.getEntryPoint()), notes,
                max_results, exclusion,
            )
        finally:
            try:
                gen.dispose()
            except Exception:  # noqa: BLE001
                logger.debug("GenSignatures dispose basarisiz", exc_info=True)

    @staticmethod
    def _matches_from_notes(
        query_name: str,
        query_addr: str,
        notes: Any,
        max_results: int,
        exclusion: Optional[_Exclusion],
    ) -> list[BSimMatch]:
        """Bir sorgu fonksiyonunun ``SimilarityNote``'larını adaylara çevir.

        Dışlama (kendisi / aynı dosya / aynı yapı) not sırasıyla uygulanır ve sayılır,
        kalanlar ``max_results``'a kırpılır. Tekli ve toplu sorgu aynı yolu kullanır
        (P16c: toplu sorgu eşleşme kümesini değiştirmemeli).
        """
        matches: list[BSimMatch] = []
        for note in notes:
            fdesc = note.getFunctionDescription()
            exe = fdesc.getExecutableRecord()
            md5 = _hex_or_empty(_call_str(lambda: exe.getMd5()), 32) if exe else ""
            rec = exclusion.provenance.get(md5) if (exclusion and md5) else None
            if exclusion is not None:
                reason = exclusion.classify(md5)
                if reason:
                    exclusion.counts[reason] = exclusion.counts.get(reason, 0) + 1
                    continue
            try:
                m_addr = format(int(fdesc.getAddress()), "x")
            except Exception:  # noqa: BLE001
                m_addr = ""
            matches.append(BSimMatch(
                query_function=query_name,
                query_address=query_addr,
                matched_function=str(fdesc.getFunctionName()),
                matched_program=str(exe.getNameExec()) if exe else "",
                similarity=float(note.getSimilarity()),
                significance=float(note.getSignificance()),
                matched_address=m_addr,
                matched_exe_md5=md5,
                matched_exe_sha256=str((rec or {}).get("sha256") or ""),
                matched_source=SOURCE_RECORDED if rec else SOURCE_UNRECORDED,
            ))
        out = matches[:max_results]
        if exclusion is not None:
            exclusion.unrecorded_candidates += sum(
                1 for m in out if m.matched_source == SOURCE_UNRECORDED
            )
        return out

    def query_functions(
        self,
        database: Any,
        program: Any,
        funcs: list[Any],
        min_similarity: float = 0.7,
        max_results: int = 5,
        significance_threshold: float = _DEFAULT_SIGNIFICANCE_THRESHOLD,
        exclusion: Optional[_Exclusion] = None,
        extra_slots: int = 0,
    ) -> tuple[list[BSimMatch], int]:
        """Bütün fonksiyonlar için TEK ``GenSignatures`` + TEK ``QueryNearest`` (P16c).

        Eski yol (``query_function`` döngüsü) her fonksiyon için ayrı bir
        ``GenSignatures`` kuruyordu (``openProgram`` + kendi decompiler'ı): Debian
        ``cat``'te 107 fonksiyon 26,5 sn, fonksiyon başına ≈ 0,25 sn. Burada imzalar bir
        kez üretilir, sorgu bir kez koşar; ``ResponseNearest.result`` içindeki her
        ``SimilarityResult``'ın tabanı (``getBase()``) sorgu fonksiyonudur ve giriş
        adresiyle fonksiyona eşlenir. Adaylar fonksiyon sırasıyla, tekli yolla aynı
        dışlama ve kırpmadan geçer.

        Returns:
            (adaylar, taranamayan fonksiyon sayısı)
        """
        from ghidra.features.bsim.query.protocol import QueryNearest

        scan_failed = 0
        self.last_query_kismi = None
        denetci = getattr(self, "denetci", None)
        paralel = bool(getattr(self, "paralel_tarama", False))
        self.last_scan_mode, self.last_scan_hatasi, self.last_scan_sayac = None, "", ""
        # HZ-2: aynı oturumda tam ingest edildiyse onun yöneticisi (yeni GenSignatures yok).
        manager = self.hazir_yonetici(program, funcs) if paralel else None
        self._ingest_yoneticisi = None  # bir kez kullanılır; bellek tutulmaz
        gen = None if manager is not None else self._gen_signatures(database, program)
        try:
            scanned: list[Any] = []
            taranan = 0
            paralel_taranan: Optional[int] = None
            if manager is not None:
                paralel_taranan = len(funcs)
                self.last_scan_mode = SCAN_PARALLEL
            elif paralel:
                paralel_taranan, gen = self._tara(gen, database, program, funcs, denetci)
            if paralel_taranan is not None:
                taranan = paralel_taranan
                scanned = list(funcs)
            for func in (funcs if paralel_taranan is None else ()):
                # ÖL-2: tarama fonksiyon başına ilerler: parça sınırında bütçe / olay denetimi.
                if denetci is not None and denetci.denetle(taranan, len(funcs)):
                    break
                taranan += 1
                try:
                    gen.scanFunction(func)
                    scanned.append(func)
                except Exception:
                    scan_failed += 1
                    logger.debug("BSim sorgu fonksiyonu taranamadi", exc_info=True)
            # ÖL-2: ``QueryNearest.execute`` tek Java çağrısıdır, içinden kesilemez (HZ-2'nin
            # alanı). Bütçe taramada ya da çağrıdan hemen önce dolduysa çağrı yapılmaz.
            if denetci is not None and (denetci.doldu or denetci.denetle(taranan, len(funcs))):
                denetci.ek_neden = "toplu sorgu çağrılmadı (%d / %d fonksiyon tarandı)" % (
                    taranan, len(funcs))
                denetci.islenen = 0  # sorgusu biten fonksiyon yok
                self.last_query_kismi = {"islenen": 0, "toplam": len(funcs)}
                return [], scan_failed
            if not scanned:
                return [], scan_failed

            query = QueryNearest()
            query.manage = manager if manager is not None else gen.getDescriptionManager()
            query.thresh = float(min_similarity)
            query.signifthresh = float(significance_threshold)
            query.max = int(max_results + max(0, extra_slots))

            response = query.execute(database)
            if response is None:
                raise RuntimeError(
                    f"BSim QueryNearest (toplu) basarisiz: {self._last_error(database)}"
                )

            by_addr: dict[int, list[Any]] = {}
            for sim_result in response.result:
                base = sim_result.getBase()
                try:
                    key = int(base.getAddress())
                except Exception:  # noqa: BLE001
                    continue
                by_addr.setdefault(key, []).extend(note for note in sim_result)

            matches: list[BSimMatch] = []
            for func in scanned:
                entry = func.getEntryPoint()
                matches.extend(self._matches_from_notes(
                    str(func.getName()), str(entry),
                    by_addr.get(int(entry.getOffset()), []),
                    max_results, exclusion,
                ))
            return matches, scan_failed
        finally:
            if gen is not None:
                try:
                    gen.dispose()
                except Exception:  # noqa: BLE001
                    logger.debug("GenSignatures dispose basarisiz", exc_info=True)

    def query_similar(
        self,
        program: Any,
        function_name: str,
        db_name: str,
        min_similarity: float = 0.7,
        max_results: int = 5,
        significance_threshold: float = _DEFAULT_SIGNIFICANCE_THRESHOLD,
        exclusion: Optional[_Exclusion] = None,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin (adiyla) benzer fonksiyonlari sorgula; kendi istemcisini acar."""
        database = self._build_client(db_name)
        try:
            target_func = None
            for func in self._iter_real_functions(program):
                if func.getName() == function_name:
                    target_func = func
                    break
            if target_func is None:
                return []
            slots = exclusion.extra_slots() if exclusion is not None else 0
            return self.query_function(
                database, program, target_func, min_similarity, max_results,
                significance_threshold, exclusion, slots,
            )
        finally:
            try:
                database.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)
            self.release(db_name)

    def close(self) -> None:
        """Acik veritabani baglantisini kapat."""
        self._ingest_yoneticisi = None
        if self._database is not None:
            try:
                self._database.close()
            except Exception:
                logger.debug("Session/kaynak kapatma basarisiz, atlaniyor", exc_info=True)
            self._database = None


# ---------------------------------------------------------------------------
# Ana BSimDatabase sinifi
# ---------------------------------------------------------------------------

def _new_status(mode: str) -> dict[str, Any]:
    return {
        "mode": mode,
        "status": STATUS_NOT_RUN,
        "reason": "",
        "lock": "flock" if fcntl is not None else "none",
        "lock_wait_s": 0.0,
        "busy_retries": 0,
        "ingest_s": None,
        "query_s": None,
        "ingested_functions": None,
        "already_ingested": None,
        "query_errors": 0,
        "known_executables": None,
        "excluded": {"self": 0, "same_file": 0, "same_build": 0},
        "unrecorded_candidates": 0,
        "own_identity": None,
        "h2_released": None,  # oturum sonunda H2 havuzu kapatıldı mı (None: native istemci yoktu)
    }


class BSimDatabase:
    """BSim fonksiyon benzerlik veritabani yoneticisi.

    Otomatik olarak BSim native veya BSim lite modunu secer:
    - Ghidra BSim API erisilebiliyorsa native mod (gercek feature vector)
    - Degilse lite mod (SHA256 hash + JSON index)

    Oturum (P16b): ``ingest_program`` depo kilidini alir ve (``auto_query``
    aciksa) ``query_all_functions`` bitene ya da ``close`` cagrilana kadar
    tutar; native istemci oturum boyunca bir kez acilir. Durum ``status``
    sozlugunde ve ``BSimResult.status``'ta.

    Attributes:
        config: Karadul konfigurasyonu
        db_path: Veritabani dizini
        mode: "native" veya "lite"
        status: kip, durum, bekleme, sureler, dislanan aday sayilari
    """

    def __init__(self, config: Any) -> None:
        """BSimDatabase baslat.

        Args:
            config: Config nesnesi (config.bsim.db_path kullanilir).
                    Bos ise ~/.cache/karadul/bsim/ varsayilir.
        """
        bsim_cfg = getattr(config, "bsim", None)
        if bsim_cfg and bsim_cfg.db_path:
            self.db_path = Path(bsim_cfg.db_path)
        else:
            # R3: sabit ~/.cache/karadul yerine merkezi cache-root (env
            # override: KARADUL_CACHE_DIR / KARADUL_DATA_DIR). Izole kosumlar
            # (test/benchmark/farkli kullanici) ayni BSim DB'yi paylasip
            # birbirini bozmasin.
            from karadul.config import resolve_cache_root
            self.db_path = resolve_cache_root() / "bsim"
        self.db_path.mkdir(parents=True, exist_ok=True)

        self.config = config
        self._closed = False
        # ÖL-2: köprünün o anki alt adımının denetçisi (``headless._AdimDenetcisi``; ingest'ten
        # önce ingest'in, sorgudan önce sorgunun). None = bütçe yok, adım içi olay yok.
        self.denetci: Any = None
        # ÖL-2: "depoda başka program var mı" kararı (ingest'ten önce, köken kaydından).
        self._bos_depo: Optional[dict[str, Any]] = None
        self._lite_kismi: Optional[dict[str, int]] = None
        self._session_lock: Optional[_DirLock] = None
        self._session_deadline = 0.0
        self._client: Any = None
        self._client_db = ""
        self._identity: Optional[ExeIdentity] = None
        self._lite_hashes: dict[str, tuple[str, str]] = {}

        # Mod secimi
        if _check_bsim():
            self.mode = "native"
            self._native: Optional[_BSimNativeWrapper] = _BSimNativeWrapper(self.db_path)
            self._lite: Optional[_BSimLiteIndex] = None
            logger.info("BSim native mod aktif")
        else:
            self.mode = "lite"
            self._native = None
            self._lite = _BSimLiteIndex(self.db_path)
            logger.info("BSim lite mod aktif (Ghidra BSim API bulunamadi)")
        self.status: dict[str, Any] = _new_status(self.mode)

    # -- yardimcilar --------------------------------------------------

    def _bsim_cfg_value(self, name: str, default: Any) -> Any:
        value = getattr(getattr(self.config, "bsim", None), name, None)
        return default if value is None else value

    def _default_db_name(self) -> str:
        bsim_cfg = getattr(self.config, "bsim", None)
        return bsim_cfg.default_database if bsim_cfg else "karadul_bsim"

    def _lock_timeout(self) -> float:
        try:
            return max(0.0, float(self._bsim_cfg_value("lock_timeout_s", _LOCK_WAIT_S)))
        except (TypeError, ValueError):
            return _LOCK_WAIT_S

    def _skip(self, reason: str) -> None:
        self.status["status"] = STATUS_SKIPPED_BUSY
        self.status["reason"] = reason
        logger.warning("BSim atlandi: %s", reason)

    def _begin_session(self) -> bool:
        """Depo kilidini al (zaten tutuluyorsa True). Alinamazsa durum 'atlandi'."""
        if getattr(self, "_session_lock", None) is not None:
            return True
        if self.status.get("status") == STATUS_SKIPPED_BUSY:
            return False
        timeout = self._lock_timeout()
        lock = _DirLock(self.db_path)

        def _on_wait() -> None:
            logger.warning(
                "BSim deposu baska bir kosuda kullaniliyor (%s); en cok %.0f sn beklenecek",
                self.db_path, timeout,
            )

        ok = lock.acquire(timeout, on_wait=_on_wait)
        self.status["lock"] = lock.mechanism
        self.status["lock_wait_s"] = round(self.status.get("lock_wait_s", 0.0) + lock.waited_s, 3)
        if not ok:
            self._skip(f"depo kilidi {timeout:.0f} sn icinde alinamadi ({self.db_path})")
            return False
        self._session_lock = lock
        self._session_deadline = time.monotonic() + max(0.0, timeout - lock.waited_s)
        return True

    def _close_client(self) -> None:
        client = getattr(self, "_client", None)
        db_name = getattr(self, "_client_db", "")
        self._client = None
        self._client_db = ""
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)
            # Havuz kapanmazsa H2 dosyasi surec bitene dek bu surecte acik kalir.
            release = getattr(getattr(self, "_native", None), "release", None)
            if callable(release):
                self.status["h2_released"] = bool(release(db_name))

    def _end_session(self) -> None:
        self._close_client()
        lock = getattr(self, "_session_lock", None)
        self._session_lock = None
        if lock is not None:
            lock.release()

    def _ensure_client(self, db_name: str) -> Any:
        """Oturum istemcisini ac; H2 mesgulse (kilidi bilmeyen surec) sure dolana dek yeniden dene."""
        if self._client is not None and self._client_db == db_name:
            return self._client
        self._close_client()
        assert self._native is not None
        warned = False
        while True:
            try:
                self._client = self._native.open_client(db_name)
                self._client_db = db_name
                return self._client
            except Exception as exc:
                if not _is_busy_error(exc) or time.monotonic() + _BUSY_RETRY_S > self._session_deadline:
                    raise
                self.status["busy_retries"] = int(self.status.get("busy_retries", 0)) + 1
                if not warned:
                    logger.warning(
                        "BSim H2 veritabani mesgul (kilidi bilmeyen bir surec tutuyor olabilir); "
                        "%.0f sn arayla yeniden denenecek: %s", _BUSY_RETRY_S, exc,
                    )
                    warned = True
                time.sleep(_BUSY_RETRY_S)

    def _identity_for(self, program: Any) -> ExeIdentity:
        if self._identity is None:
            self._identity = program_identity(program)
            self.status["own_identity"] = self._identity.to_dict()
        return self._identity

    def _record_provenance(self, db_name: str, mode: str,
                           kismi: Optional[dict[str, int]] = None, tam: bool = False) -> None:
        if self._identity is None or not self._identity.md5:
            return
        try:
            _ProvenanceStore(self.db_path, db_name).record(self._identity, mode, kismi, tam)
        except Exception as exc:  # noqa: BLE001
            logger.warning("BSim kaynak kaydi yazilamadi: %s", exc)

    def _paralel_tarama(self) -> bool:
        """HZ-2: ``bsim.paralel_tarama`` (kapalı = bugünkü tekli yol)."""
        return bool(getattr(getattr(self.config, "bsim", None), "paralel_tarama", False))

    def _tarama_durumu(self) -> None:
        """HZ-2: son taramanın yolu ``status["scan_mode"]``'a (yalnız ayar açıkken).

        Bir adımda tekli yola düşüldüyse ``serial_fallback`` kalıcıdır (sorgu ingest'in
        yöneticisini kullansa bile) ve neden ``scan_fallback_error``'da. Sayaç okunamadıysa
        ``scan_sayac`` (adım içi olay o yüzden yok)."""
        if not self._paralel_tarama():
            return
        native = getattr(self, "_native", None)
        mod = getattr(native, "last_scan_mode", None)
        if not mod:
            return
        if self.status.get("scan_mode") != SCAN_SERIAL_FALLBACK:
            self.status["scan_mode"] = mod
        hata = getattr(native, "last_scan_hatasi", "")
        if mod == SCAN_SERIAL_FALLBACK and hata:
            self.status["scan_fallback_error"] = hata
        sayac = getattr(native, "last_scan_sayac", "")
        if sayac:
            self.status["scan_sayac"] = "okunamadı: " + sayac

    def _onceki_kismi(self, db_name: str) -> None:
        """HZ-2: bu md5 depoda zaten varsa ve önceki ingest kısmıysa durumda görünsün."""
        if self._identity is None or not self._identity.md5:
            return
        try:
            rec = _ProvenanceStore(self.db_path, db_name).load().get(self._identity.md5) or {}
        except Exception:  # noqa: BLE001
            logger.debug("BSim kaynak kaydi okunamadi", exc_info=True)
            return
        kismi = rec.get("kismi") if isinstance(rec, dict) else None
        if not isinstance(kismi, dict):
            return
        metin = "%s / %s" % (kismi.get("islenen", "?"), kismi.get("toplam", "?"))
        self.status["onceki_ingest_kismi"] = metin
        logger.warning(
            "BSim: bu ikilinin önceki ingest'i kısmiydi (%s fonksiyon); bu koşuda yeniden "
            "eklenmedi, depodaki eksik fonksiyonlar eksik kalıyor", metin)

    def _bos_depoda_atla(self) -> bool:
        return bool(self._bsim_cfg_value("bos_depoda_sorgu_atla", False))

    def bos_depo_durumu(self, program: Any, db_name: str) -> dict[str, Any]:
        """ÖL-2: depoda bu programdan başka program var mı (köken kaydından; Ghidra yok).

        Programın kendisi ve aynı kimlikli kopyaları (``_Exclusion.classify`` ile aynı ölçüt:
        md5, sha256, derleme kimliği) dışarıda tutulur: aynı ikili ikinci kez koşulduğunda depo
        "boş" sayılır. Karar verilemiyorsa (köken kaydı bozuk / okunamıyor, karantinada yedeği
        var, ya da kayıt yokken depo dosyası var) ``bos`` False'tur ve ``neden`` bunu söyler:
        sorgu bugünkü gibi koşar.

        Returns:
            ``{"bos": bool, "kayit": n, "baska": m}`` ya da ``{"bos": False, "neden": "…"}``.
        """
        identity = self._identity_for(program)
        store = _ProvenanceStore(self.db_path, db_name)
        provenance = store.load()
        if store.load_error:
            return {"bos": False,
                    "neden": f"köken kaydı okunamadı ({store.load_error}); sorgu atlanmadı"}
        karantina = sorted(self.db_path.glob(f"{store.path.name}{_QUARANTINE_INFIX}*"))
        if karantina:
            return {"bos": False,
                    "neden": f"köken kaydının karantinada {len(karantina)} yedeği var; "
                             "sorgu atlanmadı"}
        if not store.path.exists():
            depo_dosyasi = (self.db_path / f"{db_name}.mv.db").exists() or (
                self.db_path / _LITE_INDEX_NAME).exists()
            if depo_dosyasi:
                return {"bos": False,
                        "neden": "köken kaydı yok ama depo dosyası var; sorgu atlanmadı"}
        dislama = _Exclusion(identity, provenance)
        baska = sum(1 for md5 in provenance if not dislama.classify(md5))
        return {"bos": baska == 0, "kayit": len(provenance), "baska": baska}

    def _bos_depo_karari(self, program: Any, db_name: str) -> dict[str, Any]:
        """``bos_depo_durumu``; düşerse sorgu atlanmaz ve neden yazılır."""
        try:
            return self.bos_depo_durumu(program, db_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("BSim boş depo denetimi düştü: %s", exc)
            return {"bos": False,
                    "neden": f"boş depo denetimi düştü ({type(exc).__name__}: {exc}); "
                             "sorgu atlanmadı"}

    def _sorgu_karari(self, program: Any, db_name: str) -> dict[str, Any]:
        """ÖL-2: sorgu atlanacak mı. Ayar kapalıysa ya da depo kilidi / liste düştüyse {}
        (bugünkü yol). Ingest bu oturumda koştuysa onun ingest'ten ÖNCE verdiği karar."""
        if not self._bos_depoda_atla():
            return {}
        if self.status.get("status") in (STATUS_SKIPPED_BUSY, STATUS_FAILED):
            return {}
        if self._bos_depo is None:
            self._bos_depo = self._bos_depo_karari(program, db_name)
        return self._bos_depo

    def _ingest_kismi(self, kismi: Optional[dict[str, int]]) -> None:
        """ÖL-2: ingest bütçesi dolduysa durum ``kismi``; sayılar ve neden yazılır."""
        if not kismi:
            return
        den = self.denetci
        neden = den.neden() if den is not None and hasattr(den, "neden") else "ingest bütçesi doldu"
        if self.status.get("status") == STATUS_OK:
            self.status["status"] = STATUS_KISMI
        self.status["neden"] = "ingest: " + neden
        self.status["ingest_islenen"] = int(kismi.get("islenen", 0))
        if kismi.get("toplam") is not None:  # toplam bilinmiyorsa (lite) yazılmaz
            self.status["ingest_toplam"] = int(kismi["toplam"])
        logger.warning("BSim ingest bütçesi doldu: %s / %s fonksiyon tarandı (%s)",
                       kismi.get("islenen"), kismi.get("toplam"), neden)

    # -- public -------------------------------------------------------

    def create_database(self, name: str) -> Path:
        """Yeni BSim veritabani olustur.

        Args:
            name: Veritabani adi

        Returns:
            Olusturulan veritabani dosyasinin Path'i
        """
        self.db_path.mkdir(parents=True, exist_ok=True)

        if self.mode == "native" and self._native is not None:
            lock = _DirLock(self.db_path)
            if not lock.acquire(self._lock_timeout()):
                raise _BSimBusy(f"BSim deposu kilidi alinamadi ({self.db_path})")
            try:
                return self._native.create_database(name)
            except Exception as exc:
                logger.warning(
                    "BSim native DB olusturulamadi, lite moda dusulecek: %s", exc
                )
                self.mode = "lite"
                self._lite = _BSimLiteIndex(self.db_path)
            finally:
                lock.release()

        # Lite mod
        if self._lite is not None:
            self._lite.create_database(name)
        return self.db_path / f"{name}.bsim_lite.json"

    def ingest_program(self, program: Any, db_name: str) -> int:
        """Programdaki tum fonksiyonlari hash'leyerek veritabanina ekle.

        Depo kilidi alinamazsa (ya da H2 sure icinde bosalmazsa) ingest
        ATLANIR: 0 doner ve ``status['status'] == 'skipped_busy'``.

        Args:
            program: Ghidra program nesnesi (FlatProgramAPI uzerinden)
            db_name: Hedef veritabani adi

        Returns:
            Eklenen fonksiyon sayisi
        """
        self._identity_for(program)
        if not self._begin_session():
            return 0
        t0 = time.monotonic()
        keep_session = bool(self._bsim_cfg_value("auto_query", True))
        try:
            # ÖL-2: "depoda başka program var mı" ingest'ten ÖNCE ve kilit altında (eşzamanlı bir
            # koşunun kaydı yarıda okunmasın) cevaplanır; sorgu bu kararı kullanır.
            if self._bos_depoda_atla():
                self._bos_depo = self._bos_depo_karari(program, db_name)
            if self.mode == "native" and self._native is not None:
                try:
                    client = self._ensure_client(db_name)
                    self._native.denetci = self.denetci
                    self._native.paralel_tarama = self._paralel_tarama()
                    count = self._native.ingest_program(program, db_name, database=client)
                    self.status.update({
                        "mode": "native",
                        "status": STATUS_OK,
                        "ingested_functions": count,
                        "already_ingested": self._native.last_ingest_already,
                    })
                    kismi = getattr(self._native, "last_ingest_kismi", None)
                    self._ingest_kismi(kismi)
                    self._tarama_durumu()
                    if self._native.last_ingest_already:
                        self._onceki_kismi(db_name)
                    self._record_provenance(db_name, "native", kismi,
                                            tam=not kismi and not self._native.last_ingest_already)
                    return count
                except Exception as exc:
                    self._close_client()
                    if _is_busy_error(exc):
                        self._skip(
                            f"H2 veritabani mesgul ({self.status.get('busy_retries', 0)} "
                            f"yeniden deneme): {exc}"
                        )
                        keep_session = False
                        return 0
                    # Kilit / mesgul DISINDAKI yerel hata: lite yedegi, ama acikca.
                    logger.warning("BSim native ingest basarisiz, lite'a dusulecek: %s", exc)
                    self.mode = "lite"
                    if self._lite is None:
                        self._lite = _BSimLiteIndex(self.db_path)
                    self.status.update({
                        "mode": "lite",
                        "status": STATUS_FALLBACK_LITE,
                        "reason": f"native ingest basarisiz: {exc}",
                    })

            count = self._lite_ingest(program, db_name)
            if self.status.get("status") != STATUS_FALLBACK_LITE:
                self.status.update({"mode": "lite", "status": STATUS_OK})
            self.status["ingested_functions"] = count
            self._ingest_kismi(self._lite_kismi)
            self._record_provenance(db_name, "lite", self._lite_kismi, tam=not self._lite_kismi)
            return count
        finally:
            self.status["ingest_s"] = round(time.monotonic() - t0, 3)
            if not keep_session:
                self._end_session()

    def _lite_ingest(self, program: Any, db_name: str) -> int:
        """Lite mod: Ghidra API'den fonksiyonlari cek, hash'le (kilit altinda)."""
        if self._lite is None:
            self._lite = _BSimLiteIndex(self.db_path)
        identity = self._identity
        func_count = 0
        self._lite_kismi = None
        denetci = getattr(self, "denetci", None)
        try:
            program_name = program.getName()
            func_manager = program.getFunctionManager()
            func_iter = func_manager.getFunctions(True)

            # Decompiler lazim
            decomp_iface = None
            try:
                from ghidra.app.decompiler import DecompInterface
                decomp_iface = DecompInterface()
                decomp_iface.openProgram(program)
            except (ImportError, Exception) as exc:
                logger.debug("Decompiler acilamadi: %s", exc)

            while func_iter.hasNext():
                # ÖL-2: fonksiyon başına bütçe / olay denetimi (toplam bilinmiyor).
                if denetci is not None and denetci.denetle(func_count):
                    self._lite_kismi = {"islenen": func_count}
                    break
                func = func_iter.next()
                if func.isThunk() or func.isExternal():
                    continue

                func_name = func.getName()
                func_addr = str(func.getEntryPoint())
                decompiled_code = self._decompile(decomp_iface, func)
                instructions = self._instructions(program, func)

                entry = self._lite.ingest_function(
                    db_name=db_name,
                    program_name=program_name,
                    func_name=func_name,
                    func_address=func_addr,
                    decompiled_code=decompiled_code,
                    instructions=instructions,
                    identity=identity,
                )
                # Sorguda ayni fonksiyonu ucuncu kez decompile etmemek icin
                self._lite_hashes[func_addr] = (
                    entry.get("structural_hash", ""), entry.get("opcode_hash", ""),
                )
                func_count += 1

            if decomp_iface is not None:
                try:
                    decomp_iface.dispose()
                except Exception:
                    logger.debug("Decompiler interface dispose basarisiz, atlaniyor", exc_info=True)

            self._lite.save()
        except Exception as exc:
            logger.error("BSim lite ingest hatasi: %s", exc)
            # Kismen eklenmis fonksiyonlar kaybolmasin
            if self._lite is not None:
                try:
                    self._lite.save()
                except Exception:  # noqa: BLE001
                    logger.warning("BSim lite dizini kaydedilemedi", exc_info=True)

        return func_count

    @staticmethod
    def _decompile(decomp_iface: Any, func: Any) -> str:
        if decomp_iface is None:
            return ""
        try:
            result = decomp_iface.decompileFunction(func, 30, None)
            if result and result.decompileCompleted():
                decompiled_func = result.getDecompiledFunction()
                if decompiled_func:
                    return decompiled_func.getC()
        except Exception:
            logger.debug("BSim fonksiyon decompile basarisiz, atlaniyor", exc_info=True)
        return ""

    @staticmethod
    def _instructions(program: Any, func: Any) -> list[dict[str, Any]]:
        instructions: list[dict[str, Any]] = []
        try:
            listing = program.getListing()
            instr_iter = listing.getInstructions(func.getBody(), True)
            while instr_iter.hasNext():
                instr = instr_iter.next()
                instructions.append({"mnemonic": instr.getMnemonicString()})
        except Exception:
            logger.debug("BSim instruction toplama basarisiz, atlaniyor", exc_info=True)
        return instructions

    def _batch_query_enabled(self) -> bool:
        # P16c: toplu sorgu öntanımlı açık; ``bsim.batch_query`` alanı config.py'de
        # yok (yama: yamalar/P16c__config.py.patch), eklenirse getattr ile okunur.
        return bool(self._bsim_cfg_value("batch_query", True))

    def _significance(self) -> float:
        # KISIT: BSimConfig'de henuz min_significance alani YOK (config.py
        # bu paketin yetkisi disinda). getattr ile okuyoruz: alan sonradan
        # eklenirse kod degismeden devreye girer, yoksa modul varsayilani.
        try:
            return float(self._bsim_cfg_value("min_significance", _DEFAULT_SIGNIFICANCE_THRESHOLD))
        except (TypeError, ValueError):
            return _DEFAULT_SIGNIFICANCE_THRESHOLD

    def query_similar(
        self,
        program: Any,
        function_name: str,
        min_similarity: float = 0.7,
        max_results: int = 5,
        db_name: Optional[str] = None,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin veritabaninda benzer fonksiyonlari ara.

        Args:
            program: Ghidra program nesnesi
            function_name: Sorgulanacak fonksiyon adi
            min_similarity: Minimum benzerlik esigi [0.0, 1.0]
            max_results: Maksimum sonuc sayisi
            db_name: Veritabani adi (None = config.bsim.default_database)

        Returns:
            Eslesen fonksiyonlarin listesi (benzerlige gore sirali)
        """
        db_name = db_name or self._default_db_name()
        target = None
        try:
            func_iter = program.getFunctionManager().getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                if func.getName() == function_name:
                    target = func
                    break
        except Exception as exc:  # noqa: BLE001
            logger.warning("BSim sorgu hatasi: %s", exc)
            return []
        if target is None:
            return []
        result = self._query_functions(program, [target], min_similarity, max_results, db_name)
        return result.matches

    def _query_functions(
        self,
        program: Any,
        funcs: list[Any],
        min_similarity: float,
        max_results: int,
        db_name: str,
    ) -> BSimResult:
        identity = self._identity_for(program)
        started_here = getattr(self, "_session_lock", None) is None
        t0 = time.monotonic()
        all_matches: list[BSimMatch] = []
        try:
            if not self._begin_session():
                return self._result(db_name, 0, [], t0)
            provenance = _ProvenanceStore(self.db_path, db_name).load()
            exclusion = _Exclusion(identity, provenance)
            self.status["known_executables"] = len(provenance)

            if self.mode == "native" and self._native is not None:
                try:
                    client = self._ensure_client(db_name)
                except Exception as exc:
                    if _is_busy_error(exc):
                        self._skip(f"H2 veritabani mesgul: {exc}")
                    else:
                        self.status["status"] = STATUS_FAILED
                        self.status["reason"] = f"native sorgu istemcisi acilamadi: {exc}"
                        logger.warning("BSim native sorgu basarisiz: %s", exc)
                    return self._result(db_name, len(funcs), [], t0, exclusion)
                slots = exclusion.extra_slots()
                signif = self._significance()
                batch_done = False
                denetci = getattr(self, "denetci", None)
                kismi: Optional[dict[str, int]] = None
                if self._batch_query_enabled() and len(funcs) > 1:
                    # P16c: tek GenSignatures + tek QueryNearest. Düşerse eski tekli
                    # yola geçilir; dışlama sayaçları baştan sayılsın diye sıfırlanır.
                    counts_before = dict(exclusion.counts)
                    unrecorded_before = exclusion.unrecorded_candidates
                    try:
                        self._native.denetci = denetci
                        self._native.paralel_tarama = self._paralel_tarama()
                        batch_matches, scan_failed = self._native.query_functions(
                            client, program, funcs, min_similarity, max_results,
                            signif, exclusion, slots,
                        )
                        self._tarama_durumu()
                        all_matches.extend(batch_matches)
                        kismi = getattr(self._native, "last_query_kismi", None)
                        if scan_failed:
                            self.status["query_scan_failed"] = scan_failed
                        self.status["query_mode"] = "batch"
                        batch_done = True
                    except Exception as exc:  # noqa: BLE001
                        exclusion.counts = counts_before
                        exclusion.unrecorded_candidates = unrecorded_before
                        self.status["batch_query_error"] = "%s: %s" % (type(exc).__name__, exc)
                        logger.warning(
                            "BSim toplu sorgu basarisiz, fonksiyon basina sorguya "
                            "geciliyor: %s", exc,
                        )
                if not batch_done:
                    self.status["query_mode"] = "per_function"
                    sorgulanan = 0
                    for func in funcs:
                        # ÖL-2: fonksiyon başına yol: parça sınırında bütçe / olay denetimi.
                        if denetci is not None and denetci.denetle(sorgulanan, len(funcs)):
                            kismi = {"islenen": sorgulanan, "toplam": len(funcs)}
                            break
                        sorgulanan += 1
                        try:
                            all_matches.extend(self._native.query_function(
                                client, program, func, min_similarity, max_results,
                                signif, exclusion, slots,
                            ))
                        except Exception:
                            self.status["query_errors"] = int(self.status.get("query_errors", 0)) + 1
                            logger.debug("BSim tek fonksiyon sorgusu basarisiz", exc_info=True)
                if self.status.get("status") == STATUS_NOT_RUN:
                    self.status["status"] = STATUS_OK
                if kismi:
                    self._sorgu_kismi(kismi)
                    return self._result(db_name, kismi["islenen"], all_matches, t0, exclusion)
                return self._result(db_name, len(funcs), all_matches, t0, exclusion)

            # Lite mod
            if self._lite is None:
                return self._result(db_name, len(funcs), [], t0, exclusion)
            lookup = self._lite.build_lookup(db_name)
            program_name = _call_str(lambda: program.getName())
            decomp_iface = None
            denetci = getattr(self, "denetci", None)
            lite_kismi: Optional[dict[str, int]] = None
            for sira, func in enumerate(funcs):
                # ÖL-2: fonksiyon başına bütçe / olay denetimi.
                if denetci is not None and denetci.denetle(sira, len(funcs)):
                    lite_kismi = {"islenen": sira, "toplam": len(funcs)}
                    break
                try:
                    func_addr = str(func.getEntryPoint())
                    hashes = self._lite_hashes.get(func_addr)
                    if hashes is None:
                        if decomp_iface is None:
                            decomp_iface = self._open_decompiler(program)
                        code = self._decompile(decomp_iface, func)
                        instrs = self._instructions(program, func)
                        hashes = (
                            _BSimLiteIndex._compute_structural_hash(code) if code else "",
                            _BSimLiteIndex._compute_opcode_hash(instrs) if instrs else "",
                        )
                    all_matches.extend(self._lite.query_function(
                        db_name=db_name,
                        func_address=func_addr,
                        structural_hash=hashes[0],
                        opcode_hash=hashes[1],
                        exclude_program=program_name,
                        min_similarity=min_similarity,
                        max_results=max_results,
                        query_name=str(func.getName()),
                        exclusion=exclusion,
                        lookup=lookup,
                    ))
                except Exception:
                    self.status["query_errors"] = int(self.status.get("query_errors", 0)) + 1
                    logger.debug("BSim lite sorgu hatasi", exc_info=True)
            if decomp_iface is not None:
                try:
                    decomp_iface.dispose()
                except Exception:  # noqa: BLE001
                    logger.debug("Decompiler dispose basarisiz", exc_info=True)
            if self.status.get("status") == STATUS_NOT_RUN:
                self.status["status"] = STATUS_OK
            if lite_kismi:
                self._sorgu_kismi(lite_kismi)
                return self._result(db_name, lite_kismi["islenen"], all_matches, t0, exclusion)
            return self._result(db_name, len(funcs), all_matches, t0, exclusion)
        finally:
            if started_here or self.status.get("status") == STATUS_SKIPPED_BUSY:
                self._end_session()

    def _neden_ekle(self, neden: str) -> None:
        onceki = self.status.get("neden")
        self.status["neden"] = "%s; %s" % (onceki, neden) if onceki else neden

    def _sorgu_kismi(self, kismi: dict[str, int]) -> None:
        """ÖL-2: sorgu bütçesi dolduysa durum ``kismi``; eldeki eşleşmeler yazılır."""
        den = self.denetci
        neden = den.neden() if den is not None and hasattr(den, "neden") else "sorgu bütçesi doldu"
        if self.status.get("status") == STATUS_OK:
            self.status["status"] = STATUS_KISMI
        self._neden_ekle("sorgu: " + neden)
        self.status["sorgu_islenen"] = int(kismi.get("islenen", 0))
        self.status["sorgu_toplam"] = int(kismi.get("toplam", 0))
        logger.warning("BSim sorgu bütçesi doldu: %s / %s fonksiyon sorgulandı (%s)",
                       kismi.get("islenen"), kismi.get("toplam"), neden)

    def _atlanan_sorgu(self, db_name: str, t0: float) -> BSimResult:
        """ÖL-2: boş depoda sorgu yerine aynı şemada sonuç (0 eşleşme, 0 sorgu, ``atlandi``)."""
        try:
            self.status["known_executables"] = len(_ProvenanceStore(self.db_path, db_name).load())
        except Exception:  # noqa: BLE001
            logger.debug("BSim kaynak kaydi okunamadi", exc_info=True)
        if self.status.get("status") in (STATUS_OK, STATUS_NOT_RUN):
            self.status["status"] = STATUS_ATLANDI
        self.status["sorgu_atlandi"] = True
        self._neden_ekle(BOS_DEPO_NEDENI)
        logger.info("BSim sorgusu atlandı: %s", BOS_DEPO_NEDENI)
        return self._result(db_name, 0, [], t0)

    @staticmethod
    def _open_decompiler(program: Any) -> Any:
        try:
            from ghidra.app.decompiler import DecompInterface
            iface = DecompInterface()
            iface.openProgram(program)
            return iface
        except (ImportError, Exception):
            return None

    def _result(
        self,
        db_name: str,
        total_queries: int,
        matches: list[BSimMatch],
        t0: float,
        exclusion: Optional[_Exclusion] = None,
    ) -> BSimResult:
        duration = time.monotonic() - t0
        self.status["query_s"] = round(duration, 3)
        if exclusion is not None:
            self.status["excluded"] = dict(exclusion.counts)
            self.status["unrecorded_candidates"] = exclusion.unrecorded_candidates
        self.status["mode"] = self.mode
        return BSimResult(
            total_queries=total_queries,
            total_matches=len(matches),
            matches=matches,
            database_name=db_name,
            query_duration=round(duration, 3),
            mode=self.mode,
            status=json.loads(json.dumps(self.status)),
        )

    def query_all_functions(
        self,
        program: Any,
        min_similarity: float = 0.7,
        db_name: Optional[str] = None,
    ) -> BSimResult:
        """Programdaki tum fonksiyonlar icin toplu benzerlik sorgusu.

        Sorgu bitince depo kilidi birakilir. Kilit alinamadiysa ya da ingest
        atlandiysa sorgu yapilmaz; ``BSimResult.status`` bunu soyler.

        Args:
            program: Ghidra program nesnesi
            min_similarity: Minimum benzerlik esigi [0.0, 1.0]
            db_name: Veritabani adi (None = config.bsim.default_database)

        Returns:
            BSimResult: Toplam sorgu istatistikleri, eslesmeler, kip ve durum
        """
        db_name = db_name or self._default_db_name()
        bsim_cfg = getattr(self.config, "bsim", None)
        max_results = bsim_cfg.max_results_per_function if bsim_cfg else 5

        funcs: list[Any] = []
        try:
            func_iter = program.getFunctionManager().getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                if func.isThunk() or func.isExternal():
                    continue
                funcs.append(func)
        except Exception as exc:
            logger.error("BSim toplu sorgu hatasi: %s", exc)
            self.status["status"] = STATUS_FAILED
            self.status["reason"] = f"fonksiyon listesi alinamadi: {exc}"

        try:
            karar = self._sorgu_karari(program, db_name)
            if karar.get("bos"):
                result = self._atlanan_sorgu(db_name, time.monotonic())
            else:
                if karar.get("neden"):
                    # Karar verilemedi: sorgu bugünkü gibi koşar, neden durumda görünür.
                    self.status["bos_depo_denetimi"] = karar["neden"]
                result = self._query_functions(
                    program, funcs, min_similarity, max_results, db_name)
        finally:
            # Oturum (ingest'ten beri tutulan kilit) burada biter; H2 havuzu kapanır.
            self._end_session()
        result.status["h2_released"] = self.status.get("h2_released")
        return result

    def storage_info(self) -> dict[str, Any]:
        """Analizin kullandigi depo (CLI ve arayuz dogru yeri gostersin; GHIDRA-12)."""
        native = sorted(
            str(f) for f in self.db_path.glob("*.mv.db") if f.is_file()
        ) if self.db_path.exists() else []
        lite = self.db_path / _LITE_INDEX_NAME
        return {
            "db_path": str(self.db_path),
            "mode": self.mode,
            "native_api_available": bool(_check_bsim()),
            "native_databases": native,
            "lite_index": str(lite) if lite.exists() else None,
            "lock_file": str(self.db_path / _LOCK_FILE_NAME),
            "default_database": self._default_db_name(),
        }

    def list_databases(self) -> list[dict[str, Any]]:
        """Mevcut BSim veritabanlarini listele (salt okur; kipten bagimsiz).

        Native ``.mv.db`` dosyalari JVM'siz surecte de listelenir (analizin
        kullandigi depo budur); lite dizini de eklenir. Hicbir dosya yazilmaz.

        Returns:
            Her veritabani icin {name, mode, ...} iceren sozluk listesi
        """
        databases: list[dict[str, Any]] = []
        if self.db_path.exists():
            for f in sorted(self.db_path.iterdir()):
                if f.is_file() and f.name.endswith(".mv.db"):
                    db_name = f.name[: -len(".mv.db")]
                    entry: dict[str, Any] = {
                        "name": db_name,
                        "path": str(f),
                        "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                        "mode": "native",
                    }
                    prov = _ProvenanceStore(self.db_path, db_name)
                    if prov.path.exists():
                        entry["recorded_programs"] = len(prov.load())
                    databases.append(entry)

        lite = self._lite if self._lite is not None else _BSimLiteIndex(self.db_path)
        databases.extend(lite.list_databases())
        return databases

    def _close(self, save_timeout: float) -> None:
        if getattr(self, "_closed", False):
            return
        self._closed = True
        lite = getattr(self, "_lite", None)
        if lite is not None:
            try:
                lite.save(save_timeout)  # değişiklik yoksa dosyaya dokunmaz
            except Exception:
                logger.warning("BSim lite dizini kaydedilemedi", exc_info=True)
        try:
            self._end_session()
        except Exception:  # noqa: BLE001
            logger.debug("BSim oturumu kapatilamadi", exc_info=True)
        native = getattr(self, "_native", None)
        if native is not None:
            native.close()

    def close(self) -> None:
        """Tum kaynaklari serbest birak. Birden fazla cagri guvenlidir.

        Lite dizini yalniz degisiklik varsa yazilir (GHIDRA-12 e).
        """
        self._close(self._lock_timeout())

    def __enter__(self) -> BSimDatabase:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            # Cop toplayicida uzun bekleme yok: kilit hemen alinamazsa kayit atlanir.
            self._close(0.0)
        except Exception:
            logger.debug("BSim destructor close basarisiz, atlaniyor", exc_info=True)
