"""Debugger Bridge -- GDB/LLDB runtime deger yakalama.

Binary'leri debugger altinda calistirarak runtime degerler toplar.
Ghidra'nin statik tip tahminlerini dogrulamak ve
fonksiyon parametrelerinin gercek degerlerini yakalamak icin kullanilir.

UYARI: Bilinmeyen binary'leri calistirmak guvenlik riski tasir.
Bu ozellik varsayilan olarak KAPALIDIR.

Kullanim:
    bridge = DebuggerBridge(config)
    if bridge.detect_debugger():
        values = bridge.capture_at_breakpoints(binary, breakpoints)
        verifications = bridge.verify_types(values, ghidra_types)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

# B21: cikplak subprocess.run yerine safe_run (LD_PRELOAD/DYLD koruma).
# debugger_cmd[0] caller tarafinda lldb/gdb absolute yolu olarak verilmistir;
# burada env temizligi yeterli.
from karadul.core.safe_subprocess import safe_run

if TYPE_CHECKING:
    from karadul.config import Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------


@dataclass
class CaptureSpec:
    """Bir breakpoint'te ne yakalanacagini tanimlar.

    Attributes:
        registers: Okunacak register isimleri (orn. ["rdi", "rsi", "rax"]).
        stack_depth: Stack frame derinligi (0 = sadece mevcut frame).
        memory_reads: Okunacak bellek bolgesi listesi -- [(adres, boyut)].
    """
    registers: list[str] = field(default_factory=lambda: ["rdi", "rsi", "rax"])
    stack_depth: int = 0
    memory_reads: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class BreakpointSpec:
    """Breakpoint tanimlamasi.

    Attributes:
        address: Hex adres (orn. "0x100003f00") veya fonksiyon adi.
        function_name: Opsiyonel fonksiyon adi (Ghidra'dan).
        capture: Bu breakpoint'te ne yakalanacagi.
    """
    address: str
    function_name: str | None = None
    capture: CaptureSpec = field(default_factory=CaptureSpec)


@dataclass
class CapturedValue:
    """Bir breakpoint'ten yakalanan runtime degeri.

    Attributes:
        address: Breakpoint adresi.
        function_name: Fonksiyon adi (varsa).
        hit_count: Bu breakpoint kac kez tetiklendi.
        register_values: Register adi -> deger eslesmesi.
        stack_values: Stack frame bilgisi.
        timestamp: Yakalama zamani (monotonic).
    """
    address: str
    function_name: str | None
    hit_count: int
    register_values: dict[str, int | str]
    stack_values: dict[str, int | str]
    timestamp: float


@dataclass
class TypeVerification:
    """Ghidra tip tahmini ile runtime deger karsilastirmasi.

    Attributes:
        function_name: Fonksiyon adi.
        variable_name: Degisken/register adi.
        ghidra_type: Ghidra'nin tahmini tip.
        runtime_value: Runtime'da yakalanan deger.
        inferred_type: Runtime degerden cikarilan tip.
        match: Ghidra tipiyle uyum var mi.
        confidence: Eslesme guveni (0.0 - 1.0).
    """
    function_name: str
    variable_name: str
    ghidra_type: str
    runtime_value: int | str
    inferred_type: str
    match: bool
    confidence: float


# ---------------------------------------------------------------------------
# Tip cikarimi yardimcilari
# ---------------------------------------------------------------------------


def _infer_type_from_value(value: int | str) -> tuple[str, float]:
    """Runtime degerden tip tahmin et.

    Basit heuristikler kullanir:
    - 0 veya 1 -> bool (dusuk guven, int de olabilir)
    - 0-255 -> char/byte
    - 0-65535 -> short/uint16
    - 0-4294967295 -> int/uint32
    - Cok buyuk pozitif degerler -> pointer
    - Negatif degerler -> signed int

    Returns:
        (tip_adi, guven_skoru) tuple'i.
    """
    if isinstance(value, str):
        # Hex string olarak gelen pointer degeri
        try:
            value = int(value, 16)
        except (ValueError, TypeError):
            return ("string", 0.5)

    if not isinstance(value, int):
        return ("unknown", 0.1)

    # Bool kontrolu (en dusuk oncelik -- int de olabilir)
    if value in (0, 1):
        return ("bool", 0.3)

    # Negatif -> signed
    if value < 0:
        if -128 <= value:
            return ("int8", 0.6)
        if -32768 <= value:
            return ("int16", 0.6)
        if -2147483648 <= value:
            return ("int32", 0.7)
        return ("int64", 0.7)

    # Pozitif degerler
    if value <= 0xFF:
        return ("uint8", 0.5)
    if value <= 0xFFFF:
        return ("uint16", 0.6)
    if value <= 0xFFFFFFFF:
        return ("uint32", 0.7)

    # Cok buyuk deger -- muhtemelen pointer
    # x86_64 canonical adresler: 0x7fxxxxxxxxxx veya 0xffffxxxxxxxx
    if value > 0x100000:
        return ("pointer", 0.8)

    return ("uint64", 0.6)


def _types_compatible(ghidra_type: str, inferred_type: str) -> tuple[bool, float]:
    """Ghidra tipi ile cikarilmis tipin uyumlu olup olmadigini kontrol et.

    Returns:
        (uyumlu_mu, guven) tuple'i.
    """
    ghidra_lower = ghidra_type.lower().strip()
    inferred_lower = inferred_type.lower().strip()

    # Birebir eslesme
    if ghidra_lower == inferred_lower:
        return (True, 0.95)

    # Pointer tipleri
    pointer_indicators = ("*", "ptr", "pointer", "addr")
    ghidra_is_ptr = any(p in ghidra_lower for p in pointer_indicators)
    if ghidra_is_ptr and inferred_lower == "pointer":
        return (True, 0.85)
    if ghidra_is_ptr and inferred_lower != "pointer":
        return (False, 0.7)

    # Bool tipleri
    bool_types = {"bool", "_bool", "boolean", "byte"}
    if ghidra_lower in bool_types and inferred_lower == "bool":
        return (True, 0.6)

    # Char/byte tipleri
    char_types = {"char", "uchar", "byte", "uint8", "uint8_t", "unsigned char"}
    if ghidra_lower in char_types and inferred_lower in ("uint8", "bool"):
        return (True, 0.7)

    # Int tipleri -- genis eslesme
    int_types_32 = {"int", "uint", "dword", "uint32", "uint32_t", "int32_t", "unsigned int"}
    if ghidra_lower in int_types_32 and inferred_lower in ("uint32", "int32"):
        return (True, 0.8)

    # Short tipleri
    short_types = {"short", "ushort", "uint16", "uint16_t", "int16_t", "word"}
    if ghidra_lower in short_types and inferred_lower in ("uint16", "int16"):
        return (True, 0.8)

    # Long/int64
    long_types = {"long", "ulong", "uint64", "uint64_t", "int64_t", "qword", "long long"}
    if ghidra_lower in long_types and inferred_lower in ("uint64", "int64", "pointer"):
        return (True, 0.7)

    # void* = pointer
    if ghidra_lower in ("void *", "void*", "undefined8") and inferred_lower == "pointer":
        return (True, 0.75)

    # Eslesmedi
    return (False, 0.5)


# ---------------------------------------------------------------------------
# v1.15-E B5: CWE-94 (Python kod enjeksiyonu) savunma katmani
# ---------------------------------------------------------------------------
#
# Eski LLDB/GDB script sablonlari kullanici-kontrollu degerleri (register
# isimleri, fonksiyon adlari, breakpoint adresleri) ``{...!r}`` ile dogrudan
# Python source koduna gomuyordu. ``repr()`` newline'lari escape eder ama
# defense-in-depth icin uc kati savunma uyguluyoruz:
#
#   1. **Whitelist:** ``_is_safe_identifier`` + ``_is_safe_address`` ile
#      gecersiz girdiler script uretiminden once reddedilir (``ValueError``).
#   2. **Veri-kod ayrimi:** Dinamik veri tek bir JSON string olarak
#      ``_CONFIG_JSON`` icine gomulur ve runtime'da ``json.loads`` ile
#      parse edilir. JSON spesifikasyonu yurutulebilir kod tasimaz.
#   3. **Python literal escape:** ``_CONFIG_JSON = {config_json!r}``
#      ``repr()`` JSON string'i Python str literal olarak guvenli sekilde
#      escape eder (newline, quote vb. kacik karakter satira tasamaz).

# Whitelist regex'leri — kati Python identifier ve hex/identifier adres.
# Uzunluk siniri: 128 karakter (DoS koruma + makul ust sinir).
_IDENT_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
# Adres: ya 0x-hex (max 32 hex digit = 128-bit, gercekte 64-bit yeterli)
# ya da identifier benzeri (C++ namespace ``::``, ``.`` mangled icin mubah).
_ADDR_RE = re.compile(
    r"\A(0x[0-9a-fA-F]{1,32}|[A-Za-z_][A-Za-z0-9_:.]{0,127})\Z",
)


def _is_safe_identifier(name: object) -> bool:
    """Strict whitelist: ``[A-Za-z_][A-Za-z0-9_]*`` (max 128 char).

    Register adlari, fonksiyon isimleri ve script icinde Python identifier
    olarak kullanilacak diger isimler icin. Bos string, sayi/punctuation
    ile baslayanlar, herhangi bir kacis karakteri iceren string'ler
    reddedilir.
    """
    if not isinstance(name, str):
        return False
    return _IDENT_RE.match(name) is not None


def _is_safe_address(addr: object) -> bool:
    """Whitelist: ``0xHEX`` veya identifier (``::``/``.`` mubah).

    Breakpoint adresleri ya hex literal (``0x...``) ya da fonksiyon adi
    (mubah: C++ namespace ayraci ``::``, mangled isimde ``.``) olabilir.
    Kacis karakterleri (``'``, ``"``, ``\\n`` vb.) reddedilir.
    """
    if not isinstance(addr, str):
        return False
    return _ADDR_RE.match(addr) is not None


# ---------------------------------------------------------------------------
# LLDB script sablonu
# ---------------------------------------------------------------------------
#
# Tek format parametresi: ``config_json`` (JSON string).
# Runtime'da ``json.loads`` ile parse edilir; saldirgan payload (kacis
# karakterleri vs.) JSON string seviyesinde kalir, Python kod katmanina
# yukselemez.

_LLDB_SCRIPT_TEMPLATE = '''\
"""Karadul LLDB capture script -- otomatik uretilmis, elle degistirmeyin."""
import lldb
import json
import time

# v1.15-E B5: Tum dinamik veri TEK JSON string olarak gomulur. repr() ile
# Python str literal'i icinde escape edilir; runtime'da json.loads ile
# parse edilir. Bu sayede saldirgan payload Python kodu olarak DEGIL,
# JSON string verisi olarak yorumlanir.
_CONFIG_JSON = {config_json!r}
_CONFIG = json.loads(_CONFIG_JSON)

OUTPUT_PATH = _CONFIG["output_path"]
MAX_CAPTURES_PER_BP = _CONFIG["max_captures"]

results = []
hit_counts = {{}}


def breakpoint_callback(frame, bp_loc, extra_args, internal_dict):
    """Breakpoint tetiklendiginde cagrilir."""
    bp_id = str(bp_loc.GetBreakpoint().GetID())
    hit_counts[bp_id] = hit_counts.get(bp_id, 0) + 1

    if hit_counts[bp_id] > MAX_CAPTURES_PER_BP:
        return False  # Artik durdurma

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    entry = {{
        "address": hex(frame.GetPC()),
        "function_name": frame.GetFunctionName() or "",
        "hit_count": hit_counts[bp_id],
        "register_values": {{}},
        "stack_values": {{}},
        "timestamp": time.monotonic(),
    }}

    # Register degerlerini oku
    registers_to_read = _CONFIG["registers"]
    for reg_set in frame.GetRegisters():
        for reg in reg_set:
            if reg.GetName() in registers_to_read:
                val = reg.GetValue()
                entry["register_values"][reg.GetName()] = val if val else "N/A"

    # Stack frame bilgisi
    stack_depth = _CONFIG["stack_depth"]
    for i in range(min(stack_depth + 1, thread.GetNumFrames())):
        sf = thread.GetFrameAtIndex(i)
        entry["stack_values"]["frame_" + str(i)] = {{
            "pc": hex(sf.GetPC()),
            "function": sf.GetFunctionName() or "unknown",
        }}

    results.append(entry)
    return False  # Devam et (True = dur)


def __lldb_init_module(debugger, internal_dict):
    """LLDB script yukleme noktasi."""
    target = debugger.GetSelectedTarget()
    if not target:
        print("[karadul] HATA: Hedef bulunamadi")
        return

    breakpoints = _CONFIG["breakpoints"]
    for bp_spec in breakpoints:
        addr = bp_spec["address"]
        if addr.startswith("0x"):
            bp = target.BreakpointCreateByAddress(int(addr, 16))
        else:
            # Fonksiyon adi olarak dene
            bp = target.BreakpointCreateByName(addr)

        if bp.IsValid():
            bp.SetScriptCallbackFunction("karadul_lldb_capture.breakpoint_callback")
            print(f"[karadul] Breakpoint ayarlandi: {{addr}} (ID={{bp.GetID()}})")
        else:
            print(f"[karadul] UYARI: Breakpoint ayarlanamadi: {{addr}}")

    # Process'i calistir
    process = target.GetProcess()
    if process and process.IsValid():
        process.Continue()


def atexit_handler():
    """Sonuclari dosyaya yaz."""
    try:
        with open(OUTPUT_PATH, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[karadul] {{len(results)}} yakalama {{OUTPUT_PATH}} dosyasina yazildi")
    except Exception as e:
        print(f"[karadul] Yazma hatasi: {{e}}")


import atexit
atexit.register(atexit_handler)
'''

# ---------------------------------------------------------------------------
# GDB script sablonu
# ---------------------------------------------------------------------------

_GDB_SCRIPT_TEMPLATE = '''\
"""Karadul GDB capture script -- otomatik uretilmis, elle degistirmeyin."""
import gdb
import json
import time

# v1.15-E B5: Tek JSON string, runtime json.loads. CWE-94 savunmasi.
_CONFIG_JSON = {config_json!r}
_CONFIG = json.loads(_CONFIG_JSON)

CAPTURE_OUT = _CONFIG["output_path"]
MAX_CAPTURES_PER_BP = _CONFIG["max_captures"]

results = []
hit_counts = {{}}


class KaradulBreakpoint(gdb.Breakpoint):
    """Breakpoint alt sinifi -- yakalama yapar."""

    def __init__(self, spec, registers, stack_depth):
        super().__init__(spec)
        self.registers_to_read = registers
        self.stack_depth = stack_depth

    def stop(self):
        """Breakpoint tetiklendiginde cagrilir. False = devam et."""
        bp_id = str(self.number)
        hit_counts[bp_id] = hit_counts.get(bp_id, 0) + 1

        if hit_counts[bp_id] > MAX_CAPTURES_PER_BP:
            return False

        frame = gdb.selected_frame()
        entry = {{
            "address": hex(frame.pc()),
            "function_name": str(frame.name()) if frame.name() else "",
            "hit_count": hit_counts[bp_id],
            "register_values": {{}},
            "stack_values": {{}},
            "timestamp": time.monotonic(),
        }}

        # Register degerlerini oku
        for reg_name in self.registers_to_read:
            try:
                val = gdb.parse_and_eval("$" + reg_name)
                entry["register_values"][reg_name] = str(val)
            except gdb.error:
                entry["register_values"][reg_name] = "N/A"

        # Stack frame bilgisi
        try:
            f = gdb.selected_frame()
            for i in range(self.stack_depth + 1):
                entry["stack_values"]["frame_" + str(i)] = {{
                    "pc": hex(f.pc()),
                    "function": str(f.name()) if f.name() else "unknown",
                }}
                older = f.older()
                if older is None:
                    break
                f = older
        except gdb.error:
            pass

        results.append(entry)
        return False  # Devam et


breakpoints_spec = _CONFIG["breakpoints"]
registers_list = _CONFIG["registers"]
stack_depth_val = _CONFIG["stack_depth"]

for bp_spec in breakpoints_spec:
    addr = bp_spec["address"]
    try:
        KaradulBreakpoint(addr, registers_list, stack_depth_val)
        print(f"[karadul] Breakpoint ayarlandi: {{addr}}")
    except gdb.error as e:
        print(f"[karadul] UYARI: Breakpoint ayarlanamadi: {{addr}} -- {{e}}")


def save_results():
    """Sonuclari dosyaya yaz."""
    try:
        with open(CAPTURE_OUT, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[karadul] {{len(results)}} yakalama {{CAPTURE_OUT}} dosyasina yazildi")
    except Exception as e:
        print(f"[karadul] Yazma hatasi: {{e}}")


import atexit
atexit.register(save_results)
'''


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------


class DebuggerBridge:
    """GDB/LLDB ile runtime deger yakalama koprusu.

    Binary'yi debugger altinda calistirarak breakpoint'lerdeki register
    ve stack degerlerini yakalar. Ghidra'nin statik tip tahminlerini
    dogrulamak icin kullanilir.

    UYARI: Bilinmeyen binary'leri calistirmak guvenlik riski tasir.
    Bu ozellik varsayilan olarak KAPALIDIR (config.debugger.enabled = False).
    Sadece guvenilir binary'ler icin kullanin.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._debugger_cfg = config.debugger
        self._detected_debugger: str | None = None

    # -----------------------------------------------------------------------
    # Debugger tespiti
    # -----------------------------------------------------------------------

    def detect_debugger(self) -> str | None:
        """Sistemde kullanilabilir debugger'i tespit et.

        config.debugger.preferred_debugger ayarina gore:
        - "auto": macOS'ta lldb, Linux'ta gdb tercih edilir.
        - "lldb": Sadece lldb aranir.
        - "gdb": Sadece gdb aranir.

        Returns:
            "lldb", "gdb" veya None (bulunamadiysa).
        """
        pref = self._debugger_cfg.preferred_debugger

        if pref == "lldb":
            if shutil.which("lldb"):
                self._detected_debugger = "lldb"
                return "lldb"
            logger.warning("lldb tercih edildi ama bulunamadi")
            return None

        if pref == "gdb":
            if shutil.which("gdb"):
                self._detected_debugger = "gdb"
                return "gdb"
            logger.warning("gdb tercih edildi ama bulunamadi")
            return None

        # auto: once lldb (macOS default), sonra gdb (Linux default)
        if shutil.which("lldb"):
            self._detected_debugger = "lldb"
            return "lldb"
        if shutil.which("gdb"):
            self._detected_debugger = "gdb"
            return "gdb"

        logger.info("Ne lldb ne gdb bulunamadi -- debugger bridge devre disi")
        self._detected_debugger = None
        return None

    # -----------------------------------------------------------------------
    # Breakpoint yakalama
    # -----------------------------------------------------------------------

    def capture_at_breakpoints(
        self,
        binary_path: Path,
        breakpoints: list[BreakpointSpec],
        args: list[str] | None = None,
    ) -> list[CapturedValue]:
        """Binary'yi debugger ile calistirip breakpoint'lerdeki degerleri yakala.

        Args:
            binary_path: Hedef binary dosya yolu.
            breakpoints: Breakpoint tanimlari listesi.
            args: Binary'ye verilecek argümanlar.

        Returns:
            Yakalanan degerler listesi. Hata durumunda bos liste.
        """
        if not self._detected_debugger:
            debugger = self.detect_debugger()
            if not debugger:
                logger.warning("Debugger bulunamadi, yakalama yapilamaz")
                return []

        # Binary dogrulama: symlink coz, dosya ve executable kontrol
        binary_path = binary_path.resolve()
        if not binary_path.is_file():
            logger.error("Binary dosya degil: %s", binary_path)
            return []

        # Breakpoint address validation (injection onleme)
        import re
        _addr_re = re.compile(r'^(0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_:.]*)$')
        for bp in breakpoints:
            if not _addr_re.match(bp.address):
                logger.error("Gecersiz breakpoint adresi: %r", bp.address)
                return []

        # Breakpoint limiti
        max_bp = self._debugger_cfg.max_breakpoints
        if len(breakpoints) > max_bp:
            logger.warning(
                "Breakpoint sayisi (%d) limiti (%d) asiyor, ilk %d alinacak",
                len(breakpoints), max_bp, max_bp,
            )
            breakpoints = breakpoints[:max_bp]

        if not breakpoints:
            logger.info("Breakpoint listesi bos, yakalama atlanıyor")
            return []

        # Gecici cikti dosyasi
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_karadul_capture.json", delete=False,
        ) as tmp_out:
            output_path = Path(tmp_out.name)

        try:
            # Debugger turune gore script uret
            if self._detected_debugger == "lldb":
                script_path = self._generate_lldb_script(
                    breakpoints, binary_path, output_path,
                )
                cmd = [
                    "lldb",
                    "-b",                   # batch modu
                    "-o", f"command script import {script_path}",
                    "-o", "run",
                    "-o", "quit",
                    str(binary_path),
                ]
            else:
                script_path = self._generate_gdb_script(
                    breakpoints, binary_path, output_path,
                )
                cmd = [
                    "gdb",
                    "-batch",
                    "-x", str(script_path),
                    str(binary_path),
                ]

            # Argumanlari ekle
            if args:
                cmd.extend(["--"] + args)

            # Debugger'i calistir
            self._run_debugger(cmd, self._debugger_cfg.capture_timeout)

            # Sonuclari parse et
            return self._parse_output(output_path)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Debugger timeout (%ss), mevcut sonuclar donduruluyor",
                self._debugger_cfg.capture_timeout,
            )
            # Timeout olsa bile kismi sonuclar dosyaya yazilmis olabilir
            return self._parse_output(output_path)

        except FileNotFoundError:
            logger.error(
                "Debugger calistirilabilir dosyasi bulunamadi: %s",
                self._detected_debugger,
            )
            return []

        except Exception as exc:
            logger.error("Debugger calistirma hatasi: %s", exc)
            return []

        finally:
            # Gecici dosyalari temizle
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                script_path.unlink(missing_ok=True)
            except (OSError, NameError):
                pass

    # -----------------------------------------------------------------------
    # Script uretimi
    # -----------------------------------------------------------------------

    def _generate_lldb_script(
        self,
        breakpoints: list[BreakpointSpec],
        binary_path: Path,
        output_path: Path,
    ) -> Path:
        """LLDB Python capture script'i uret.

        Args:
            breakpoints: Breakpoint tanimlari.
            binary_path: Hedef binary (bilgi icin).
            output_path: JSON cikti dosyasi yolu.

        Returns:
            Uretilen script dosyasi yolu.
        """
        # v1.15-E B5: Whitelist validasyonu -- CWE-94 birinci savunma katmani.
        # Tum register/fonksiyon/adres degerleri Python kod uretiminden
        # ONCE strict regex ile kontrol edilir; gecersiz ise ValueError.
        bp_list, all_registers, max_stack_depth = self._validate_and_collect(breakpoints)

        # JSON serileme: ikinci savunma katmani (veri-kod ayrimi).
        config_json = json.dumps({
            "output_path": str(output_path),
            "max_captures": self._debugger_cfg.max_captures_per_bp,
            "registers": sorted(all_registers),
            "stack_depth": max_stack_depth,
            "breakpoints": bp_list,
        })

        script_content = _LLDB_SCRIPT_TEMPLATE.format(config_json=config_json)

        fd, script_path_str = tempfile.mkstemp(
            suffix="_karadul_lldb.py", prefix="karadul_",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_content)
        return Path(script_path_str)

    def _generate_gdb_script(
        self,
        breakpoints: list[BreakpointSpec],
        binary_path: Path,
        output_path: Path,
    ) -> Path:
        """GDB Python capture script'i uret.

        Args:
            breakpoints: Breakpoint tanimlari.
            binary_path: Hedef binary (bilgi icin).
            output_path: JSON cikti dosyasi yolu.

        Returns:
            Uretilen script dosyasi yolu.
        """
        # v1.15-E B5: LLDB ile ayni validasyon (kod tekrar tek metotta).
        bp_list, all_registers, max_stack_depth = self._validate_and_collect(breakpoints)

        config_json = json.dumps({
            "output_path": str(output_path),
            "max_captures": self._debugger_cfg.max_captures_per_bp,
            "registers": sorted(all_registers),
            "stack_depth": max_stack_depth,
            "breakpoints": bp_list,
        })

        script_content = _GDB_SCRIPT_TEMPLATE.format(config_json=config_json)

        fd, script_path_str = tempfile.mkstemp(
            suffix="_karadul_gdb.py", prefix="karadul_",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_content)
        return Path(script_path_str)

    # -----------------------------------------------------------------------
    # v1.15-E B5: Breakpoint/register whitelist validasyonu
    # -----------------------------------------------------------------------

    @staticmethod
    def _validate_and_collect(
        breakpoints: list[BreakpointSpec],
    ) -> tuple[list[dict], set[str], int]:
        """Tum breakpoint spec'lerini whitelist ile dogrula ve topla.

        Returns:
            ``(bp_list, all_registers, max_stack_depth)``.

        Raises:
            ValueError: gecersiz adres / fonksiyon adi / register adi.
        """
        bp_list: list[dict] = []
        all_registers: set[str] = set()
        max_stack_depth = 0

        for bp in breakpoints:
            # 1) breakpoint adresi
            if not _is_safe_address(bp.address):
                raise ValueError(
                    f"Gecersiz breakpoint adresi (whitelist disi): {bp.address!r}"
                )
            # 2) function_name (opsiyonel; None/"" mubah)
            if bp.function_name:
                if not _is_safe_identifier(bp.function_name):
                    raise ValueError(
                        f"Gecersiz fonksiyon adi (whitelist disi): "
                        f"{bp.function_name!r}"
                    )
            # 3) registers
            for reg in bp.capture.registers:
                if not _is_safe_identifier(reg):
                    raise ValueError(
                        f"Gecersiz register adi (whitelist disi): {reg!r}"
                    )

            bp_list.append({
                "address": bp.address,
                "function_name": bp.function_name or "",
            })
            all_registers.update(bp.capture.registers)
            max_stack_depth = max(max_stack_depth, bp.capture.stack_depth)

        return bp_list, all_registers, max_stack_depth

    # -----------------------------------------------------------------------
    # Debugger calistirma
    # -----------------------------------------------------------------------

    def _run_debugger(self, debugger_cmd: list[str], timeout: float) -> str:
        """Debugger komutunu calistir.

        Args:
            debugger_cmd: Calistirilacak komut listesi.
            timeout: Zaman asimi (saniye).

        Returns:
            Standart cikti (stdout).

        Raises:
            subprocess.TimeoutExpired: Zaman asimi.
            FileNotFoundError: Debugger bulunamadi.
            subprocess.CalledProcessError: Debugger hatasi.
        """
        logger.debug("Debugger komutu: %s", " ".join(debugger_cmd))

        # B21: safe_run -- LD_PRELOAD/DYLD env temizligi (CWE-114).
        # Debugger (lldb/gdb) binary'leri yukler; LD_PRELOAD ile attacker
        # debugger session'ina dylib enjekte edebilir, safe_env ile engellenir.
        result = safe_run(
            debugger_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.warning(
                "Debugger cikis kodu %d: %s",
                result.returncode,
                result.stderr[:500] if result.stderr else "(stderr bos)",
            )

        return result.stdout

    # -----------------------------------------------------------------------
    # Cikti parse
    # -----------------------------------------------------------------------

    def _parse_output(self, output_path: Path) -> list[CapturedValue]:
        """Debugger cikti JSON dosyasini parse et.

        Args:
            output_path: JSON dosya yolu.

        Returns:
            CapturedValue listesi. Dosya yoksa veya parse hatasi varsa bos liste.
        """
        if not output_path.exists():
            logger.debug("Cikti dosyasi bulunamadi: %s", output_path)
            return []

        try:
            raw = output_path.read_text(encoding="utf-8").strip()
            if not raw:
                return []

            data = json.loads(raw)
            if not isinstance(data, list):
                logger.warning("Beklenmeyen JSON yapisi (list degil)")
                return []

            captured: list[CapturedValue] = []
            for entry in data:
                try:
                    captured.append(CapturedValue(
                        address=str(entry.get("address", "0x0")),
                        function_name=entry.get("function_name") or None,
                        hit_count=int(entry.get("hit_count", 1)),
                        register_values=entry.get("register_values", {}),
                        stack_values=entry.get("stack_values", {}),
                        timestamp=float(entry.get("timestamp", 0.0)),
                    ))
                except (TypeError, ValueError) as exc:
                    logger.debug("Yakalama entry'si parse hatasi: %s", exc)

            logger.info("%d yakalama basariyla parse edildi", len(captured))
            return captured

        except json.JSONDecodeError as exc:
            logger.warning("JSON parse hatasi: %s", exc)
            return []
        except OSError as exc:
            logger.warning("Dosya okuma hatasi: %s", exc)
            return []

    # -----------------------------------------------------------------------
    # Tip dogrulama
    # -----------------------------------------------------------------------

    def verify_types(
        self,
        captured: list[CapturedValue],
        ghidra_types: dict[str, str],
    ) -> list[TypeVerification]:
        """Yakalanan runtime degerlerle Ghidra tip tahminlerini karsilastir.

        Her yakalanan deger icin:
        1. Register degerinden tip cikar (heuristik)
        2. Ghidra'nin tahmini tipiyle karsilastir
        3. Eslesme sonucu ve guven skoru uret

        Args:
            captured: Yakalanan degerler listesi.
            ghidra_types: register/degisken adi -> Ghidra tip tahmini eslesmesi.
                Ornek: {"rdi": "char *", "rsi": "int", "rax": "void *"}

        Returns:
            TypeVerification listesi.
        """
        if not captured or not ghidra_types:
            return []

        verifications: list[TypeVerification] = []

        for cap in captured:
            for reg_name, reg_value in cap.register_values.items():
                ghidra_type = ghidra_types.get(reg_name)
                if ghidra_type is None:
                    continue

                # Degeri int'e cevirmeye calis
                if isinstance(reg_value, str):
                    try:
                        numeric_value: int | str = int(reg_value, 0)
                    except (ValueError, TypeError):
                        numeric_value = reg_value
                else:
                    numeric_value = reg_value

                # Tip cikar
                inferred_type, infer_confidence = _infer_type_from_value(numeric_value)

                # Ghidra tipiyle karsilastir
                match, match_confidence = _types_compatible(ghidra_type, inferred_type)

                # Nihai guven: cikarim guveni * eslesme guveni
                final_confidence = round(infer_confidence * match_confidence, 3)

                verifications.append(TypeVerification(
                    function_name=cap.function_name or cap.address,
                    variable_name=reg_name,
                    ghidra_type=ghidra_type,
                    runtime_value=numeric_value,
                    inferred_type=inferred_type,
                    match=match,
                    confidence=final_confidence,
                ))

        return verifications
