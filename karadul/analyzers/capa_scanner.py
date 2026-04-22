"""CAPA capability detection entegrasyonu.

Mandiant CAPA, binary dosyalari analiz edip her fonksiyonun ne yaptigini
tespit eder: network communication, encrypt data, create file, anti-debug, vb.
1000+ kural ile calisan acik kaynak capability detection araci.

Karadul'da kullanim:
1. Binary'deki fonksiyonlarin capability'lerini tespit et
2. Naming pipeline'ina hint olarak ver (capability -> fonksiyon adi)
3. Comment generation'da @capability annotasyonu ekle

CAPA kurulu degilse (flare-capa paketi) graceful skip yapar.
Pipeline'in geri kalani aynen calisir.

Kullanim:
    scanner = CAPAScanner()
    results = scanner.scan(Path("/path/to/binary"))
    # results: {
    #   "0x1000": ["network communication", "encrypt data using AES"],
    #   "0x2000": ["create mutex"],
    # }
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.core.safe_subprocess import resolve_tool, safe_run

logger = logging.getLogger(__name__)

# Varsayilan capa kurallarinin bulundugu dizin
DEFAULT_RULES_PATH = Path.home() / ".cache" / "karadul" / "capa-rules"

# Timeout: buyuk binary'lerde capa yavas olabilir
DEFAULT_TIMEOUT_SECONDS = 600

# Harici CAPA namespace -> fonksiyon ismi haritasi (resources/capa_name_map.json)
# Lazy-load + cache: bir kere okunur, sonra bellekte kalir.
_NAME_MAP_JSON_PATH = Path(__file__).resolve().parent.parent / "resources" / "capa_name_map.json"
_EXTERNAL_NAME_MAP_CACHE: dict[str, str] | None = None


def _normalize_addr(addr: str | int) -> str:
    """CAPA adres stringini kanonik forma cevir.

    Kanonik form: lowercase hex, '0x' prefix YOK, minimum 8 hex (zfill).
    Boyle bir padding sayesinde `"0x401234"`, `"401234"`, `"0x00401234"`
    tumunun karsiligi `"00401234"` olur ve ghidra_functions.json
    anahtarlariyla (genelde `"0x00401234"` ya da `"00401234"` seklinde
    yazilan) dogru eslesir.

    64-bit adresler (16 hex) dokunulmaz halde kalir; yalnizca 8'den kucuk
    olanlar 8 hex'e padlenir. `int` verilirse hex'e cevrilir.
    """
    if isinstance(addr, int):
        s = f"{addr:x}"
    else:
        s = str(addr).strip().lower()
    # 0x prefix'leri (varsa birden fazla) temizle
    while s.startswith("0x"):
        s = s[2:]
    # Leading zero'lari silip en az 8 hex'e padle (64-bit 16 hex ise koru)
    s = s.lstrip("0") or "0"
    if len(s) <= 8:
        s = s.zfill(8)
    return s


def _load_external_name_map() -> dict[str, str]:
    """resources/capa_name_map.json'u yukle (lazy + cache'li).

    Dosya yoksa bos dict doner. Bu sayede `capa_name_map.json`
    deployment'ta eksik olsa bile CAPAScanner patlamaz.
    """
    global _EXTERNAL_NAME_MAP_CACHE
    if _EXTERNAL_NAME_MAP_CACHE is not None:
        return _EXTERNAL_NAME_MAP_CACHE
    try:
        if _NAME_MAP_JSON_PATH.is_file():
            with _NAME_MAP_JSON_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _EXTERNAL_NAME_MAP_CACHE = {
                    str(k): str(v) for k, v in data.items()
                    if isinstance(v, str)
                }
            else:
                _EXTERNAL_NAME_MAP_CACHE = {}
        else:
            _EXTERNAL_NAME_MAP_CACHE = {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("capa_name_map.json yuklenemedi: %s", exc)
        _EXTERNAL_NAME_MAP_CACHE = {}
    return _EXTERNAL_NAME_MAP_CACHE


def _reset_external_name_map_cache() -> None:
    """Test yardimcisi: cache'i sifirla (JSON'u tekrar yukletmek icin)."""
    global _EXTERNAL_NAME_MAP_CACHE
    _EXTERNAL_NAME_MAP_CACHE = None

# Capability isimlerini C fonksiyon isimlerine cevirirken kullanilan
# ozel isimlendirme tablosu.  Genel pattern:
#   "encrypt data using AES"  ->  "aes_encrypt_handler"
#   "send HTTP request"       ->  "http_request_handler"
#   "create mutex"            ->  "mutex_create_handler"
# Tabloda olmayan capability'ler generic kurala gore isimlendirilir.
_CAPABILITY_NAME_MAP: dict[str, str] = {
    # -- Crypto --
    "encrypt data using AES": "aes_encrypt",
    "encrypt data using DES": "des_encrypt",
    "encrypt data using RC4": "rc4_encrypt",
    "encrypt data using Blowfish": "blowfish_encrypt",
    "encrypt data using Camellia": "camellia_encrypt",
    "hash data using SHA256": "sha256_hash",
    "hash data using SHA1": "sha1_hash",
    "hash data using MD5": "md5_hash",
    "hash data using CRC32": "crc32_compute",
    "hash data using SHA512": "sha512_hash",
    "generate random numbers using the Mersenne Twister": "mersenne_twister_rng",
    "encrypt data using AES via WinAPI": "aes_encrypt_winapi",
    "encrypt data using RSA": "rsa_encrypt",
    # -- Network --
    "send HTTP request": "http_request_send",
    "send data": "network_send_data",
    "receive data": "network_recv_data",
    "create TCP socket": "tcp_socket_create",
    "create UDP socket": "udp_socket_create",
    "connect to URL": "url_connect",
    "download URL to file": "url_download_to_file",
    "encode data using Base64": "base64_encode",
    "decode data using Base64": "base64_decode",
    "send DNS query": "dns_query_send",
    # -- File I/O --
    "create file": "file_create",
    "delete file": "file_delete",
    "read file": "file_read",
    "write file": "file_write",
    "move file": "file_move",
    "copy file": "file_copy",
    "get file attributes": "file_get_attributes",
    "enumerate files": "file_enumerate",
    "find file": "file_find",
    # -- Process --
    "create process": "process_create",
    "terminate process": "process_terminate",
    "create mutex": "mutex_create",
    "create thread": "thread_create",
    "create pipe": "pipe_create",
    "inject thread": "thread_inject",
    "allocate RWX memory": "memory_alloc_rwx",
    # -- Registry --
    "query or enumerate registry value": "registry_query",
    "set registry value": "registry_set",
    "delete registry key": "registry_delete",
    # -- Anti-analysis --
    "check for debugger": "debugger_check",
    "check for sandbox": "sandbox_check",
    "check for VM": "vm_check",
    "obfuscate data": "data_obfuscate",
    # -- Persistence --
    "persist via Windows service": "service_persist",
    "modify service": "service_modify",
    "schedule task": "task_schedule",
    # -- Compression --
    "compress data": "data_compress",
    "decompress data": "data_decompress",
    "compress data using LZO": "lzo_compress",
    "compress data using LZMA": "lzma_compress",
    "decompress data using aPLib": "aplib_decompress",
}


@dataclass
class CAPACapability:
    """Tek bir CAPA capability eslesmesi."""
    name: str
    namespace: str = ""
    description: str = ""
    attack: list[dict[str, str]] = field(default_factory=list)
    mbc: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.namespace:
            d["namespace"] = self.namespace
        if self.description:
            d["description"] = self.description
        if self.attack:
            d["attack"] = self.attack
        if self.mbc:
            d["mbc"] = self.mbc
        return d


@dataclass
class CAPAScanResult:
    """CAPA scan sonucu.

    Iki paralel anahtarlama destekler:
    - `function_capabilities`: adres -> capability listesi (CAPA'nin native formatı)
    - `capability_by_funcname`: fonksiyon ismi -> capability listesi (pipeline icin)

    Reconstruction pipeline'i fonksiyon ismiyle calistigi icin,
    `capability_by_funcname` gecilecek ghidra functions_data sayesinde doldurulur.
    Eger `functions_data` verilmezse `capability_by_funcname` bos kalir (graceful).
    """
    success: bool = False
    # func_address (hex str) -> capability listesi (CAPA native)
    function_capabilities: dict[str, list[CAPACapability]] = field(default_factory=dict)
    # function_name -> capability listesi (reconstruction pipeline icin)
    capability_by_funcname: dict[str, list[CAPACapability]] = field(default_factory=dict)
    # file-level capability'ler (fonksiyona bagli olmayan)
    file_capabilities: list[CAPACapability] = field(default_factory=list)
    total_rules_matched: int = 0
    total_functions_matched: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    format_: str = ""
    arch: str = ""
    os_: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "total_rules_matched": self.total_rules_matched,
            "total_functions_matched": self.total_functions_matched,
            "duration_seconds": round(self.duration_seconds, 2),
            "format": self.format_,
            "arch": self.arch,
            "os": self.os_,
            "function_capabilities": {
                addr: [c.to_dict() for c in caps]
                for addr, caps in self.function_capabilities.items()
            },
            "capability_by_funcname": {
                fname: [c.to_dict() for c in caps]
                for fname, caps in self.capability_by_funcname.items()
            },
            "file_capabilities": [c.to_dict() for c in self.file_capabilities],
            "errors": self.errors,
        }


class CAPAScanner:
    """CAPA capability detection scanner.

    Binary dosyayi CAPA ile tarar, her fonksiyon icin tespit edilen
    capability'leri dondurur.

    Iki mod destekler:
    1. Python API (programatik): capa kutuphaneleri import edilir, in-process calisir
    2. CLI fallback (subprocess): capa CLI JSON ciktisi parse edilir

    Python API tercih edilir (daha hizli), CLI fallback olarak kullanilir.
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        """CAPA kurallarini yukle.

        Args:
            rules_path: CAPA kurallarinin bulundugu dizin.
                None ise DEFAULT_RULES_PATH kullanilir.
            timeout: Scan timeout (saniye). Buyuk binary'ler icin 600s.
        """
        if rules_path is not None:
            self._rules_path = Path(rules_path)
        else:
            self._rules_path = DEFAULT_RULES_PATH
        self._timeout = timeout
        self._capa_available: bool | None = None  # lazy check
        self._cli_path: str | None = None
        # PERF (v1.10.0 H12): rglob sonucunu cache'le.
        # is_available() birden fazla kez cagirilabildiginden eskiden
        # 1000+ .yml dosyasi her cagrida tekrar tariandi.
        self._yml_count: int | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """CAPA kullanilabilir mi kontrol et (kural + binary/modul)."""
        if self._capa_available is not None:
            return self._capa_available

        # Kural dizini kontrolu
        if not self._rules_path.is_dir():
            logger.debug(
                "CAPA kurallar dizini bulunamadi: %s", self._rules_path,
            )
            self._capa_available = False
            return False

        # En az birkac .yml dosyasi olmali (cached -- v1.10.0 H12)
        if self._yml_count is None:
            self._yml_count = sum(1 for _ in self._rules_path.rglob("*.yml"))
        yml_count = self._yml_count
        if yml_count < 10:
            logger.debug(
                "CAPA kurallar dizininde yeterli kural yok (%d < 10): %s",
                yml_count, self._rules_path,
            )
            self._capa_available = False
            return False

        # v1.10.0 Batch 5B CRITICAL-2: resolve_tool ile PATH hijack koruma.
        cli = resolve_tool("capa")
        if cli:
            self._cli_path = cli
            self._capa_available = True
            logger.debug("CAPA CLI bulundu: %s (%d kural)", cli, yml_count)
            return True

        # Python API mevcut mu?
        try:
            import capa.rules  # noqa: F401
            import capa.loader  # noqa: F401
            self._capa_available = True
            logger.debug("CAPA Python API mevcut (%d kural)", yml_count)
            return True
        except ImportError:
            pass

        logger.debug("CAPA ne CLI ne Python API mevcut degil")
        self._capa_available = False
        return False

    def scan(
        self,
        binary_path: Path,
        functions_data: dict[str, Any] | None = None,
    ) -> CAPAScanResult:
        """Binary'yi tara, fonksiyon -> capability listesi dondur.

        Args:
            binary_path: Taranacak binary dosya yolu.
            functions_data: Opsiyonel ghidra functions.json indeksi:
                `{normalized_addr: {"name": "...", ...}}` seklinde.
                Verildiginde sonuca `capability_by_funcname` da eklenir.
                None ise sadece adres bazli `function_capabilities` doldurulur.

        Returns:
            CAPAScanResult: Scan sonuclari.
        """
        if not self.is_available():
            return CAPAScanResult(
                success=False,
                errors=["CAPA mevcut degil veya kurallar bulunamadi"],
            )

        if not binary_path.exists():
            return CAPAScanResult(
                success=False,
                errors=[f"Binary bulunamadi: {binary_path}"],
            )

        start = time.monotonic()

        # CLI varsa onu tercih et (tum format'lari destekler)
        if self._cli_path:
            result = self._scan_via_cli(binary_path)
        else:
            result = self._scan_via_api(binary_path)

        # Fonksiyon ismi indeksini doldur (functions_data varsa)
        if functions_data is not None and result.success:
            result.capability_by_funcname = self._build_funcname_index(
                result.function_capabilities, functions_data,
            )

        result.duration_seconds = time.monotonic() - start
        return result

    def _build_funcname_index(
        self,
        function_capabilities: dict[str, list[CAPACapability]],
        functions_data: dict[str, Any],
    ) -> dict[str, list[CAPACapability]]:
        """Address-keyed capability'leri function-name-keyed'e cevir.

        Her adres iki yolla aranir:
        1. `_normalize_addr(addr)` ile kanonik form
        2. Ham addr stringi (functions_data dogrudan CAPA formatinda ise)

        `functions_data` degerleri dict olmali; `"name"` yoksa `FUN_<addr>`
        duserek fallback uretilir (ghidra'nin default isimlendirmesi).
        Baska formatlar (ornegin `{addr: "name_str"}`) da tolere edilir.
        """
        name_index: dict[str, list[CAPACapability]] = {}
        if not isinstance(functions_data, dict):
            return name_index

        # functions_data'nin anahtarlarini da normalize et (hizli lookup icin)
        normalized_fd: dict[str, Any] = {}
        for k, v in functions_data.items():
            try:
                normalized_fd[_normalize_addr(k)] = v
            except Exception:
                # Anahtar hex degil — orijinaliyle kal
                normalized_fd[str(k).lower()] = v

        for addr_str, caps in function_capabilities.items():
            if not caps:
                continue
            try:
                norm = _normalize_addr(addr_str)
            except Exception:
                norm = str(addr_str).lower()

            fn_entry = normalized_fd.get(norm)
            if fn_entry is None:
                # Fallback: functions_data'da bu adres yok — FUN_xxx ismi ver
                fname = f"FUN_{norm}"
            elif isinstance(fn_entry, dict):
                fname = fn_entry.get("name") or f"FUN_{norm}"
            elif isinstance(fn_entry, str):
                fname = fn_entry
            else:
                fname = f"FUN_{norm}"

            name_index.setdefault(fname, []).extend(caps)

        return name_index

    def get_function_names(
        self,
        scan_result: CAPAScanResult,
    ) -> dict[str, str]:
        """CAPA capability'lerinden fonksiyon isim onerileri uret.

        En spesifik (en uzun namespace'li) capability'yi secer,
        onu C fonksiyon ismine cevirir.

        Args:
            scan_result: scan() sonucu.

        Returns:
            {func_address: "suggested_function_name"}
        """
        names: dict[str, str] = {}
        for addr, capabilities in scan_result.function_capabilities.items():
            if not capabilities:
                continue
            # En spesifik capability: namespace en uzun olan veya
            # isim en uzun olan (daha detayli = daha iyi isim)
            best = max(
                capabilities,
                key=lambda c: (len(c.namespace), len(c.name)),
            )
            name = capability_to_function_name(best.name)
            if name:
                names[addr] = name
        return names

    def get_capability_comments(
        self,
        scan_result: CAPAScanResult,
    ) -> dict[str, list[str]]:
        """CAPA capability'lerinden fonksiyon yorum satirlari uret.

        Args:
            scan_result: scan() sonucu.

        Returns:
            {func_address: ["@capability network communication", ...]}
        """
        comments: dict[str, list[str]] = {}
        for addr, capabilities in scan_result.function_capabilities.items():
            lines = []
            for cap in capabilities:
                line = f"@capability {cap.name}"
                if cap.attack:
                    # MITRE ATT&CK taktik/teknik bilgisi
                    tactics = ", ".join(
                        a.get("technique", a.get("tactic", ""))
                        for a in cap.attack
                        if a.get("technique") or a.get("tactic")
                    )
                    if tactics:
                        line += f" [ATT&CK: {tactics}]"
                lines.append(line)
            if lines:
                comments[addr] = lines
        return comments

    # ------------------------------------------------------------------
    # CLI scan
    # ------------------------------------------------------------------

    def _scan_via_cli(self, binary_path: Path) -> CAPAScanResult:
        """capa CLI ile JSON ciktisi al ve parse et.

        PERF/MEM (v1.10.0 C6): Eskiden `capture_output=True` ile tum JSON
        (100+ MB olabilir) stdout uzerinden Python bellegine aktariliyordu.
        Yeni versiyon `-o/--output-file` flag'ini kullanip diske yazdirir,
        sonra dosyayi stream ile okur. Subprocess stderr hala yakalanir
        (kucuk, hata mesaji icin), stdout `DEVNULL`'a yonlendirilir.
        """
        # CAPA cikti dosyasi: binary ile ayni dizinde gecici dosya
        import tempfile as _tempfile
        tmp_out = _tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="capa_out_",
            delete=False, encoding="utf-8",
        )
        tmp_out.close()
        output_file = Path(tmp_out.name)

        cmd = [
            self._cli_path,
            str(binary_path),
            "-j",                                # JSON output
            "-r", str(self._rules_path),         # kural dizini
            "-q",                                # quiet (progress bar yok)
            "-o", str(output_file),              # JSON dosyaya yaz (stdout degil)
        ]

        logger.info("CAPA CLI calistiriliyor: %s", " ".join(cmd))

        try:
            # v1.10.0 Batch 5B MED-19: stderr unbounded koruma.
            # stderr text=True + PIPE -> rich Python string build, kotu
            # durumda ~1GB olabilir. Bytes mode okuyup cap uyguluyoruz.
            proc = safe_run(
                cmd,
                stdout=subprocess.DEVNULL,          # stdout bellege almama
                stderr=subprocess.PIPE,             # stderr byte mode
                text=False,
                timeout=self._timeout,
            )
            # stderr kap limitle, unicode-decode errors replace
            _stderr_cap = 1 * 1024 * 1024  # 1MB, SecurityConfig ile uyumlu
            _raw_stderr = proc.stderr or b""
            if len(_raw_stderr) > _stderr_cap:
                logger.warning(
                    "CAPA stderr %d > cap %d, kirpiliyor", len(_raw_stderr), _stderr_cap,
                )
                _raw_stderr = _raw_stderr[:_stderr_cap]
            # proc.stderr (str) alanini override et downstream caller'lar icin
            proc_stderr_decoded = _raw_stderr.decode("utf-8", errors="replace")
            # Yeniden atamak icin CompletedProcess'in stderr'ini override
            # bir namedtuple degil, basit attribute; direkt yazabiliriz.
            try:
                proc.stderr = proc_stderr_decoded
            except AttributeError:
                pass
        except subprocess.TimeoutExpired:
            try:
                output_file.unlink(missing_ok=True)
            except OSError:
                pass
            return CAPAScanResult(
                success=False,
                errors=[
                    f"CAPA timeout ({self._timeout}s) -- "
                    f"binary cok buyuk olabilir: {binary_path.name}",
                ],
            )
        except FileNotFoundError:
            try:
                output_file.unlink(missing_ok=True)
            except OSError:
                pass
            return CAPAScanResult(
                success=False,
                errors=["capa CLI bulunamadi"],
            )

        try:
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                # Bazi hatalar beklenen: format desteklenmiyor vb.
                if "UnsupportedFormatError" in stderr or "not appear to be a supported" in stderr:
                    return CAPAScanResult(
                        success=False,
                        errors=[
                            f"CAPA bu binary formatini desteklemiyor: "
                            f"{binary_path.name} (sadece PE/ELF/shellcode)"
                        ],
                    )
                return CAPAScanResult(
                    success=False,
                    errors=[f"CAPA CLI hatasi (exit {proc.returncode}): {stderr[:500]}"],
                )

            # JSON parse -- dosyadan stream
            try:
                if not output_file.exists() or output_file.stat().st_size == 0:
                    return CAPAScanResult(
                        success=False,
                        errors=["CAPA bos cikti uretti"],
                    )
                with output_file.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                return CAPAScanResult(
                    success=False,
                    errors=[f"CAPA JSON parse hatasi: {exc}"],
                )

            return self._parse_json_output(data)
        finally:
            try:
                output_file.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Python API scan (fallback)
    # ------------------------------------------------------------------

    def _scan_via_api(self, binary_path: Path) -> CAPAScanResult:
        """capa Python API ile in-process scan."""
        try:
            import capa.rules as capa_rules
            import capa.rules.cache  # noqa: F401 -- side-effect import
            import capa.loader
            import capa.main as capa_main
            import capa.render.json as capa_json
        except ImportError as exc:
            return CAPAScanResult(
                success=False,
                errors=[f"CAPA Python modulu import edilemedi: {exc}"],
            )

        # Kurallari yukle
        try:
            ruleset = capa_rules.get_rules([self._rules_path])
        except Exception as exc:
            return CAPAScanResult(
                success=False,
                errors=[f"CAPA kural yukleme hatasi: {exc}"],
            )

        # Extractor olustur
        try:
            extractor = capa.loader.get_extractor(
                input_path=binary_path,
                input_format="auto",
                os_="auto",
                backend="auto",
                sigpaths=[],
                disable_progress=True,
            )
        except Exception as exc:
            return CAPAScanResult(
                success=False,
                errors=[f"CAPA extractor hatasi (format desteklenmiyor olabilir): {exc}"],
            )

        # Capability'leri bul
        try:
            capabilities = capa_main.find_capabilities(
                ruleset, extractor, disable_progress=True,
            )
        except Exception as exc:
            return CAPAScanResult(
                success=False,
                errors=[f"CAPA analiz hatasi: {exc}"],
            )

        # JSON render et ve parse et (en stabil format)
        try:
            meta = capa.loader.collect_metadata(
                argv=[],
                input_path=binary_path,
                input_format="auto",
                os_="auto",
                rules_path=[self._rules_path],
                extractor=extractor,
                capabilities=capabilities,
            )
            json_str = capa_json.render(meta, ruleset, capabilities.matches)
            data = json.loads(json_str)
            return self._parse_json_output(data)
        except Exception as exc:
            # JSON render basarisiz olursa ham capabilities'den parse et
            logger.warning("CAPA JSON render hatasi, ham parse deneniyor: %s", exc)
            return self._parse_raw_capabilities(capabilities, ruleset)

    # ------------------------------------------------------------------
    # JSON parsing
    # ------------------------------------------------------------------

    def _parse_json_output(self, data: dict[str, Any]) -> CAPAScanResult:
        """CAPA JSON ciktisini parse et.

        CAPA JSON formati (v9.x):
        {
            "meta": {
                "analysis": {
                    "format": "pe",
                    "arch": "amd64",
                    "os": "windows",
                    "layout": {
                        "functions": [
                            {"address": {"type": "absolute", "value": 4096},
                             "matched_basic_blocks": [...]}
                        ]
                    }
                }
            },
            "rules": {
                "rule name": {
                    "meta": {
                        "name": "...",
                        "namespace": "...",
                        "description": "...",
                        "attack": [...],
                        "mbc": [...]
                    },
                    "matches": [
                        [{"type": "absolute", "value": 4096}, {...}],
                        ...
                    ]
                }
            }
        }
        """
        result = CAPAScanResult(success=True)

        # Meta bilgileri
        meta = data.get("meta", {})
        analysis = meta.get("analysis", {})
        if isinstance(analysis, dict):
            result.format_ = analysis.get("format", "")
            result.arch = analysis.get("arch", "")
            result.os_ = analysis.get("os", "")

        # Kurallari isle
        rules = data.get("rules", {})
        result.total_rules_matched = len(rules)

        for _rule_name, rule_data in rules.items():
            rule_meta = rule_data.get("meta", {})
            cap_name = rule_meta.get("name", _rule_name)
            namespace = rule_meta.get("namespace", "")
            description = rule_meta.get("description", "")
            lib_rule = rule_meta.get("lib", False)

            # Lib kurallarini atla (dahili bagimliliklar, kullanici icin ilginc degil)
            if lib_rule:
                continue

            # ATT&CK ve MBC mapping
            attack = []
            for a in rule_meta.get("attack", []):
                if isinstance(a, dict):
                    attack.append(a)

            mbc = []
            for m in rule_meta.get("mbc", []):
                if isinstance(m, dict):
                    mbc.append(m)

            cap = CAPACapability(
                name=cap_name,
                namespace=namespace,
                description=description,
                attack=attack,
                mbc=mbc,
            )

            # Her eslestirmenin adresine bak
            matches = rule_data.get("matches", [])
            has_function_match = False

            for match_entry in matches:
                # match_entry: [address_dict, match_details]
                if not isinstance(match_entry, (list, tuple)) or len(match_entry) < 1:
                    continue

                addr_info = match_entry[0]
                if isinstance(addr_info, dict):
                    addr_type = addr_info.get("type", "")
                    addr_value = addr_info.get("value", 0)

                    if addr_type in ("absolute", "relative"):
                        # Fonksiyon adresi
                        addr_hex = f"0x{addr_value:x}" if isinstance(addr_value, int) else str(addr_value)
                        result.function_capabilities.setdefault(addr_hex, []).append(cap)
                        has_function_match = True
                    elif addr_type == "no address":
                        # File-level capability
                        result.file_capabilities.append(cap)
                        has_function_match = True

            if not has_function_match:
                # Adres bilgisi cikarilamamissa file-level'a ekle
                result.file_capabilities.append(cap)

        result.total_functions_matched = len(result.function_capabilities)
        return result

    def _parse_raw_capabilities(self, capabilities: Any, ruleset: Any) -> CAPAScanResult:
        """Ham capa Capabilities objesinden minimal parse.

        JSON render basarisiz oldugunda fallback olarak kullanilir.
        """
        result = CAPAScanResult(success=True)

        try:
            for rule_name, match_list in capabilities.matches.items():
                if rule_name not in ruleset.rules:
                    continue
                rule = ruleset.rules[rule_name]
                if getattr(rule.meta, "lib", False):
                    continue

                cap = CAPACapability(
                    name=rule_name,
                    namespace=getattr(rule.meta, "namespace", "") or "",
                )

                for addr, _match in match_list:
                    addr_val = getattr(addr, "v", getattr(addr, "value", 0))
                    if addr_val:
                        addr_hex = f"0x{addr_val:x}"
                        result.function_capabilities.setdefault(addr_hex, []).append(cap)
                    else:
                        result.file_capabilities.append(cap)

            result.total_rules_matched = len(capabilities.matches)
            result.total_functions_matched = len(result.function_capabilities)
        except Exception as exc:
            result.errors.append(f"Ham capabilities parse hatasi: {exc}")

        return result


# -----------------------------------------------------------------------
# Utility: capability ismi -> C fonksiyon ismi donusumu
# -----------------------------------------------------------------------

def capability_to_function_name(capability: str) -> str:
    """CAPA capability ismini C fonksiyon ismine donustur.

    Strateji (oncelik sirasi):
    1. Dahili `_CAPABILITY_NAME_MAP` (kod icinde tanimli, en guvenilir)
    2. Harici `resources/capa_name_map.json` (lazy load, cache'li)
       - CAPA namespace/rule path formatini destekler:
         ornegin `"crypto/aes/encrypt"` -> `"aes_encrypt_block"`
    3. Generic heuristic donusum:
       - Kucuk harfe cevir
       - "using X" / "via X" pattern'lerini one al
       - Ozel karakterleri '_' ile degistir
       - Max 63 karakter (C identifier limit)

    Examples:
        "encrypt data using AES"     -> "aes_encrypt"       (dahili)
        "crypto/aes/encrypt"         -> "aes_encrypt_block" (JSON)
        "send HTTP request"          -> "http_request_send" (dahili)
        "create mutex"               -> "mutex_create"      (dahili)
        "check for debugger"         -> "debugger_check"    (dahili)
        "obfuscated with Base64"     -> "base64_obfuscated" (heuristic)
    """
    # 1) Bilinen dahili mapping
    if capability in _CAPABILITY_NAME_MAP:
        return _CAPABILITY_NAME_MAP[capability]

    # 2) Harici JSON mapping (capa_name_map.json) - kanonikleştirilmiş anahtarlar
    external = _load_external_name_map()
    if external:
        # Direkt eslesme
        if capability in external:
            return external[capability]
        # Namespace path formatini normalize ederek dene
        cap_lower = capability.lower().strip()
        if cap_lower in external:
            return external[cap_lower]

    # 3) Generic donusum
    name = capability.lower().strip()

    # "using X" pattern'ini onde al: "encrypt data using AES" -> "aes_encrypt_data"
    using_match = re.search(r"\busing\s+(\w+)", name)
    if using_match:
        prefix = using_match.group(1)
        rest = name[:using_match.start()].strip()
        rest = re.sub(r"[^a-z0-9]+", "_", rest).strip("_")
        name = f"{prefix}_{rest}"
    else:
        # "via X" pattern'i
        via_match = re.search(r"\bvia\s+(\w+)", name)
        if via_match:
            prefix = via_match.group(1)
            rest = name[:via_match.start()].strip()
            rest = re.sub(r"[^a-z0-9]+", "_", rest).strip("_")
            name = f"{prefix}_{rest}"
        else:
            # Genel temizlik
            name = re.sub(r"[^a-z0-9]+", "_", name).strip("_")

    # Art arda underscore temizle
    name = re.sub(r"_+", "_", name)

    # C identifier limiti
    if len(name) > 63:
        name = name[:63].rstrip("_")

    # Sayi ile basliyorsa prefix ekle
    if name and name[0].isdigit():
        name = "cap_" + name

    return name


def rank_capabilities(capabilities: list[CAPACapability]) -> list[CAPACapability]:
    """Capability'leri spesifiklik sirasina gore sirala.

    En spesifik capability isim icin en iyi aday:
    - Daha uzun namespace = daha spesifik
    - ATT&CK mapping'i olan = daha bilgilendirici
    - Daha uzun isim = genellikle daha detayli
    """
    def _score(cap: CAPACapability) -> tuple[int, int, int]:
        return (
            len(cap.namespace.split("/")) if cap.namespace else 0,
            len(cap.attack),
            len(cap.name),
        )
    return sorted(capabilities, key=_score, reverse=True)
