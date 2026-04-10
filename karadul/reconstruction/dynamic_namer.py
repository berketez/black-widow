"""Frida dinamik analiz izlerinden degisken isimlendirme -- Karadul v1.8.7

Frida trace_report.json dosyasini okuyarak, runtime'da gozlemlenen API
cagrilarindan decompile edilmis C kodundaki generic parametrelere
(param_1, local_XX) anlamli isimler onerir.

Bu modul PASIF bir tuketicidir -- Frida calistirmaz, sadece mevcut
trace verisini okur ve isim onerisi uretir.

Tasarim:
  - trace_report.json'daki api_calls listesinden hangi API'lerin
    runtime'da cagrildigini cikarir
  - APIParamDB ile eslestirerek param_1 -> "sockfd" gibi oneriler uretir
  - Runtime verisine dayandigi icin confidence yuksektir (0.85-0.90)
  - Trace yoksa sessizce bos sonuc doner

Kullanim:
    from karadul.reconstruction.dynamic_namer import DynamicNamer

    namer = DynamicNamer(Path("workspace/dynamic/trace_report.json"))
    if namer.load_trace():
        suggestions = namer.infer_names("FUN_00401000", c_code)
        types = namer.infer_types("FUN_00401000")
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.reconstruction.api_param_db import APIParamDB

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------

@dataclass
class DynamicNameSuggestion:
    """Runtime trace'den turetilmis isim onerisi."""

    var_name: str           # param_1, local_10, etc.
    suggested_name: str     # "fd", "buffer", "size"
    confidence: float       # 0.0-1.0
    source: str             # "frida_api_trace", "frida_type_inference"
    evidence: str           # "send(param_1, param_2, param_3) called at runtime"


# ---------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------

# Generic degisken isimleri pattern'i -- sadece bunlari rename et
_GENERIC_VAR_RE = re.compile(
    r'^(param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|in_\w+|uVar\d+|iVar\d+|lVar\d+|sVar\d+|bVar\d+|cVar\d+|pvVar\d+|ppvVar\d+|pcVar\d+|piVar\d+|puVar\d+|plVar\d+)$'
)

# Runtime deger araliklari -- tip cikarimi icin
_POINTER_THRESHOLD = 0x1000        # Bu adresin ustu pointer
_CHAR_RANGE = (0x20, 0x7e)         # Yazdirilabilir ASCII
_SMALL_INT_MAX = 0xffff            # size_t/int olasiligi yuksek
_NEGATIVE_MASK = 0x80000000        # 32-bit signed negatif kontrol

# Confidence degerleri -- runtime verisi guvenilirdir
_CONF_API_TRACE = 0.88             # API param eslestirme
_CONF_API_TRACE_INDIRECT = 0.82    # Dolayli eslestirme (isim cakismasi)
_CONF_TYPE_INFERENCE = 0.70        # Deger-bazli tip cikarimi
_CONF_FILE_ACCESS = 0.85           # Dosya erisiminden cikarim
_CONF_CRYPTO_OP = 0.85             # Crypto isleminden cikarim


# ---------------------------------------------------------------
# DynamicNamer
# ---------------------------------------------------------------

class DynamicNamer:
    """Frida trace verisinden degisken isim onerisi ureten modul.

    Sadece trace_report.json okur, Frida calistirmaz.
    Trace yoksa tum metodlar bos sonuc doner.
    """

    def __init__(self, trace_report_path: Path | None = None) -> None:
        self._trace_path = Path(trace_report_path) if trace_report_path else None
        self._trace_data: dict[str, Any] | None = None
        self._api_db = APIParamDB()
        self._loaded = False

        # Trace'den cikarilan ozet veriler
        self._api_call_names: list[str] = []
        self._api_call_records: list[dict] = []
        self._file_accesses: list[dict] = []
        self._crypto_ops: list[dict] = []
        self._env_accesses: list[dict] = []
        self._unique_modules: list[str] = []
        self._call_sequence: list[dict] = []

        # Onbellek: fonksiyon_adi -> oneriler
        self._cache: dict[str, list[DynamicNameSuggestion]] = {}

    # ----------------------------------------------------------
    # Yukleme
    # ----------------------------------------------------------

    def load_trace(self) -> bool:
        """trace_report.json dosyasini yukle.

        Returns:
            True: Basariyla yuklendi.
            False: Dosya yok, okunamiyor veya gecersiz JSON.
        """
        if self._trace_path is None:
            logger.debug("DynamicNamer: trace_report_path verilmedi")
            return False

        if not self._trace_path.exists():
            logger.debug("DynamicNamer: trace dosyasi yok: %s", self._trace_path)
            return False

        try:
            raw = self._trace_path.read_text(encoding="utf-8")
            self._trace_data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("DynamicNamer: trace dosyasi okunamiyor: %s", exc)
            return False

        if not isinstance(self._trace_data, dict):
            logger.warning("DynamicNamer: trace dosyasi dict degil")
            self._trace_data = None
            return False

        # Ozet verileri cikar
        self._extract_trace_summary()
        self._loaded = True

        logger.info(
            "DynamicNamer: trace yuklendi -- %d API call, %d dosya erisimi, "
            "%d crypto op, %d modul",
            len(self._api_call_names),
            len(self._file_accesses),
            len(self._crypto_ops),
            len(self._unique_modules),
        )
        return True

    def _extract_trace_summary(self) -> None:
        """Trace verisinden ozet bilgileri cikar.

        FunctionTracer.to_json() formati:
            {
                "total_calls": int,
                "unique_modules": [...],
                "stats": {...},
                "api_calls": [{"name": ..., "args": ..., ...}, ...],
                "file_accesses": [{"name": ..., "args": ..., ...}, ...],
                "crypto_operations": [...],
                "env_accesses": [...],
                "call_sequence": [...],
            }

        Eski format (sadece isim listesi):
            {
                "api_calls": ["send", "recv", ...],
                "unique_modules": [...],
                ...
            }
        """
        data = self._trace_data
        if not data:
            return

        # API calls -- hem dict hem string formatini destekle
        raw_api = data.get("api_calls", [])
        self._api_call_records = []
        self._api_call_names = []
        for item in raw_api:
            if isinstance(item, dict):
                self._api_call_records.append(item)
                name = item.get("name", "")
                if name and name not in self._api_call_names:
                    self._api_call_names.append(name)
            elif isinstance(item, str):
                if item not in self._api_call_names:
                    self._api_call_names.append(item)

        # File accesses
        raw_files = data.get("file_accesses", [])
        self._file_accesses = []
        for item in raw_files:
            if isinstance(item, dict):
                self._file_accesses.append(item)
            elif isinstance(item, str):
                self._file_accesses.append({"path": item})

        # Crypto
        raw_crypto = data.get("crypto_operations", [])
        self._crypto_ops = []
        for item in raw_crypto:
            if isinstance(item, dict):
                self._crypto_ops.append(item)
            elif isinstance(item, str):
                self._crypto_ops.append({"algorithm": item})

        # Environment
        raw_env = data.get("environment_variables", data.get("env_accesses", []))
        self._env_accesses = []
        for item in (raw_env if isinstance(raw_env, list) else []):
            if isinstance(item, dict):
                self._env_accesses.append(item)
            elif isinstance(item, str):
                self._env_accesses.append({"name": item})

        # Modules
        raw_modules = data.get("unique_modules", [])
        self._unique_modules = [str(m) for m in raw_modules if m]

        # Call sequence
        self._call_sequence = data.get("call_sequence", [])

    # ----------------------------------------------------------
    # Isim cikarimi
    # ----------------------------------------------------------

    def infer_names(
        self,
        func_name: str,
        func_code: str,
    ) -> list[DynamicNameSuggestion]:
        """Fonksiyon icin runtime trace'den isim onerileri uret.

        Strateji:
        1. trace_report'taki api_calls'dan bu fonksiyonun kodunda
           cagirilan API'leri bul (kod icinde grep)
        2. Her API call icin APIParamDB'den param isimlerini al
        3. Fonksiyon kodundaki call site'larla eslestir
        4. param_1 -> "sockfd", param_2 -> "buf" gibi oneriler uret

        Args:
            func_name: Fonksiyon adi (orn. "FUN_00401000").
            func_code: Decompile edilmis C kodu.

        Returns:
            Isim onerileri listesi, confidence'a gore azalan sirada.
        """
        if not self._loaded or not func_code:
            return []

        # Onbellek kontrol
        cache_key = f"{func_name}:{hash(func_code)}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        suggestions: list[DynamicNameSuggestion] = []
        seen_vars: set[str] = set()  # Ayni degiskene birden fazla oneri verme

        # Strateji 1: API parametre eslestirme
        self._match_api_params(func_name, func_code, suggestions, seen_vars)

        # Strateji 2: Return value cikarimi -- API'nin donusunu alan degisken
        self._match_return_values(func_name, func_code, suggestions, seen_vars)

        # Strateji 3: Dosya erisim cikarimi
        self._match_file_access_context(func_name, func_code, suggestions, seen_vars)

        # Strateji 4: Crypto islem cikarimi
        self._match_crypto_context(func_name, func_code, suggestions, seen_vars)

        # Confidence'a gore azalan sirala
        suggestions.sort(key=lambda s: s.confidence, reverse=True)

        self._cache[cache_key] = suggestions
        return suggestions

    def _match_api_params(
        self,
        func_name: str,
        func_code: str,
        suggestions: list[DynamicNameSuggestion],
        seen_vars: set[str],
    ) -> None:
        """Trace'deki API cagrilarini C kodundaki call site'larla eslestir.

        C kodunda `send(param_1, param_2, param_3, 0)` gorursek ve
        trace'de `send` cagrildigini biliyorsak, APIParamDB'den
        send'in parametre isimlerini alip eslestiririz:
            param_1 -> sockfd
            param_2 -> buf
            param_3 -> len
        """
        if not self._api_call_names:
            return

        # Trace'de gozlemlenmis API'lerden C kodunda gecenleri bul
        for api_name in self._api_call_names:
            # C kodunda bu API'nin cagrildigi yeri bul
            # Hem normal hem underscore-prefix versiyonunu dene
            candidates = [api_name]
            if not api_name.startswith("_"):
                candidates.append(f"_{api_name}")

            for call_name in candidates:
                # func_name(arg1, arg2, ...) formatini bul
                # Balanced parantez parse icin basit regex + fallback
                pattern = re.compile(
                    r'\b' + re.escape(call_name) + r'\s*\(([^)]*)\)'
                )

                for match in pattern.finditer(func_code):
                    args_str = match.group(1)
                    args = [a.strip() for a in args_str.split(",")]

                    # APIParamDB'den parametre isimlerini al
                    param_names = self._api_db.get_param_names(call_name)
                    if not param_names:
                        # Underscore olmadan dene
                        bare = call_name.lstrip("_")
                        param_names = self._api_db.get_param_names(bare)
                    if not param_names:
                        continue

                    for i, (arg, pname) in enumerate(zip(args, param_names)):
                        arg = arg.strip()
                        if not _GENERIC_VAR_RE.match(arg):
                            continue
                        if arg in seen_vars:
                            continue

                        seen_vars.add(arg)
                        suggestions.append(DynamicNameSuggestion(
                            var_name=arg,
                            suggested_name=pname,
                            confidence=_CONF_API_TRACE,
                            source="frida_api_trace",
                            evidence=(
                                f"{call_name}({', '.join(args)}) called at "
                                f"runtime; param[{i}] = {pname}"
                            ),
                        ))

    def _match_return_values(
        self,
        func_name: str,
        func_code: str,
        suggestions: list[DynamicNameSuggestion],
        seen_vars: set[str],
    ) -> None:
        """API return degerini alan degiskeni isimlendir.

        Pattern: `iVar3 = malloc(local_20);` -> iVar3 = "alloc_ptr"
        Pattern: `iVar5 = open(param_1, 0);` -> iVar5 = "fd"
        """
        # Bilinen API'lerin return deger isimleri
        _RETURN_NAMES: dict[str, str] = {
            "malloc": "alloc_ptr",
            "calloc": "alloc_ptr",
            "realloc": "realloc_ptr",
            "open": "fd",
            "fopen": "fp",
            "socket": "sockfd",
            "accept": "client_fd",
            "connect": "connect_result",
            "dlopen": "lib_handle",
            "dlsym": "sym_ptr",
            "mmap": "mapped_addr",
            "strdup": "dup_str",
            "strlen": "str_len",
            "read": "bytes_read",
            "write": "bytes_written",
            "recv": "bytes_received",
            "send": "bytes_sent",
            "fork": "child_pid",
            "waitpid": "wait_result",
            "pthread_create": "thread_result",
            "sqlite3_open": "db_result",
            "sqlite3_prepare_v2": "prepare_result",
            "SSL_new": "ssl",
            "SSL_CTX_new": "ssl_ctx",
            "BIO_new": "bio",
            "curl_easy_init": "curl_handle",
        }

        # Underscore-prefix versiyonlari
        prefixed = {f"_{k}": v for k, v in _RETURN_NAMES.items()}
        _RETURN_NAMES.update(prefixed)

        if not self._api_call_names:
            return

        # var = api_call(...) pattern'ini bul
        assign_re = re.compile(
            r'(\b(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|[iuplscb]Var\d+|p[a-z]Var\d+|pp[a-z]Var\d+))\s*='
            r'\s*(\w+)\s*\('
        )

        for match in assign_re.finditer(func_code):
            var = match.group(1)
            callee = match.group(2)

            if var in seen_vars:
                continue

            # Callee trace'de gozlemlenmis mi?
            bare_callee = callee.lstrip("_")
            if bare_callee not in self._api_call_names and callee not in self._api_call_names:
                continue

            ret_name = _RETURN_NAMES.get(callee) or _RETURN_NAMES.get(bare_callee)
            if not ret_name:
                continue

            seen_vars.add(var)
            suggestions.append(DynamicNameSuggestion(
                var_name=var,
                suggested_name=ret_name,
                confidence=_CONF_API_TRACE_INDIRECT,
                source="frida_api_trace",
                evidence=f"{var} = {callee}(...); return value -> {ret_name}",
            ))

    def _match_file_access_context(
        self,
        func_name: str,
        func_code: str,
        suggestions: list[DynamicNameSuggestion],
        seen_vars: set[str],
    ) -> None:
        """Dosya erisim izinden baglamsal isimler cikar.

        Trace'de /tmp/data.txt erisimi varsa ve C kodunda open() goruyorsak,
        open'in ilk parametresini "file_path" olarak isimlendirebiliriz.
        """
        if not self._file_accesses:
            return

        # Dosya erisimi olan fonksiyonda open/fopen cagrisini ara
        file_apis = {"open", "fopen", "stat", "access", "unlink", "rename",
                     "_open", "_fopen", "_stat", "_access", "_unlink", "_rename"}

        for api in file_apis:
            if api not in func_code:
                continue

            pattern = re.compile(r'\b' + re.escape(api) + r'\s*\(([^)]*)\)')
            for match in pattern.finditer(func_code):
                args = [a.strip() for a in match.group(1).split(",")]
                if not args:
                    continue

                first_arg = args[0]
                if not _GENERIC_VAR_RE.match(first_arg):
                    continue
                if first_arg in seen_vars:
                    continue

                # Dosya yollari trace'de var -- bu arguman dosya yolu
                seen_vars.add(first_arg)
                accessed_paths = [
                    fa.get("path", fa.get("args", {}).get("path", ""))
                    for fa in self._file_accesses[:3]
                ]
                path_evidence = ", ".join(p for p in accessed_paths if p)

                suggestions.append(DynamicNameSuggestion(
                    var_name=first_arg,
                    suggested_name="file_path",
                    confidence=_CONF_FILE_ACCESS,
                    source="frida_api_trace",
                    evidence=(
                        f"Runtime file access detected ({path_evidence}); "
                        f"{api}({first_arg}, ...) -> file_path"
                    ),
                ))

    def _match_crypto_context(
        self,
        func_name: str,
        func_code: str,
        suggestions: list[DynamicNameSuggestion],
        seen_vars: set[str],
    ) -> None:
        """Crypto islemlerinden parametre isimleri cikar.

        Trace'de AES-256-CBC islemsi varsa ve C kodunda
        EVP_EncryptInit_ex goruyorsak, key/iv parametrelerini isimlendir.
        """
        if not self._crypto_ops:
            return

        crypto_apis = {
            "EVP_EncryptInit_ex", "EVP_DecryptInit_ex",
            "EVP_EncryptUpdate", "EVP_DecryptUpdate",
            "EVP_DigestInit_ex", "EVP_DigestUpdate",
            "CCCrypt", "CCCryptorCreate",
        }

        for api in crypto_apis:
            if api not in func_code:
                continue

            # Bu fonksiyonda crypto API'si var ve trace'de crypto op var
            param_names = self._api_db.get_param_names(api)
            if not param_names:
                continue

            pattern = re.compile(r'\b' + re.escape(api) + r'\s*\(([^)]*)\)')
            for match in pattern.finditer(func_code):
                args = [a.strip() for a in match.group(1).split(",")]

                algo_names = [
                    op.get("algorithm", op.get("name", ""))
                    for op in self._crypto_ops[:3]
                ]
                algo_evidence = ", ".join(a for a in algo_names if a)

                for i, (arg, pname) in enumerate(zip(args, param_names)):
                    if not _GENERIC_VAR_RE.match(arg):
                        continue
                    if arg in seen_vars:
                        continue

                    seen_vars.add(arg)
                    suggestions.append(DynamicNameSuggestion(
                        var_name=arg,
                        suggested_name=pname,
                        confidence=_CONF_CRYPTO_OP,
                        source="frida_api_trace",
                        evidence=(
                            f"Runtime crypto operation ({algo_evidence}); "
                            f"{api}(...) param[{i}] = {pname}"
                        ),
                    ))

    # ----------------------------------------------------------
    # Tip cikarimi
    # ----------------------------------------------------------

    def infer_types(self, func_name: str) -> dict[str, str]:
        """Runtime degerlerden tip cikarimi.

        Call sequence'daki args degerlerini inceleyerek degiskenlerin
        muhtemel tiplerini belirler:
            - 0x7fff... -> pointer
            - 0-65535 -> int / size_t
            - 0x20-0x7e -> possible char
            - Negatif -> signed int
            - -1 (0xffffffff) -> error sentinel

        Args:
            func_name: Fonksiyon adi.

        Returns:
            {param_adi: tip_adi} dict'i. Bos dict eger trace yoksa.
        """
        if not self._loaded:
            return {}

        type_map: dict[str, str] = {}

        # Call sequence'daki args degerlerini tara
        for call in self._call_sequence:
            args = call.get("args", {})
            if not isinstance(args, dict):
                continue

            for arg_name, value in args.items():
                if arg_name in type_map:
                    continue  # Ilk gorulende karar ver

                inferred = self._infer_single_type(value)
                if inferred:
                    type_map[arg_name] = inferred

        return type_map

    @staticmethod
    def _infer_single_type(value: Any) -> str | None:
        """Tek bir degerden tip cikar.

        Args:
            value: Runtime'da yakalanan deger.

        Returns:
            Tip ismi veya None.
        """
        if value is None:
            return None

        # String deger
        if isinstance(value, str):
            # Hex pointer string: "0x7fff..."
            if value.startswith("0x") or value.startswith("0X"):
                try:
                    int_val = int(value, 16)
                    return DynamicNamer._classify_int_value(int_val)
                except ValueError:
                    pass
            # Dosya yolu
            if "/" in value or "\\" in value:
                return "char *"  # path string
            return "char *"

        # Integer deger
        if isinstance(value, int):
            return DynamicNamer._classify_int_value(value)

        # Float
        if isinstance(value, float):
            return "double"

        # Bool
        if isinstance(value, bool):
            return "int"  # C'de bool yok, int kullanilir

        return None

    @staticmethod
    def _classify_int_value(value: int) -> str:
        """Integer degerin muhtemel tipini belirle.

        Args:
            value: Integer deger.

        Returns:
            C tipi string'i.
        """
        # Negatif deger -> signed
        if value < 0:
            if value == -1:
                return "int"  # Error sentinel
            if value >= -128:
                return "int8_t"
            if value >= -32768:
                return "int16_t"
            return "int"

        # Sifir -- belirsiz, en genel tip
        if value == 0:
            return "int"

        # Buyuk deger -> pointer
        if value > 0x7f000000:
            return "void *"

        # Yazdirilabilir ASCII araliginda -> olasi char
        if _CHAR_RANGE[0] <= value <= _CHAR_RANGE[1]:
            return "char"  # kesinlesmemis, int de olabilir

        # Kucuk pozitif -> size_t veya int
        if value <= _SMALL_INT_MAX:
            return "int"

        # Orta buyukluk -> uint32_t veya flags
        return "uint32_t"

    # ----------------------------------------------------------
    # Toplu cikarim
    # ----------------------------------------------------------

    def get_all_suggestions(self) -> dict[str, list[DynamicNameSuggestion]]:
        """Tum fonksiyonlar icin onerileri dondur.

        Bu metod trace_report'taki call_sequence'dan fonksiyon bazli
        gruplama yapar. Ancak decompile edilmis C kodu olmadan
        sadece trace-seviyesi isim cikarimi yapar (API param mapping).

        Returns:
            {func_name: [DynamicNameSuggestion, ...]} dict'i.
        """
        if not self._loaded:
            return {}

        results: dict[str, list[DynamicNameSuggestion]] = {}

        # Her API cagrisini fonksiyon-bagimsiz olarak isle
        # (trace_report hangi fonksiyondan cagrildigini bilmeyebilir)
        # Bu nedenle genel bir "_global_" anahtari altinda topla
        global_suggestions: list[DynamicNameSuggestion] = []
        seen_apis: set[str] = set()

        for api_name in self._api_call_names:
            if api_name in seen_apis:
                continue
            seen_apis.add(api_name)

            param_names = self._api_db.get_param_names(api_name)
            if not param_names:
                # Underscore-prefix dene
                bare = api_name.lstrip("_")
                param_names = self._api_db.get_param_names(bare)
            if not param_names:
                continue

            for i, pname in enumerate(param_names):
                generic_var = f"param_{i + 1}"
                global_suggestions.append(DynamicNameSuggestion(
                    var_name=generic_var,
                    suggested_name=pname,
                    confidence=_CONF_API_TRACE_INDIRECT,
                    source="frida_api_trace",
                    evidence=(
                        f"{api_name}() observed at runtime; "
                        f"param[{i}] typically named '{pname}'"
                    ),
                ))

        if global_suggestions:
            results["_global_"] = global_suggestions

        return results

    # ----------------------------------------------------------
    # Yardimci
    # ----------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        """Trace verisi yuklendi mi?"""
        return self._loaded

    @property
    def api_call_names(self) -> list[str]:
        """Trace'de gozlemlenmis API isimleri."""
        return list(self._api_call_names)

    @property
    def trace_stats(self) -> dict[str, int]:
        """Trace ozet istatistikleri."""
        if not self._loaded:
            return {}
        return {
            "api_calls": len(self._api_call_names),
            "api_call_records": len(self._api_call_records),
            "file_accesses": len(self._file_accesses),
            "crypto_operations": len(self._crypto_ops),
            "env_accesses": len(self._env_accesses),
            "unique_modules": len(self._unique_modules),
            "call_sequence_length": len(self._call_sequence),
        }

    def clear_cache(self) -> None:
        """Oneri onbellegini temizle."""
        self._cache.clear()

    def __repr__(self) -> str:
        status = "loaded" if self._loaded else "not loaded"
        path = self._trace_path or "N/A"
        return f"DynamicNamer({path}, {status})"
