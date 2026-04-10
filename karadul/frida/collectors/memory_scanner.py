"""Frida ile process memory'sini tara.

String pattern'leri ve byte pattern'leri icin memory scanning yapar.
Varsayilan pattern'ler: API key, URL, token, secret, password.
Pattern'ler config'den genisletilebilir.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Frida import kontrolu
try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

# Varsayilan hassas string pattern'leri (regex degil, duz metin araniyor)
DEFAULT_SENSITIVE_PATTERNS = [
    "API_KEY",
    "api_key",
    "apiKey",
    "SECRET",
    "secret",
    "TOKEN",
    "token",
    "PASSWORD",
    "password",
    "Bearer ",
    "Authorization:",
    "ssh-rsa ",
    "-----BEGIN",
    "PRIVATE KEY",
    "aws_access_key",
    "AWS_SECRET",
]


class MemoryScanner:
    """Frida ile process memory'sini tara.

    Calisan process'in memory space'ini tarayarak ilgili string'leri
    ve byte pattern'leri bulur.

    Kullanim:
        from karadul.frida.session import FridaSession

        session = FridaSession(config)
        session.spawn("/usr/local/bin/node", args=["app.js"])

        scanner = MemoryScanner(session)
        strings = scanner.scan_strings()
        patterns = scanner.scan_patterns([b'\\x00\\x01\\x02'])

    Args:
        session: Aktif FridaSession instance'i.
    """

    def __init__(self, session: Any) -> None:
        self.session = session
        self._results: list[dict] = []

    def scan_strings(
        self,
        patterns: list[str] | None = None,
        min_length: int = 8,
    ) -> list[dict]:
        """Memory'deki string'leri tara.

        Frida script'i inject ederek process memory'sini tarar.
        Bulunan her match icin adres, icerik ve pattern bilgisi doner.

        Args:
            patterns: Aranacak string pattern'leri. None ise
                      DEFAULT_SENSITIVE_PATTERNS kullanilir.
            min_length: Minimum string uzunlugu (noise filtresi).

        Returns:
            Bulunan eşlesmelerin listesi. Her eleman:
            {
                'pattern': str,      -- Aranan pattern
                'address': str,      -- Memory adresi (hex)
                'context': str,      -- Etrafindaki metin (preview)
                'module': str,       -- Hangi modülde bulundu
            }
        """
        if not self.session.is_attached:
            logger.warning("MemoryScanner: Session aktif degil, tarama yapilamiyor.")
            return []

        search_patterns = patterns or DEFAULT_SENSITIVE_PATTERNS

        # Frida script'i: her pattern icin Memory.scan calistir
        script_source = self._build_scan_script(search_patterns, min_length)

        try:
            self.session.load_script_source(script_source)
            # Tarama icin kisa bekleme
            import time
            time.sleep(2.0)

            # Sonuclari session mesajlarindan topla
            results = []
            for msg in self.session.messages:
                if isinstance(msg, dict) and msg.get("type") == "memory_match":
                    results.append(msg)

            self._results.extend(results)
            logger.info("MemoryScanner: %d string eslesmesi bulundu.", len(results))
            return results

        except Exception as exc:
            logger.error("MemoryScanner string tarama hatasi: %s", exc)
            return []

    def scan_patterns(self, patterns: list[bytes]) -> list[dict]:
        """Belirli byte pattern'leri ara.

        Args:
            patterns: Aranacak byte dizileri listesi.

        Returns:
            Bulunan eslesmelerin listesi.
        """
        if not self.session.is_attached:
            logger.warning("MemoryScanner: Session aktif degil.")
            return []

        # Byte pattern'leri hex string'e cevir
        hex_patterns = []
        for pat in patterns:
            hex_str = " ".join(f"{b:02x}" for b in pat)
            hex_patterns.append({"name": hex_str[:20], "hex": hex_str})

        script_source = self._build_byte_scan_script(hex_patterns)

        try:
            self.session.load_script_source(script_source)
            import time
            time.sleep(2.0)

            results = []
            for msg in self.session.messages:
                if isinstance(msg, dict) and msg.get("type") == "byte_match":
                    results.append(msg)

            self._results.extend(results)
            logger.info("MemoryScanner: %d byte pattern eslesmesi.", len(results))
            return results

        except Exception as exc:
            logger.error("MemoryScanner byte tarama hatasi: %s", exc)
            return []

    def dump_module(self, module_name: str, output_path: Path) -> bool:
        """Bir modulun memory dump'ini al.

        Process'in yukledigi bir modulun (dylib, framework, vb.)
        memory icerigini dosyaya yazar.

        Args:
            module_name: Modul adi (orn: "libcrypto.dylib", "node").
            output_path: Dump dosyasinin yazilacagi yol.

        Returns:
            True ise basarili dump.
        """
        if not self.session.is_attached:
            logger.warning("MemoryScanner: Session aktif degil.")
            return False

        # CWE-94 fix: module_name'i json.dumps ile escape et
        # json.dumps zaten tirnak ekler, JS string literal olarak guvenli
        safe_name = json.dumps(module_name)

        script_source = f"""
        (function() {{
            try {{
                var mod = Process.getModuleByName({safe_name});
                if (mod) {{
                    var data = mod.base.readByteArray(mod.size);
                    send({{
                        type: 'module_dump',
                        name: mod.name,
                        base: mod.base.toString(),
                        size: mod.size
                    }}, data);
                }} else {{
                    send({{ type: 'module_dump_error', error: 'Module not found: ' + {safe_name} }});
                }}
            }} catch (e) {{
                send({{ type: 'module_dump_error', error: e.toString() }});
            }}
        }})();
        """

        # Module dump binary data ile gelecegi icin ozel handling gerekir
        # Simdilik metadata'yi donduruyoruz
        try:
            self.session.load_script_source(script_source)
            import time
            time.sleep(1.0)

            # Module dump verisi Frida'nin binary data kanalidan gelir
            # Session._on_message'da 'data' parametresi olarak gelecek
            # Suan icin sadece metadata logluyoruz
            for msg in self.session.messages:
                if isinstance(msg, dict) and msg.get("type") == "module_dump":
                    logger.info(
                        "Module dump meta: %s, base=%s, size=%d",
                        msg.get("name"), msg.get("base"), msg.get("size", 0)
                    )
                    # Binary data ayri kanalda gelir -- tam implementasyon
                    # session._on_message'in data parametresini kullanmayi gerektirir
                    output_path = Path(output_path)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    # Metadata'yi kaydet
                    meta_path = output_path.with_suffix(".json")
                    meta_path.write_text(
                        json.dumps(msg, indent=2, default=str),
                        encoding="utf-8",
                    )
                    logger.info("Module dump metadata kaydedildi: %s", meta_path)
                    return True

                elif isinstance(msg, dict) and msg.get("type") == "module_dump_error":
                    logger.error("Module dump hatasi: %s", msg.get("error"))
                    return False

            logger.warning("Module dump icin mesaj alinamadi.")
            return False

        except Exception as exc:
            logger.error("Module dump hatasi: %s", exc)
            return False

    @property
    def results(self) -> list[dict]:
        """Toplanan tum tarama sonuclari."""
        return list(self._results)

    def clear(self) -> None:
        """Tarama sonuclarini temizle."""
        self._results.clear()

    @staticmethod
    def _build_scan_script(patterns: list[str], min_length: int) -> str:
        """String tarama icin Frida JS scripti olustur."""
        # Pattern'leri JSON olarak embed et
        patterns_json = json.dumps(patterns)

        return f"""
        (function() {{
            var patterns = {patterns_json};
            var minLength = {min_length};

            var modules = Process.enumerateModules();

            for (var mi = 0; mi < modules.length; mi++) {{
                var mod = modules[mi];

                // Cok buyuk modulleri atla (performance)
                if (mod.size > 100 * 1024 * 1024) continue;

                for (var pi = 0; pi < patterns.length; pi++) {{
                    var pattern = patterns[pi];

                    // String'i hex pattern'e cevir
                    var hex = '';
                    for (var ci = 0; ci < pattern.length; ci++) {{
                        hex += ('0' + pattern.charCodeAt(ci).toString(16)).slice(-2) + ' ';
                    }}
                    hex = hex.trim();

                    try {{
                        Memory.scan(mod.base, mod.size, hex, {{
                            onMatch: function(address, size) {{
                                // Etrafindaki context'i oku
                                var ctx = '';
                                try {{
                                    ctx = address.readUtf8String(Math.min(64, size + 32));
                                }} catch(e) {{
                                    try {{
                                        ctx = address.readCString(Math.min(64, size + 32));
                                    }} catch(e2) {{
                                        ctx = '[unreadable]';
                                    }}
                                }}

                                if (ctx.length >= minLength) {{
                                    send({{
                                        type: 'memory_match',
                                        pattern: pattern,
                                        address: address.toString(),
                                        context: ctx.substring(0, 200),
                                        module: mod.name,
                                        timestamp: Date.now()
                                    }});
                                }}
                            }},
                            onComplete: function() {{}}
                        }});
                    }} catch(e) {{
                        // Bazi memory bolgeleri okunamayabilir
                    }}
                }}
            }}
        }})();
        """

    @staticmethod
    def _build_byte_scan_script(patterns: list[dict]) -> str:
        """Byte pattern tarama icin Frida JS scripti olustur."""
        patterns_json = json.dumps(patterns)

        return f"""
        (function() {{
            var patterns = {patterns_json};
            var modules = Process.enumerateModules();

            for (var mi = 0; mi < modules.length; mi++) {{
                var mod = modules[mi];
                if (mod.size > 100 * 1024 * 1024) continue;

                for (var pi = 0; pi < patterns.length; pi++) {{
                    var pat = patterns[pi];

                    try {{
                        Memory.scan(mod.base, mod.size, pat.hex, {{
                            onMatch: function(address, size) {{
                                send({{
                                    type: 'byte_match',
                                    pattern_name: pat.name,
                                    address: address.toString(),
                                    module: mod.name,
                                    timestamp: Date.now()
                                }});
                            }},
                            onComplete: function() {{}}
                        }});
                    }} catch(e) {{}}
                }}
            }}
        }})();
        """
