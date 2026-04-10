"""npm paketlerinin orijinal kaynak kodunu unpkg.com'dan cek -- diske yazmadan.

Kullanim:
    resolver = SourceResolver(Config())
    source = resolver.resolve("highlight.js")
    print(source.version, len(source.source_code))

HTTP icin sadece urllib.request kullanir (ek dependency yok).
Cache hafizada tutulur (dict), session boyunca gecerli.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karadul.config import Config

logger = logging.getLogger(__name__)

# --- Sabitler ---
UNPKG_BASE = "https://unpkg.com"
REQUEST_TIMEOUT = 10  # saniye
RATE_LIMIT_DELAY = 0.05  # 50ms between requests
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0  # ilk retry delay (saniye), sonraki 2x artar


@dataclass
class ResolvedSource:
    """Bir npm paketinin cozulmus kaynak kodu."""

    package_name: str
    version: str
    entry_file: str  # ana dosya path'i (orn: "lib/core.js")
    source_code: str  # orijinal kaynak kod
    additional_files: dict[str, str] = field(default_factory=dict)  # ek dosyalar


class SourceResolver:
    """npm paketlerinin orijinal kaynak kodunu bul -- diske yazmadan.

    Oncelik sirasi:
    1. Cache (hafizada)
    2. unpkg.com CDN

    Rate limiting: Her HTTP istegi arasinda 50ms bekler.
    Timeout: 10 saniye per request.
    Retry: 3 deneme, exponential backoff.
    """

    def __init__(self, config: Config | None = None):
        self.config = config
        self._cache: dict[str, ResolvedSource] = {}  # "paket@version" -> ResolvedSource
        self._last_request_time: float = 0.0

    def resolve(
        self,
        package_name: str,
        version: str | None = None,
        extra_files: list[str] | None = None,
    ) -> ResolvedSource | None:
        """Orijinal kaynak kodu bul.

        Args:
            package_name: npm paket adi (orn: "highlight.js", "@sentry/node")
            version: Belirli versiyon (None ise latest)
            extra_files: Entry point disinda cekilecek ek dosyalar

        Returns:
            ResolvedSource veya None (bulunamazsa)
        """
        # Versiyonu coz
        if version is None:
            version = self._resolve_version(package_name)
            if version is None:
                logger.warning("Versiyon cozulemedi: %s", package_name)
                return None

        cache_key = f"{package_name}@{version}"

        # Cache kontrol
        if cache_key in self._cache:
            logger.debug("Cache hit: %s", cache_key)
            return self._cache[cache_key]

        # Entry point bul
        entry_file = self._get_package_entry(package_name, version)
        if entry_file is None:
            # Fallback: index.js dene
            entry_file = "index.js"
            logger.debug("Entry point bulunamadi, fallback: %s", entry_file)

        # Ana dosyayi cek
        source_code = self._fetch_unpkg(package_name, entry_file, version)
        if source_code is None:
            logger.warning("Kaynak kod cekilemedi: %s/%s", cache_key, entry_file)
            return None

        # Ek dosyalari cek
        additional_files: dict[str, str] = {}
        if extra_files:
            for file_path in extra_files:
                content = self._fetch_unpkg(package_name, file_path, version)
                if content is not None:
                    additional_files[file_path] = content

        result = ResolvedSource(
            package_name=package_name,
            version=version,
            entry_file=entry_file,
            source_code=source_code,
            additional_files=additional_files,
        )

        self._cache[cache_key] = result
        logger.info(
            "Kaynak kod cekildi: %s@%s (%s, %d bytes)",
            package_name,
            version,
            entry_file,
            len(source_code),
        )
        return result

    def _rate_limit(self) -> None:
        """Istekler arasi minimum bekleme suresi."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()

    def _fetch_url(self, url: str) -> tuple[str | None, str | None]:
        """URL'den icerik cek. (content, final_url) dondurur.

        Redirect'leri takip eder, final URL'yi dondurur (versiyon cozme icin).
        Retry: 3 deneme, exponential backoff.
        """
        self._rate_limit()

        delay = RETRY_BACKOFF
        for attempt in range(MAX_RETRIES):
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "BlackWidow/3.0 (research)",
                        "Accept": "*/*",
                    },
                )
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    content = resp.read().decode("utf-8", errors="replace")
                    final_url = resp.url  # redirect sonrasi gercek URL
                    return content, final_url
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    logger.debug("404 Not Found: %s", url)
                    return None, None
                if e.code == 429:
                    # Rate limited -- bekle ve tekrar dene
                    logger.warning(
                        "Rate limited (429), %d. deneme, %.1fs bekliyor: %s",
                        attempt + 1,
                        delay,
                        url,
                    )
                    time.sleep(delay)
                    delay *= 2
                    continue
                logger.warning("HTTP %d: %s", e.code, url)
                return None, None
            except urllib.error.URLError as e:
                logger.warning(
                    "URL hatasi (%d. deneme): %s -- %s",
                    attempt + 1,
                    url,
                    e.reason,
                )
                if attempt < MAX_RETRIES - 1:
                    time.sleep(delay)
                    delay *= 2
                    continue
                return None, None
            except Exception as e:
                logger.warning("Beklenmeyen hata: %s -- %s", url, e)
                return None, None

        return None, None

    def _fetch_unpkg(
        self, package_name: str, file_path: str, version: str | None = None
    ) -> str | None:
        """unpkg.com'dan tek dosya cek. Diske yazmaz.

        GET https://unpkg.com/PAKET@VERSION/DOSYA
        """
        # file_path basindaki / temizle
        file_path = file_path.lstrip("./")

        if version:
            url = f"{UNPKG_BASE}/{package_name}@{version}/{file_path}"
        else:
            url = f"{UNPKG_BASE}/{package_name}/{file_path}"

        content, _ = self._fetch_url(url)
        return content

    def _get_package_entry(
        self, package_name: str, version: str | None = None
    ) -> str | None:
        """package.json'dan main/module/exports entry point'ini bul.

        Oncelik: module > main > index.js
        """
        if version:
            url = f"{UNPKG_BASE}/{package_name}@{version}/package.json"
        else:
            url = f"{UNPKG_BASE}/{package_name}/package.json"

        content, _ = self._fetch_url(url)
        if content is None:
            return None

        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("package.json parse hatasi: %s", package_name)
            return None

        # Oncelik sirasi: module (ESM) > main (CJS) > "index.js"
        entry = pkg.get("module") or pkg.get("main")
        if entry:
            # Bazi paketler "./" ile baslatir
            entry = entry.lstrip("./")
            return entry

        return None

    def _resolve_version(self, package_name: str) -> str | None:
        """Versiyon bilinmiyorsa unpkg redirect'ten al.

        unpkg.com/PAKET/ -> 302 redirect -> unpkg.com/PAKET@X.Y.Z/
        Redirect URL'sinden versiyonu parse et.
        """
        url = f"{UNPKG_BASE}/{package_name}/package.json"
        content, final_url = self._fetch_url(url)

        if final_url is None:
            return None

        # final_url: https://unpkg.com/highlight.js@11.9.0/package.json
        # Versiyonu cikar: @ ile / arasi
        try:
            # "@" isareti ile split et
            after_at = final_url.split("@")[-1]
            # "/" ile kes
            version = after_at.split("/")[0]
            if version and version[0].isdigit():
                return version
        except (IndexError, ValueError):
            pass

        # Fallback: package.json'dan version field'i
        if content:
            try:
                pkg = json.loads(content)
                return pkg.get("version")
            except json.JSONDecodeError:
                pass

        return None

    def resolve_multiple(
        self,
        packages: list[str | tuple[str, str | None]],
    ) -> dict[str, ResolvedSource]:
        """Birden fazla paketi coz.

        Args:
            packages: Paket adlari listesi veya (paket, versiyon) tuple'lari

        Returns:
            {paket_adi: ResolvedSource} dict'i (basarili olanlar)
        """
        results: dict[str, ResolvedSource] = {}
        for item in packages:
            if isinstance(item, tuple):
                name, version = item
            else:
                name, version = item, None

            source = self.resolve(name, version)
            if source is not None:
                results[name] = source

        return results

    def clear_cache(self) -> None:
        """Hafizadaki cache'i temizle."""
        count = len(self._cache)
        self._cache.clear()
        logger.debug("Cache temizlendi (%d entry)", count)

    @property
    def cache_size(self) -> int:
        """Cache'deki paket sayisi."""
        return len(self._cache)

    def cache_info(self) -> dict[str, str]:
        """Cache icerigi ozeti."""
        return {key: f"{len(v.source_code)} bytes" for key, v in self._cache.items()}
