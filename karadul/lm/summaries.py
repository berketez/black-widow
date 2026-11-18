"""KaradulLM özet deposu ve geçersiz kılma (KaradulLM v2 tasarımı §3.6 madde 4, §3.7, §3.11 "Devam").

Aşağıdan yukarı zincirde her fonksiyonun özeti bir kez hesaplanır ve sonraki paketlere girer. Kayıt
**anahtarına bağlıdır**; anahtar özeti belirleyen her girdiyi taşır:

- ``ikili_sha256``: analiz edilen ikili (deponun dizini de bu),
- ``adres``: fonksiyon (çalışma alanı yazımı),
- ``istem_surumu`` (KL-1) ve ``arac_kumesi`` (araç kaydının sürümü),
- ``model``: model kimliği (``model_key``),
- ``paket_sha256``: modele verilen paketin içeriği (kanıt, kod, çağrılanların özetleri). Sonuç
  kimlikleri (``r3``) özetlenmez: ajanın sayacına bağlıdırlar, içerik değildirler (``package_digest``),
- ``ad``: fonksiyonun o anki adı ve etiketi (pakete girmez ama "ad değişince özet bayatlar").

**Geçersiz kılma:** kayıt yalnız anahtarı birebir aynıysa geçerlidir. Fonksiyonun kodu ya da kanıtı,
adı, bir çağrılanın özeti (çağıranın paketine girer), istem, araç kümesi ya da model değişince anahtar
değişir; eski kayıt dosyada kalır ama **bayattır** (``state``: ``gecerli`` / ``bayat`` / ``yok``) ve
hiçbir pakete girmez. Silme yok (yalnız eklenir; içerik deposu gibi analist siler, karar 6 (b)).

Yer: ``~/.karadul/lm/<ikili_sha256>/ozet.jsonl`` — dizinler 0700, dosya 0600, yalnız ekleme
(``O_APPEND``), sembolik bağ izlenmez (``audit.py`` / ``events.ContentStore`` kalıbı). Nesne kurmak dosya
açmaz. Bozuk satır atlanır ve sayılır (``corrupt_lines``; sessiz kayıp yok).

Kaynak (``kaynak``): ``model`` (modelin gerçekten ürettiği metin; çağıranın paketinde
``[model-özet]`` işaretiyle, kanıt sayılmaz) ya da ``olgu`` (D0 kısa yolu: modelsiz hesaplanan satır).

Bu modül süreç açmaz, ağa bağlanmaz.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from karadul.lm.audit import _HEX64, canonical_json, now_iso, sha256_text

SUMMARY_FILE_NAME = "ozet.jsonl"
SOURCE_MODEL = "model"
SOURCE_FACT = "olgu"
SUMMARY_SOURCES = (SOURCE_MODEL, SOURCE_FACT)
STATE_VALID, STATE_STALE, STATE_NONE = "gecerli", "bayat", "yok"

_RESULT_ID_KEY = "id"


def model_key(identity: Mapping[str, Any]) -> str:
    """Arka ucun künyesinden model kimliği. ``model_sha256`` varsa o (``sha256:<…>``); yoksa künyenin
    model alanlarının özeti (``kunye:<16 onaltılık>``: tür, model yolu ya da adı, uç). Yerel sunucu model
    dosyasını özetlemiyor (16 GiB, ≈ 8 sn; ``backend._static_identity``): aynı yolda dosya değişirse
    bu kimlik değişmez (P22b.md "açık kalanlar")."""
    sha = identity.get("model_sha256")
    if isinstance(sha, str) and _HEX64.fullmatch(sha):
        return f"sha256:{sha}"
    parts = {k: identity.get(k) for k in ("tur", "model", "uc")}
    return "kunye:" + sha256_text(canonical_json(parts))[:16]


def package_digest(envelopes: Iterable[Mapping[str, Any]]) -> str:
    """Paket içeriğinin sha256'sı: zarflar sırasıyla, sonuç kimlikleri çıkarılmış (kanonik JSON)."""
    body = [{k: v for k, v in e.items() if k != _RESULT_ID_KEY} for e in envelopes]
    return sha256_text(canonical_json(body))


@dataclass(frozen=True)
class SummaryKey:
    """Özetin anahtarı (modül belgesi). Alanlardan biri değişirse kayıt bayatlar."""

    binary_sha256: str
    addr: str
    prompt_version: str
    toolset_version: str
    model: str
    package_sha256: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.binary_sha256, str) or not _HEX64.fullmatch(self.binary_sha256):
            raise ValueError("geçersiz ikili sha256")
        if not isinstance(self.addr, str) or not re.fullmatch(r"[0-9a-fA-F]{1,16}", self.addr):
            raise ValueError("geçersiz adres")
        if not isinstance(self.package_sha256, str) or not _HEX64.fullmatch(self.package_sha256):
            raise ValueError("geçersiz paket sha256")
        for v in (self.prompt_version, self.toolset_version, self.model):
            if not isinstance(v, str) or not v:
                raise ValueError("anahtar alanı boş olamaz")
        if self.name is not None and not isinstance(self.name, str):
            raise ValueError("ad dizgi ya da None olmalı")


@dataclass(frozen=True)
class SummaryRecord:
    """Bir özet. ``metin`` modelin (``kaynak == "model"``) ya da D0'ın (``"olgu"``) gerçek metnidir.
    ``pakete_girer``: denetimden geçti mi (çelişkili / enjeksiyon belirtili özet çağıranın paketine
    girmez; tasarım §3.6 madde 6). ``hukum``: denetim hükmü (olguda ``None``: model iddiası değil)."""

    key: SummaryKey
    kaynak: str
    metin: str
    belirsiz: bool
    kanit: tuple[str, ...] = ()
    hukum: Optional[str] = None
    pakete_girer: bool = True
    gorev: Optional[str] = None
    zaman: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if self.kaynak not in SUMMARY_SOURCES:
            raise ValueError(f"bilinmeyen özet kaynağı: {self.kaynak!r}")
        if not isinstance(self.metin, str) or not self.metin:
            raise ValueError("özet metni boş olamaz")
        if not isinstance(self.belirsiz, bool) or not isinstance(self.pakete_girer, bool):
            raise ValueError("belirsiz / pakete_girer mantıksal değer olmalı")
        if any(not isinstance(k, str) for k in self.kanit):
            raise ValueError("kanıt kimlikleri dizgi olmalı")

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["key"] = asdict(self.key)
        d["kanit"] = list(self.kanit)
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "SummaryRecord":
        k = d["key"]
        return SummaryRecord(key=SummaryKey(**{f: k[f] for f in SummaryKey.__dataclass_fields__}),
                             kaynak=d["kaynak"], metin=d["metin"], belirsiz=d["belirsiz"],
                             kanit=tuple(d.get("kanit") or ()), hukum=d.get("hukum"),
                             pakete_girer=d["pakete_girer"], gorev=d.get("gorev"), zaman=d["zaman"])


class SummaryStore:
    """İkili başına özet deposu (``~/.karadul/lm/<ikili_sha256>/ozet.jsonl``).

    Okuma tembeldir (ilk ``get`` / ``state``) ve nesne ömrünce bellekte tutulur; aynı dosyaya başka süreç
    yazıyorsa ``reload`` gerekir (oturum başına tek ajan; P22e). Hiçbir şey silinmez."""

    def __init__(self, binary_sha256: str, *, root: Optional[Path] = None):
        if not isinstance(binary_sha256, str) or not _HEX64.fullmatch(binary_sha256):
            raise ValueError("geçersiz ikili sha256 (64 küçük harfli onaltılık basamak beklenir)")
        self.binary_sha256 = binary_sha256
        base = Path(root) if root is not None else Path.home() / ".karadul" / "lm"
        self.dir = base / binary_sha256
        self.path = self.dir / SUMMARY_FILE_NAME
        self._records: Optional[list[SummaryRecord]] = None
        self.corrupt_lines = 0

    # --- okuma ----------------------------------------------------------------------------------

    def _load(self) -> list[SummaryRecord]:
        if self._records is None:
            self.reload()
        assert self._records is not None
        return self._records

    def reload(self) -> None:
        """Dosyayı yeniden okur. Sembolik bağ okunmaz (``OSError``); bozuk satır atlanır ve sayılır."""
        records: list[SummaryRecord] = []
        corrupt = 0
        if self.path.is_symlink():
            raise OSError(f"özet deposu sembolik bağ: {self.path}")
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = ""
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                rec = SummaryRecord.from_dict(obj)
            except (ValueError, KeyError, TypeError):
                corrupt += 1
                continue
            if rec.key.binary_sha256 != self.binary_sha256:
                corrupt += 1
                continue
            records.append(rec)
        self._records = records
        self.corrupt_lines = corrupt

    def records(self) -> list[SummaryRecord]:
        return list(self._load())

    def get(self, key: SummaryKey) -> Optional[SummaryRecord]:
        """Anahtarı birebir aynı olan en son kayıt; yoksa ``None`` (bayat kayıt verilmez)."""
        for rec in reversed(self._load()):
            if rec.key == key:
                return rec
        return None

    def state(self, key: SummaryKey) -> str:
        """``gecerli``: bu anahtarla kayıt var. ``bayat``: aynı fonksiyonun yalnız başka anahtarlı kaydı var
        (kod / ad / çağrılan özeti / istem / araç / model değişmiş). ``yok``: fonksiyonun hiç kaydı yok."""
        if self.get(key) is not None:
            return STATE_VALID
        if any(int(r.key.addr, 16) == int(key.addr, 16) for r in self._load()):
            return STATE_STALE
        return STATE_NONE

    # --- yazma ----------------------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        missing: list[Path] = []
        p = self.dir
        while not p.exists() and not p.is_symlink():
            missing.append(p)
            p = p.parent
        for d in reversed(missing):
            try:
                d.mkdir(mode=0o700)
            except FileExistsError:
                pass
        if self.dir.is_symlink() or not self.dir.is_dir():
            raise OSError(f"özet dizini dizin değil ya da sembolik bağ: {self.dir}")

    def put(self, record: SummaryRecord) -> None:
        """Kaydı dosyaya ekler (tek satır). Başka ikilinin anahtarı ``ValueError``; yazılamazsa ``OSError``."""
        if record.key.binary_sha256 != self.binary_sha256:
            raise ValueError("kayıt bu ikilinin deposuna ait değil")
        line = (json.dumps(record.as_dict(), ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self._load()
        self._ensure_dir()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(line)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        assert self._records is not None
        self._records.append(record)
