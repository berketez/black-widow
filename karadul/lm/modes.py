"""KaradulLM kipleri ve izin modeli (KaradulLM v2 tasarımı §3.4, §3.9; P22e kalem 2-3).

**Kip** = sistem istemine eklenen blok + araç alt kümesi (P22d ``tools.MODE_TOOLSETS``) + izin satırı +
cevap şeması. Dört kip: ``kesif`` (öntanım), ``acikla``, ``adlandir``, ``plan``. Kip oturum içinde değişebilir,
ama yalnız görev sınırında (sabit önek değişir; tasarım K-B1).

- **Hat kiplerinin (açıkla, adlandır) istem bloğu BOŞTUR.** "Ad öner" öneki KL-0, "açıkla" öneki KL-1'dir ve
  ikisi de bayt bayt kilitlidir (pilot eşitliği, K0 dumanı; ``context.SYSTEM_PROMPT_KL0`` / ``_KL1``). Bu
  kiplerin farkı istemde değil izindedir: açıkla yalnız yorum, adlandır yalnız ad önerisi açar.
- **Keşif** bloğu cevap şemasını (``cevap`` ≤ 480 karakter, ``kanit``) ve "bu kipte öneri yok" kuralını
  anlatır. Keşif sorusu görevi ajanda henüz YOK (``Agent``'ın görev türleri: ad öner, açıkla, özet alt
  görevi); blok ve önek ölçümü o görev bağlandığında kullanılacak (P22e.md "Açık kalanlar").
- **Plan** kipinde model çağrılmaz (karar 3 (a): belirlenimci plan); önek yoktur.

**İzin modeli** (§3.9): sabit eylem × kip tablosu, ``allow`` / ``ask`` / ``deny``. ``uygula`` (ad haritasına
ya da deponun model bölümüne yazmak) ve ``calistir`` (hedefi ya da herhangi bir süreci çalıştırmak) her
kipte ``deny`` ve ayarla AÇILAMAZ; keşifte ``ag`` da ``deny`` (Berke kararı 8 (a): keşifte yalnız yerel
model). Politika yalnız daraltır: analist ``allow``'u ``ask`` ya da ``deny``'a, ``ask``'ı ``deny``'a çekebilir;
gevşetme ``ValueError``. "Deny her kipte kazanır" (Claude Code [CC-2]); "politika yalnız daraltır"
(opencode [OC-2]).

**"Hedef hiçbir koşulda çalıştırılmaz" üç katmanı:** (1) kayıt defterinde süreç başlatan araç yok
(``tools.TOOL_CLASS_ACTIONS``: yalnız ``oku`` / ``oner``); (2) durağan sınama (``tests/test_lm_izin.py``):
oturum, kip, terminal, defter, olay ve özet modülleri süreç başlatan modülü içe aktarmaz ve çağırmaz;
(3) tek alt süreç ``backend.build_llama_command``'ın kapalı komut listesidir; ikili yolu
``check_server_binary`` ile denetlenir: adı ``llama-server``, çalışma alanının içinde değil, özeti
analiz edilen ikilinin özetiyle aynı değil.

Bu modül süreç başlatmaz, ağa çıkmaz, dosya yazmaz.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from karadul.lm import BUDGET_PREFIX_TOKENS
from karadul.lm.context import (
    MODE_K0, MODE_K2, PROMPT_VERSION, PROMPT_VERSION_KL1, estimate_text_tokens, fixed_prefix,
)
from karadul.lm.tools import (
    ACTION_PROPOSE, ACTION_READ, MODE_EXPLAIN, MODE_EXPLORE, MODE_NAME, MODE_PLAN, ModeTools, default_registry,
    mode_toolset, registry_for_mode,
)

# --- Kipler (tasarım §3.4) ------------------------------------------------------------------------
SESSION_MODES = (MODE_EXPLORE, MODE_EXPLAIN, MODE_NAME, MODE_PLAN)
DEFAULT_MODE = MODE_EXPLORE
# Keşif cevabının ``cevap`` alanı (tasarım §3.4 keşif satırı: ≤ 480 karakter [seçim]). Sabit dosyası
# (``karadul/lm/__init__.py``) bu paketin yazma listesinde değil; tek tanım burada.
EXPLORE_ANSWER_MAX_CHARS = 480

# Öneri türleri (``events`` ``oneri.oneri_turu`` kümesiyle aynı yazım).
PROPOSAL_NAME, PROPOSAL_COMMENT = "ad", "yorum"

# Keşif kipinin istem bloğu (İngilizce: istemin dili; analist metni Türkçe — KL-0 son satırı).
EXPLORE_BLOCK = (
    "\n"
    "Mode: explore. The researcher asks a question about the program. Use the tools to collect what you "
    'need, then reply {"kind": "final", "cevap": "<answer in Turkish, at most '
    f'{EXPLORE_ANSWER_MAX_CHARS} characters>", "kanit": [<ids of the results you relied on>]}}. Answer only what '
    "the results show and say what is missing. You cannot file proposals in this mode.\n"
)

ENGINE_LOOP, ENGINE_PIPELINE, ENGINE_NONE = "dongu", "hat", "yok"


@dataclass(frozen=True)
class ModeSpec:
    """Bir kipin tanımı. ``agent_mode``: ajanın kipi (``K0`` hat, ``K2`` döngü; plan ``None``: model yok).
    ``prompt_version``: sistem isteminin sürümü (``None``: model yok). ``block``: sistem istemine eklenen
    blok (hat kiplerinde boş). ``proposals``: bu kipte açılabilen öneri türleri (izin ``oner`` ``allow``
    iken). ``label``: Türkçe görünen ad."""

    name: str
    label: str
    engine: str
    agent_mode: Optional[str]
    prompt_version: Optional[str]
    block: str
    proposals: tuple[str, ...]

    @property
    def tools(self) -> ModeTools:
        return mode_toolset(self.name)


MODE_SPECS: Mapping[str, ModeSpec] = {
    MODE_EXPLORE: ModeSpec(MODE_EXPLORE, "keşif", ENGINE_LOOP, MODE_K2, PROMPT_VERSION, EXPLORE_BLOCK, ()),
    MODE_EXPLAIN: ModeSpec(MODE_EXPLAIN, "açıkla", ENGINE_PIPELINE, MODE_K0, PROMPT_VERSION_KL1, "",
                           (PROPOSAL_COMMENT,)),
    MODE_NAME: ModeSpec(MODE_NAME, "adlandır", ENGINE_PIPELINE, MODE_K0, PROMPT_VERSION, "", (PROPOSAL_NAME,)),
    MODE_PLAN: ModeSpec(MODE_PLAN, "plan", ENGINE_NONE, None, None, "", ()),
}


def mode_spec(mode: str) -> ModeSpec:
    """Kipin tanımı; bilinmeyen kip ``ValueError`` (sessiz öntanım yok)."""
    try:
        return MODE_SPECS[mode]
    except KeyError:
        raise ValueError(f"bilinmeyen kip: {mode!r}") from None


def mode_prefix(mode: str) -> Optional[str]:
    """Kipin sabit öneki (sistem iletisi): ajanın o kipte göndereceği metin. Hat kipleri ``Agent.prefix``
    ile bayt bayt aynıdır (K0 + bugünkü kayıt + KL-0 / KL-1); keşif = K2 öneki (keşif kaydının araçlarıyla) +
    keşif bloğu. Plan kipinde model çağrılmaz: ``None``."""
    spec = mode_spec(mode)
    if spec.agent_mode is None or spec.prompt_version is None:
        return None
    if spec.agent_mode == MODE_K0:
        return fixed_prefix(MODE_K0, default_registry().definition_lines(), spec.prompt_version) + spec.block
    reg = registry_for_mode(mode)
    assert reg is not None, "döngü kipinin model araç kümesi boş olamaz"
    return fixed_prefix(spec.agent_mode, reg.definition_lines(), spec.prompt_version) + spec.block


def prefix_table() -> list[dict[str, object]]:
    """Kip başına önek ölçümü (ajanın jeton kestirimiyle; gerçek jetonlayıcıyla değil): kip, bayt,
    kestirim, dilim (``BUDGET_PREFIX_TOKENS``), sığıyor mu. Plan kipinde önek yok (``None``)."""
    out: list[dict[str, object]] = []
    for m in SESSION_MODES:
        p = mode_prefix(m)
        est = None if p is None else estimate_text_tokens(p)
        out.append({"kip": m, "bayt": None if p is None else len(p.encode("utf-8")), "kestirim": est,
                    "dilim": BUDGET_PREFIX_TOKENS, "sigar": None if est is None else est <= BUDGET_PREFIX_TOKENS})
    return out


# --- İzin modeli (tasarım §3.9) ---------------------------------------------------------------------
ACT_READ = ACTION_READ          # "oku": saklı çalışma alanını okuyan araçlar
ACT_PROPOSE = ACTION_PROPOSE    # "oner": öneri kaydı açmak (ad, yorum, parametre adı, not)
ACT_APPLY = "uygula"            # ad haritasına ya da deponun "model" bölümüne yazmak
ACT_NETWORK = "ag"              # model ucuna loopback dışından istek
ACT_RUN = "calistir"            # hedefi ya da herhangi bir süreci çalıştırmak
ACT_LONG_JOB = "uzun_is"        # beklenen süresi eşiği aşan kuyruk
ACTIONS = (ACT_READ, ACT_PROPOSE, ACT_APPLY, ACT_NETWORK, ACT_RUN, ACT_LONG_JOB)

ALLOW, ASK, DENY = "allow", "ask", "deny"
_STRICTNESS = {ALLOW: 0, ASK: 1, DENY: 2}

# Tasarım §3.9 tablosu. ``ag``: keşifte deny (karar 8 (a)); öbür kiplerde ask (açılması iki koşul ister:
# ``network.enabled`` ve analistin ilk kullanımdaki açık onayı; ``network_allowed``).
PERMISSIONS: Mapping[str, Mapping[str, str]] = {
    ACT_READ: {MODE_EXPLORE: ALLOW, MODE_EXPLAIN: ALLOW, MODE_NAME: ALLOW, MODE_PLAN: ALLOW},
    ACT_PROPOSE: {MODE_EXPLORE: DENY, MODE_EXPLAIN: ALLOW, MODE_NAME: ALLOW, MODE_PLAN: DENY},
    ACT_APPLY: {MODE_EXPLORE: DENY, MODE_EXPLAIN: DENY, MODE_NAME: DENY, MODE_PLAN: DENY},
    ACT_NETWORK: {MODE_EXPLORE: DENY, MODE_EXPLAIN: ASK, MODE_NAME: ASK, MODE_PLAN: ASK},
    ACT_RUN: {MODE_EXPLORE: DENY, MODE_EXPLAIN: DENY, MODE_NAME: DENY, MODE_PLAN: DENY},
    ACT_LONG_JOB: {MODE_EXPLORE: ASK, MODE_EXPLAIN: ASK, MODE_NAME: ASK, MODE_PLAN: ASK},
}
# Ayarla hiçbir koşulda değişmeyen satırlar (tasarım §3.9 "Hayır"; karar 8 (a)).
LOCKED_ACTIONS = frozenset({ACT_APPLY, ACT_RUN})
LOCKED_CELLS = frozenset({(ACT_NETWORK, MODE_EXPLORE)})

# ``uzun_is`` eşiği (sn): beklenen süresi bunu aşan kuyruk onay ister (§3.9 "≥ 10 dk" [seçim]; "eşik ayarla
# değişir": ``PermissionPolicy(long_job_sec=…)``). Beklenen süre bilinmiyorsa (hız ölçülmedi) de onay
# istenir: kısa olduğu gösterilemez.
LONG_JOB_THRESHOLD_SEC = 600.0

LONG_JOB_OK, LONG_JOB_ASK, LONG_JOB_DENIED = "izin", "onay", "ret"


class PermissionPolicy:
    """Tasarımın tablosu + analistin daraltmaları. ``narrowing``: ``{(eylem, kip): değer}``; değer tablodakinden
    gevşek olamaz, kilitli hücre değiştirilemez (``ValueError``)."""

    def __init__(self, narrowing: Mapping[tuple[str, str], str] | None = None, *,
                 long_job_sec: float = LONG_JOB_THRESHOLD_SEC):
        if not isinstance(long_job_sec, (int, float)) or isinstance(long_job_sec, bool) or long_job_sec <= 0:
            raise ValueError("uzun iş eşiği artı bir sayı olmalı")
        self.long_job_sec = float(long_job_sec)
        self._table = {a: dict(row) for a, row in PERMISSIONS.items()}
        for key, value in (narrowing or {}).items():
            if not (isinstance(key, tuple) and len(key) == 2):
                raise ValueError("daraltma anahtarı (eylem, kip) olmalı")
            action, mode = key
            if action not in self._table or mode not in self._table[action]:
                raise ValueError(f"bilinmeyen eylem ya da kip: {key!r}")
            if value not in _STRICTNESS:
                raise ValueError(f"bilinmeyen izin değeri: {value!r}")
            base = self._table[action][mode]
            if action in LOCKED_ACTIONS or (action, mode) in LOCKED_CELLS:
                if value != base:
                    raise ValueError(f"{action} / {mode} kilitli: ayarla değişmez")
                continue
            if _STRICTNESS[value] < _STRICTNESS[base]:
                raise ValueError(f"politika yalnız daraltır: {action} / {mode} {base} → {value} gevşetir")
            self._table[action][mode] = value

    def decide(self, action: str, mode: str) -> str:
        """``allow`` / ``ask`` / ``deny``; bilinmeyen eylem ya da kip ``deny`` değil ``ValueError``."""
        try:
            return self._table[action][mode]
        except KeyError:
            raise ValueError(f"bilinmeyen eylem ya da kip: {action!r} / {mode!r}") from None

    def may_propose(self, mode: str, kind: str) -> bool:
        """Bu kipte bu türden öneri açılabilir mi: ``oner`` ``allow`` ve tür kipin öneri türlerinde."""
        return self.decide(ACT_PROPOSE, mode) == ALLOW and kind in mode_spec(mode).proposals

    def network_allowed(self, mode: str, *, enabled: bool, consent: bool) -> bool:
        """Loopback dışı model ucu: ``deny`` hücrede hiçbir koşulda; ``ask`` hücrede yalnız ayar açık
        (``enabled is True``, katı bool) VE analistin açık onayı (``consent is True``) birlikteyse."""
        d = self.decide(ACT_NETWORK, mode)
        if d == DENY:
            return False
        if d == ASK:
            return enabled is True and consent is True
        return True

    def long_job(self, mode: str, expected_sec: Optional[float]) -> str:
        """Kuyruğun uzun iş kararı: ``izin`` (onaysız başlar), ``onay`` (analist ``/onayla`` demeli) ya da
        ``ret``. Beklenen süre bilinmiyorsa (``None``) ya da eşiğe eşit / üstündeyse ``ask`` hücre onay ister."""
        d = self.decide(ACT_LONG_JOB, mode)
        if d == DENY:
            return LONG_JOB_DENIED
        if d == ALLOW:
            return LONG_JOB_OK
        if expected_sec is None or expected_sec >= self.long_job_sec:
            return LONG_JOB_ASK
        return LONG_JOB_OK

    def line(self, mode: str) -> str:
        """Terminal başlığının izin satırı (tasarım §4.4 "kip: keşif (salt okur)"). Yalnız tablodan."""
        spec = mode_spec(mode)
        props = [k for k in spec.proposals if self.may_propose(mode, k)]
        parts = ["salt okur" if not props else "öneri: " + ", ".join(props)]
        if spec.engine == ENGINE_NONE:
            parts.append("model çağrılmaz")
        parts.append("uygula yok · çalıştır yok")
        parts.append("ağ " + {DENY: "kapalı", ASK: "onayla", ALLOW: "açık"}[self.decide(ACT_NETWORK, mode)])
        return f"kip: {spec.label} ({' · '.join(parts)})"


# --- Katman 3: yerel sunucunun ikilisi hedef olamaz (§3.9) ------------------------------------------
SERVER_BINARY_NAME = "llama-server"


class ServerBinaryRefused(ValueError):
    """Yerel model sunucusu olarak verilen ikili kabul edilmedi (hedef çalıştırılmaz)."""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_server_binary(binary: Path, workspace_root: Path, target_sha256: Optional[str]) -> Path:
    """``LlamaServerBackend``'e verilecek ikili yolunu denetler ve çözülmüş yolu döndürür.

    Reddedilir (``ServerBinaryRefused``): dosya adı ``llama-server`` değil (sembolik bağ çözülmüş hâliyle de);
    çalışma alanının içinde; ya da içeriğinin sha256'sı analiz edilen ikilininkiyle aynı (hedefin kopyası
    başka bir adla verilmiş). Dosya yoksa ya da okunamıyorsa da reddedilir (doğrulanamayan ikili başlatılmaz)."""
    p = Path(binary)
    try:
        real = p.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ServerBinaryRefused("sunucu ikilisi bulunamadı") from None
    if p.name != SERVER_BINARY_NAME or real.name != SERVER_BINARY_NAME:
        raise ServerBinaryRefused(f"sunucu ikilisinin adı {SERVER_BINARY_NAME!r} olmalı")
    if not real.is_file() or not os.access(real, os.X_OK):
        raise ServerBinaryRefused("sunucu ikilisi çalıştırılabilir bir dosya değil")
    try:
        ws_real = Path(workspace_root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ServerBinaryRefused("çalışma alanı çözülemedi") from None
    if real == ws_real or ws_real in real.parents:
        raise ServerBinaryRefused("sunucu ikilisi çalışma alanının içinde: hedef çalıştırılmaz")
    try:
        digest = _sha256_file(real)
    except OSError:
        raise ServerBinaryRefused("sunucu ikilisi okunamadı") from None
    if isinstance(target_sha256, str) and digest == target_sha256.lower():
        raise ServerBinaryRefused("sunucu ikilisi analiz edilen ikiliyle aynı: hedef çalıştırılmaz")
    return real
