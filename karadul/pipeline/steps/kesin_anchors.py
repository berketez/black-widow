"""KesinAnchorsStep — KS-1 kesin çapalarının Faz 1'de bir kez çıkarılması (plan v2.2 N1 adım 3).

Tasarım: ``docs/arge/2026-11-10_n1_adim3/baglama_tasarimi_taslak.md`` §2.1.

Akış:
    1. Bayrak denetimi: ``binary_reconstruction.enable_ks1_anchors`` açık değilse adım iş yapmaz;
       yapıt ``baglama.disabled()`` (durum ``kapali``), dosya yazılmaz.
    2. Girdi: ``workspace.get_stage_dir("static")``, yani ölçümdeki dizinin aynısı. c_namer'ın
       okuduğu ``deobfuscated/`` kopyası kullanılmaz; ölçülen girdi ``static/``'tir.
    3. Çıkarım ve karar: ``baglama.bind_static``. Hata fırlatmaz; girdi eksikse, platform
       desteklenmiyorsa ya da çıkarım hata verirse durum kodu döner ve hat sürer.
    4. Yan çıktı: ``reconstructed/kesin_capalar.json`` (çapalar, satırlar, etiketler, atlananlar).
       GT değildir; ürünün kendi kanıt dökümüdür.

Adım ad yazmaz. Adları ön ad sözlüğüne ``stages.py``'deki tohum (``_seed_recovery_pre_names``)
``baglama.apply_binding`` ile, ``main`` tohumundan sonra yazar; tohum iki kez çağrıldığı için
çıkarım burada bir kez yapılıp yapıt olarak saklanır. Mantık ``tarif/baglama.py``'dedir; bu modül
yalnız çağırır.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step
from karadul.pipeline.steps._feedback_naming_merger import config_flag
from karadul.reconstruction.tarif import baglama

logger = logging.getLogger(__name__)

# Adımın ürettiği yapıtın ve Faz 2'ye taşınan künye sözlüğünün anahtarları
KS1_ARTIFACT_KEY = "kesin_anchors"
PRE_NAME_META_KEY = "pre_name_meta"
# Girdi ve çıktı yerleri
KS1_INPUT_STAGE = "static"
KS1_DUMP_STAGE = "reconstructed"
KS1_DUMP_FILE = "kesin_capalar.json"
# ``stats`` anahtarları
KS1_STAT_STATUS = "ks1_status"
KS1_STAT_DETAIL = "ks1_detail"
KS1_STAT_TIMING = "timing_kesin_anchors"


def ks1_enabled(config: Any) -> bool:
    """KS-1 bayrağı (``binary_reconstruction.enable_ks1_anchors``) açık mı."""
    return config_flag(getattr(config, "binary_reconstruction", None), "enable_ks1_anchors")


def seed_inputs(artifact: Any) -> tuple[baglama.Binding | None, dict[str, dict[str, Any]] | None]:
    """Adımın yapıtından tohumun girdileri: ``(bağlama, künye sözlüğü)``.

    Yapıt yoksa ya da adım kapalıysa ``(None, None)``: tohum bugünkü gibi çalışır ve künye
    tutulmaz; bayrak kapalıyken ön adların sırası ve ad haritası değişmez. Adım çalıştıysa
    (çıkarım başarısız olsa da) boş bir künye sözlüğü döner; tohum onu doldurur.
    """
    if not isinstance(artifact, baglama.Binding) or artifact.status == baglama.RUN_DISABLED:
        return None, None
    return artifact, {}


def with_pre_name_meta(artifacts: Any, meta: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """Faz 2 tohumu: Faz 1 yapıtlarının kopyası; künye varsa ``pre_name_meta`` anahtarıyla eklenir.

    ``StepContext.artifacts`` salt okurdur; sözlük kopyaya yazılır. Künye yoksa anahtar hiç
    eklenmez (c_namer künyesiz, bugünkü gibi çağrılır).
    """
    seed = dict(artifacts)
    if meta is not None:
        seed[PRE_NAME_META_KEY] = meta
    return seed


@register_step(
    name="kesin_anchors",
    requires=[
        "functions_json_path",  # sıra ghidra_metadata'dan sonraya düşsün
    ],
    produces=[
        KS1_ARTIFACT_KEY,           # baglama.Binding
    ],
    parallelizable_with=[],
)
class KesinAnchorsStep(Step):
    """KS-1 çapalarını ``static/`` dizininden çıkarır ve ürün kararıyla bağlar. Ad yazmaz."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        step_start = time.monotonic()

        if not ks1_enabled(getattr(pc, "config", None)):
            ctx.stats[KS1_STAT_STATUS] = baglama.RUN_DISABLED
            return {KS1_ARTIFACT_KEY: baglama.disabled()}

        try:
            static_dir = pc.workspace.get_stage_dir(KS1_INPUT_STAGE)
            binding = baglama.bind_static(static_dir)
        except Exception as exc:  # bind_static fırlatmaz; dizin çözülemezse de hat düşmesin
            logger.warning("KS-1 çıkarımı yapılamadı: %s", exc)
            binding = baglama.Binding(
                status=baglama.RUN_ERROR, detail=f"{type(exc).__name__}: {exc}",
            )

        ctx.stats[KS1_STAT_STATUS] = binding.status
        if binding.detail:
            ctx.stats[KS1_STAT_DETAIL] = binding.detail
        self._dump(ctx, binding)
        ctx.stats[KS1_STAT_TIMING] = round(time.monotonic() - step_start, 3)
        logger.info(
            "KS-1 çapaları: durum %s, %d çapa (%d ad veren)",
            binding.status, len(binding.anchors), len(binding.named()),
        )
        return {KS1_ARTIFACT_KEY: binding}

    @staticmethod
    def _dump(ctx: StepContext, binding: baglama.Binding) -> None:
        """Yan çıktıyı yaz; yazılamazsa hata kaydedilir, hat sürer."""
        try:
            path = ctx.pipeline_context.workspace.save_artifact(
                KS1_DUMP_STAGE, KS1_DUMP_FILE,
                json.dumps(binding.as_dict(), indent=2, ensure_ascii=False),
            )
            ctx.produce_artifact("kesin_capalar", path)
        except Exception as exc:
            logger.warning("%s yazılamadı: %s", KS1_DUMP_FILE, exc)
            ctx.errors.append(f"kesin_anchors: {KS1_DUMP_FILE} yazılamadı: {exc}")
