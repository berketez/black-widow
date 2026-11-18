"""Füzyon kaynaklarının ölçülmüş kesinliği (P11 / TIP-02).

Python modülü olarak tutulur (JSON olsaydı ``pyproject.toml`` package-data'sına
girmediği için kurulu pakette bulunmazdı). Yeni ölçüm bu dosyayı ve kaydını
(``_kaynak.kayit``) birlikte günceller.
"""

from __future__ import annotations

from typing import Any

MEASURED_PRECISION: dict[str, Any] = {
    "_kaynak": {
        "olcum": ("python scripts/measurement/p11_olc.py imza --kosu "
                  "~/karadul_olcum/runs/genel-tarama-2026-11-18 --etiket head14"),
        "tarih": "2026-11-18",
        "set": "geliştirme setinden 12 Debian ikilisi (Karadul 1.23.1 çıktısı, genel tarama)",
        "nufus": ("Ghidra'nın adsız bıraktığı (FUN_) fonksiyonlara imza veritabanının verdiği "
                  "adlar; GT'de o adreste fonksiyon yoksa yanlış"),
        "olcut": "tam ad eşitliği (scripts/measurement/ks1_olc.py capa_degerlendir)",
        "olasilik": "Wilson %95 alt sınırı; ölçülmemiş kaynak için olasılık yok (karar: abstain)",
        "kayit": "docs/arge/2026-11-18_onarim/P11.md (Kalem 3)",
    },
    "kaynaklar": {
        "imza:call_pattern": {"n": 76, "dogru": 0, "wilson_alt": 0.0},
        "imza:string_ref": {"n": 132, "dogru": 0, "wilson_alt": 0.0},
    },
}
