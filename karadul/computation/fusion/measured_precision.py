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
    # P15c (K-2, 2026-11-18): aynı nüfusun GEVŞEK ölçütle (amaç doğru mu) ölçümü. Füzyon bu
    # bölümü OKUMAZ: füzyonun ad kanalı tam kimlik ister, yukarıdaki tam-ad kaydı geçerli.
    # Okuyan: ``signature_db`` — davranış tahmini (``string_ref`` / ``call_pattern``) kaydının
    # ``confidence``'ı burada yazan Wilson alt sınırıdır (ham eşleşme puanı ``match_score``).
    "davranis": {
        "_kaynak": {
            "olcum": ("python ~/karadul_olcum/runs/onarim-2026-11-18/P15c/p15c_olc.py oynat "
                      "--kosu ~/karadul_olcum/runs/genel-tarama-2026-11-18 --etiket gelistirme_T "
                      "--gt; ozellik --etiketler etiket_gelistirme.json"),
            "olcum_dizini": "~/karadul_olcum/runs/onarim-2026-11-18/P15c/",
            "tarih": "2026-11-18",
            "kod": "main 6a74da0 (Ghidra'sız yeniden oynatma; genel tarama Ghidra çıktıları)",
            "set": ("geliştirme seti: genel taramanın 14 ikilisi (12 Debian + mac htop / tmux); "
                    "236 kayıt (P11'in 208'i + Mac 28)"),
            "nufus": ("Ghidra'nın adsız bıraktığı (FUN_) fonksiyonlara string_ref / call_pattern "
                      "yoluyla verilen adlar"),
            "olcut": ("gevşek: rubrik v2 (docs/arge/etiket_rehberi.md); doğru = tam + "
                      "dogru_tarif; yalniz_alan doğru sayılmaz"),
            "kip": ("gerçek adın gösterildiği kip, tek etiketçi (P15c ajanı), kör değil; "
                    "etiket dosyası etiket_gelistirme.json sha256 974bb953…dd2e6"),
            "tam_ad_yeniden": "aynı 236 kayıtta tam ad: call_pattern 0/83, string_ref 0/153",
            "olasilik": "Wilson %95 alt sınırı (karadul.reconstruction.tarif.baglama.wilson)",
            "kayit": "docs/arge/2026-11-18_onarim/P15c.md (Kalem 2)",
        },
        "kaynaklar": {
            "imza:call_pattern": {"n": 83, "dogru": 19, "yalniz_alan": 30, "wilson_alt": 0.1517},
            "imza:string_ref": {"n": 153, "dogru": 5, "yalniz_alan": 14, "wilson_alt": 0.014},
        },
    },
}
