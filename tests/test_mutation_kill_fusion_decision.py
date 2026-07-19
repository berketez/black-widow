"""Mutation-kill testleri -- SignatureFusion karar/kalibrasyon delikleri.

Sonraki-kademe mutasyon denetiminde (fusion modulu) TAM-SUITE'e karsi HAYATTA
kalan (yani hicbir mevcut test tarafindan yakalanmayan) iki gercek delik:

  F3  fuser.DecisionConfig.__post_init__ invariant'i `reject <= accept`
      (inclusive). `reject == accept` DEGENERE ama GECERLI bir konfigurasyondur
      (abstain bandi bos: p>=accept -> accept, p<=reject -> reject). Hicbir test
      esit-esik konfigurasyonunu kurmuyordu; mutant `<=`->'<' bu gecerli config'i
      ValueError ile reddeder -> yakalanmazdi.

  C4  calibration.PlattCalibrator.fit Platt smoothing'i: negatif hedef
      y_minus = 1/(n_minus+2) (asla 0 degil -- asiri guveni engeller, Platt 1999).
      Mevcut fit testi sadece `A>0.5` ve `p in [0,1]` denetliyordu; mutant
      y_minus = 0.0 (smoothing kaldirilir) TAM-SUITE'e karsi HAYATTA kaliyordu.

Her iki mutant da mutation_probe.py ile TUM suite'e (`--test tests/`) karsi
enjekte edildiginde HAYATTA kaldigi dogrulandi (masking yok, gercek delik).
Bu testler eklendikten sonra ayni mutantlar KILLED olur (bkz docs/mutation_specs.json).
"""

from __future__ import annotations

import pytest

from karadul.computation.fusion import DecisionConfig, PlattCalibrator


# ---------------------------------------------------------------------------
# F3: DecisionConfig esit-esik (degenere ama gecerli) invariant'i
# ---------------------------------------------------------------------------


def test_decision_config_allows_equal_thresholds() -> None:
    """reject == accept GECERLI olmali (invariant `reject <= accept`, inclusive).

    Mutant `0 <= reject < accept <= 1` bu degenere konfigurasyonu ValueError ile
    reddederdi. Anlam: esit esikte abstain bandi bos kalir -- gecerli bir uc
    durum. Kurulum patlarsa (mutant) test KIRMIZI.
    """
    # Birden fazla nokta -- sinirin ozel bir sayida degil, esitlikte gecerli
    # oldugunu goster.
    for t in (0.0, 0.3, 0.5, 0.9, 1.0):
        cfg = DecisionConfig(accept_threshold=t, reject_threshold=t)
        assert cfg.accept_threshold == t
        assert cfg.reject_threshold == t

    # Karsit yon HALA korunmali: reject > accept gecersiz (invariant zayiflamasin).
    with pytest.raises(ValueError):
        DecisionConfig(accept_threshold=0.4, reject_threshold=0.6)


# ---------------------------------------------------------------------------
# C4: Platt negatif-hedef smoothing (y_minus = 1/(n_minus+2), 0 DEGIL)
# ---------------------------------------------------------------------------


def test_platt_yminus_smoothing_keeps_negative_target_above_zero() -> None:
    """Platt smoothing negatif hedefi 1/(n_minus+2) yapar -- ASLA tam 0 degil.

    Simetrik 2-nokta veri (pos@+4, neg@-4, her sinifta 1 ornek):
        y_plus  = (1+1)/(1+2) = 2/3
        y_minus = 1/(1+2)     = 1/3   (mutant: 0.0)
    Fit bu simetrik hedeflere TAM yakinsar (A = ln2/4). Dolayisiyla
    calibrate(-4) == 1/3 (orijinal). Mutant y_minus=0.0 negatif hedefi 0'a
    cektiginden calibrate(-4) ~0.006'ya iner -> assertion KIRMIZI.

    Bu, smoothing'in gozlemlenebilir davranisini (asiri-guven bastirma) pinler.
    """
    cal = PlattCalibrator(A=1.0, B=0.0)
    cal.fit([4.0, -4.0], [1, 0], max_iter=500, lr=0.2)

    p_neg = cal.calibrate(-4.0)
    p_pos = cal.calibrate(4.0)

    # Kritik ayirt-edici: smoothed negatif hedef 1/3 (mutant ~0.006).
    assert p_neg == pytest.approx(1.0 / 3.0, abs=0.05), (
        f"calibrate(-4)={p_neg:.5f}; smoothing kaldirilmis olabilir (y_minus=0?)"
    )
    # Negatif olasilik smoothing tabani nedeniyle 0'in belirgin uzerinde olmali.
    assert p_neg > 0.2
    # Simetri capasi (mutant'ta da gecerli -- ayirt edici degil, saglik kontrolu).
    assert p_pos == pytest.approx(2.0 / 3.0, abs=0.05)
