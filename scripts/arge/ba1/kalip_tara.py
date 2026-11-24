"""BA-1: düzenli ifadelerde üstel / polinom geri izleme taraması (hüküm 4 ve 6b).

BA-2'de tarama mantığı ``scripts/measurement/kalip_denetimi.py``'ye taşındı
(tam takımın kapısı: ``tests/test_kalip_denetimi.py``); bu betik yalnız onu
içe aktarır, iki kopya yok. Yöntem ve kullanım ``kalip_denetimi`` belgesinde;
komut satırı aynı:

    python scripts/arge/ba1/kalip_tara.py tara --json <dosya> <yol> [<yol> ...]
    python scripts/arge/ba1/kalip_tara.py gercek --json <dosya> --ws <oturum> ...
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "measurement"))

from kalip_denetimi import *  # noqa: E402,F401,F403
from kalip_denetimi import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
