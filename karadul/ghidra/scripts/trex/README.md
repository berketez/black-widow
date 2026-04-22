# TRex Ghidra P-code Export Scripts

TRex projesinden (BSD-3) alindi. Karadul headless pipeline'ina entegre edilmistir.

- **Kaynak:** https://github.com/secure-foundations/trex
- **Paper:** Bosamiya et al. "Practical Type Reconstruction for Binary Code", USENIX Security 2025
- **Lisans:** BSD-3-Clause (karadul MIT lisansiyla uyumlu)
- **Son guncelleme:** 2026-04-22

## Dosyalar

- `PCodeExporter.java` — Ghidra headless -> `.pcode-exported` dosyasi (raw P-code listing)
- `VariableExporter.java` — Ghidra headless -> `.var-exported` dosyasi (stack pointer + degisken-varnode)

## Kullanim (karadul icinden)

```python
from karadul.pipeline.steps.trex_export import TRexExportStep
```

Adim, pipeline config'inde `trex.enabled: true` olmadigi surece otomatik atlanir (default: false).

Faz 2'de Ghidra headless cagrisini gercek olarak uygulayacak:

```python
from karadul.pipeline.steps.trex_export import TRexExportStep
# pipeline config'e ekle: trex.enabled = True
```

## Telif

Copyright (c) 2021-2025 Jay Bosamiya ve katkida bulunanlar (TRex projesi).
BSD-3-Clause: https://github.com/secure-foundations/trex/blob/main/LICENSE
