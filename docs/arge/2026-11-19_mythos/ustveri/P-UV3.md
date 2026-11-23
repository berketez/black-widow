# P-ÜV3 — Swift tip üst verisi okuyucu + `swift_metadata_recovery` (ilerleme)

Paket metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV3.md`. Ortak brifler: `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`,
`docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`.
Plan: `ustveri/PLAN.md` "P-ÜV3". Kararlar: A-10, A-13, A-14, A-27.

- Başlangıç: 2026-11-23 08:12. Taban commit `f2b0db5` (main; `git merge --ff-only main`, ileri sarma tamam).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Koşu dizini: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV3/`.
- Sert son 11:30.
- Makinede Swift ABI başlıkları yok (`/Library/Developer/CommandLineTools` altında `swift/ABI/*.h` aranıp bulunamadı);
  doğrulama kaynağı yerel örneklerin `/usr/bin/nm` + `xcrun swift-demangle` çıktısı. Araç zinciri: Apple Swift 6.4.2
  (swiftlang-6.4.2.1.9), hedef arm64-apple-macosx27.2.0.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 Ön kayıt | başladı | — |
| 2 Yerel örnekler + GT betiği | — | — |
| 3 Okuyucu (tip, erişim, nitelikli ad) + testler | — | — |
| 4 vtable / geçersiz kılma / uyum / tanık | — | — |
| 5 Üretici adım + yama | — | — |
| 6 Sağlamlık + mutasyon | — | — |
| 7 Keşif ölçümü (H0, H1, H5) | — | — |
| 8 Dondurma → H2, H3 bir kez | — | — |
| 9 Tam takım | — | — |
