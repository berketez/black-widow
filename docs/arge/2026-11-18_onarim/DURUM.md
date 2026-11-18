# Karadul onarımı — durum (2026-11-18'den itibaren)

İş emri: `docs/arge/2026-11-18_genel_tarama/RAPOR.md` (§5 plan). Ortak brif: `ONARIM_BRIF.md`.
Bu dosya yaşayan durum kaydıdır: hangi paket kimde, ne birleşti, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür.

## Kurallar (bu oturum, Berke)
- Aynı anda en çok **5** Opus ajanı (Berke, 2026-11-18 onarım oturumu; tarama oturumundaki sınır 4'tü).
- Her ajan kendi git worktree'sinde (`.claude/worktrees/agent-*`, taban e9d2d08); dosya kümeleri ayrık. Ana oturum ajan commit'lerini doğrulayıp `main`'e alır (cherry-pick).
- Push her seferinde Berke'ye sorulur. Güvenlik bulgularını içeren rapor, güvenlik onarımları `main`'e girmeden push edilmez (K-7).

## Kararlar
| No | Karar | Kaynak |
|---|---|---|
| K-1 | **Beklet:** onarımı uzun sürecek katmanlar (bileşim şablonları, yapı kurtarma, hesaplama kolları) koşar, ama onarılıp masum ikili kapısından geçene kadar iddiaları rapora ve koda yazılmaz. Silme ya da kalıcı kapatma değil. | Berke, 2026-11-18 |
| K-2 | **Susturma yok, düzelt:** `kebap_ad` ve `api_param_reverse` ad üretmeye devam eder; hesaplamayla özgün ada yakın ve doğru ad üretecek biçimde onarılır (P12, ön kayıtlı ölçümle). Berke'nin sözü: "amacımız isim üretmek; düzelt, yakın ve doğru isim üretmek hesaplama ile". | Berke, 2026-11-18 |
| K-3 | Yön kabul: A türü (hiç çalışmayan kopyalar) silinir, B türü (bağlanmamış özellikler) bağlanır. Her silme kalemi paket başında "çağıran yok" kanıtıyla tek tek onaya sunulur. | Berke, 2026-11-18 (tarama oturumu) + "çöp kodları da sileceğiz" (onarım oturumu) |
| K-4 | K-3'ün B türünden çıkıyor: PDB / DWARF / Binary Ninja / TRex / Rust-Go / RTTI kanalları bağlanır; ad üretenler bayrak arkasında ve ölçülerek açılır. | K-3'ten |
| K-5 | **Uygulamaya gömülü:** yeniden kurulan imza veritabanı (yalnız tanımlanan/dışa aktarılan simgeler + ad başına kitaplık listesi) uygulama paketine gömülür. | Berke, 2026-11-18 |
| K-6 | Açık (güncelleme sorgusu; P17'den önce sorulacak). | — |
| K-7 | Rapor yerelde commit'lendi (5e49dd0); push güvenlik onarımlarından sonra. | öneri, uygulandı |
| K-8 | **Evet:** native olmayan hatlar için hat başına 3–5 açık kaynaklı örnek indirilecek. İndirmeden önce dosya adı, kaynak ve boyut listesi ayrıca onaya sunulur. | Berke, 2026-11-18 |
| K-9 | Açık: `~/karadul_olcum/runs/genel-tarama-2026-11-18` (2,0 GB) P00 tabanı alınana kadar kalır; silme onaya bağlı. | — |

## Paketler
Plan dışı yeni paket: **P-GÜV** (hedef çalıştırma ve ağ güvenliği: GHIDRA-07, 11, 13, MEK-03). RAPOR'da P15 / P16 / P-S / P20'ye dağılmış güvenlik kalemleri, raporun yayımlanabilmesi için öne alındı. Bu kalemler o paketlerin kapsamından düşer.

| Paket | Konu | Durum | Not |
|---|---|---|---|
| P00 | Ölçüm zemini (masum ikili kapısı + sağlamlık denetimi) | çalışıyor (1. tur) | |
| P19 | Native olmayan hatlar: güvenlik ve tanıma | çalışıyor (1. tur) | |
| P-GÜV | Hedef çalıştırma ve ağ güvenliği | çalışıyor (1. tur) | `stages.py`, `config.py`, `cli.py` bu pakette; bitmeden P-S1 / P15 başlamaz |
| P01 | İkili istihbarat | çalışıyor (1. tur) | |
| P02 | Anti-debug + paketleyici | çalışıyor (1. tur) | |
| P04a, P03, P06, P08, P-S1 | 2. tur adayları | bekliyor | yer açıldıkça |
