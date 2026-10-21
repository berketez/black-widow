# G6 LLM pilotu: model seçimi

- **Tarih:** 2026-10-19
- **Durum:** Sürüm 2 (2026-10-19 öğleden sonra). Sürüm 1 952018f ile commit'lendi. Sürüm 2'de Berke'nin kararlarıyla birincil model değişti (§0). Hiçbir model indirilmedi; iki model de diskte vardı.
- **Kapsam:** Plan v2 G6 (`docs/arge/2026-10-17_plan_v2.md` §5). Berke'nin kararı (2026-10-19): pilot yerel modelle yapılır. Gerekçeler: API fiyatları yüksek; öncü modeller tersine mühendislik isteklerinde engele takılabilir.
- **Bu klasördeki öteki belgeler:** `pilot_protokolu.md`, `gorulmemis_dilim_onkayit_taslak.md`.
- **Kanıt kayıtları:** Zamanla değişebilecek her iddia §9'da Claim / Evidence / Confidence / Date checked / What may change biçiminde durur. Metindeki [K#] etiketleri oraya bağlanır. Kaynak sırası: resmî model kartı ya da makale > arXiv > sürüm notları > blog > forum.

## 0. Karar (sürüm 2, Berke, 2026-10-19)

| | Birincil | İkinci model (hızlı kıyas; tam pilotta koşulur) |
|---|---|---|
| Model | Qwen3.8-27B | Gemma 4 26B-A4B-it, QAT |
| Dosya (diskte) | `~/.lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf` (16.810.714.336 B) ve görüntü kodlayıcı `mmproj-Qwen3.8-27B-BF16.gguf` (931.145.856 B) | `~/.lmstudio/models/lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit/` (3 safetensors, 15.608.838.574 B) |
| LM Studio anahtarı | `qwen/qwen3.8-27b` (mimari `qwen35`, Q4_K_M) | `google/gemma-4-26b-a4b-qat` (mimari `gemma4`, MLX 4 bit) |
| Üretici deposu | `Qwen/Qwen3.8-27B` (Apache-2.0; depo 2026-08-05) [K20] | `google/gemma-4-26B-A4B-it` (Apache-2.0; yayım 2026-04-02) [K5] |
| Çalışma zamanı | LM Studio'nun llama.cpp motorundaki `llama-server` (2.60.0), doğrudan ve yalın bayraklarla [K27][K28] | LM Studio 0.4.25+1 yerel sunucusu, mlx-llm motoru 1.13.1 [K27] |
| Bellek ve hız | Kuru koşuda ölçüldü (`pilot_protokolu.md` §8.1; kuru koşu yarıda durdu) | Ölçülmedi: kuru koşu Gemma'ya gelmeden durdu (2026-10-19) |
| Eğitim verisi zaman sınırı | Kesim beyan edilmemiş; depo 2026-08-05 → görülmemiş dilim sınırı **S = 2026-08-05** | Ön eğitim kesimi Ocak 2025 (beyan); yayım 2026-04-02 |

**Kararlar (Berke, 2026-10-19):**
- Birincil model diskteki Qwen3.8-27B GGUF. Qwen3.6-27B **indirilmeyecek**.
- `orcarouter/Qwen3.8-27B-Uncensored-MLX` **kullanılmayacak**: ağırlıkları üçüncü taraf değiştirmiş (ölçüt Ö4).
- Gemma 4 26B-A4B QAT ikinci model olarak tam pilotta koşulur.
- Çalışma zamanı LM Studio'nun OpenAI uyumlu yerel sunucusu. Log-olasılık ve belirlenimcilik sondada doğrulandı [K27]; ayrı bir Python sanal ortamı gerekmedi.
- **Kuru koşuda değişen (2026-10-19):** LM Studio'nun Qwen3.8 yüklemesi bellek eşiğini aştı (`llama-server` RSS 20,1 GiB; koşu bekçi tarafından durduruldu). Nedeni LM Studio'nun llama.cpp'ye verdiği ana bellek istem önbelleği (`--cache-ram` varsayılanı 8192 MiB), 32 bağlam kontrol noktası ve görüntü kodlayıcı. Qwen bu yüzden aynı motor ikilisiyle, bu üçü kapalı olarak doğrudan çalıştırılıyor. Yalın sunucunun belleği ~16,4 GiB RSS + ~1,1 GiB footprint; kuru kümenin 40 çağrısında çıktıları LM Studio'nunkiyle bayt bayt aynı [K28]. Gemma 4 LM Studio'da kalıyor.

**Sürüm 1'e göre değişiklik ve gerekçe:**
- Sürüm 1, görülmemiş dilim penceresini geniş tutmak için Ağustos 2026'da yayımlanan Qwen3.8'i ölçüt Ö2 ile elemişti (§3.1). Berke bu ödünleşimi tersine çevirdi: Model diskte, indirme gerekmiyor ve kod kıyaslarında en güçlü aday (LiveCodeBench v6 90,3; Qwen3.6-27B 83,9) [K20][K1]. LLM lehine okuma ilkesi (§0'daki sürüm 1 gerekçesi madde 3) de en güçlü modeli ister.
- Bedeli: Görülmemiş dilimin sınırı 2026-06-01'den **2026-08-05**'e kaydı. Kura gününe kadar aday penceresi ~3 aya iniyor (`gorulmemis_dilim_onkayit_taslak.md` §10).
- Ö2 bu yüzden sürüm 2'de "ağırlıkların ilk yayımı ≤ S" diye okunur; S = 2026-08-05.

**Sürüm 1'in önerisi (yerine geçti):** Birincil Qwen3.6-27B (`mlx-community/Qwen3.6-27B-4bit`, indirilecekti), yedek Gemma 4 26B-A4B QAT. Gerekçeleri aşağıda kayıt için duruyor.

## 0.1 Sürüm 1 önerisi (kayıt için)

| | Birincil | Yedek |
|---|---|---|
| Model | Qwen3.6-27B | Gemma 4 26B-A4B-it, QAT sürümü |
| Üretici deposu | `Qwen/Qwen3.6-27B` [K1] | `google/gemma-4-26B-A4B-it`; QAT: `google/gemma-4-26B-A4B-it-qat-q4_0-unquantized` [K5] |
| Çalıştırılacak dosyalar | `mlx-community/Qwen3.6-27B-4bit` (MLX, 4 bit) [K2] | `lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit` (MLX, 4 bit; **diskte var**) [K26] |
| Mimari | Yoğun, 27B. 64 katman; Gated DeltaNet ve kapılı dikkat blokları 16 bloklu düzende. Çok kipli; pilotta yalnız metin | MoE: 25,2B toplam, 3,8B etkin; 128 uzmandan 8'i + 1 paylaşımlı; 1024 jetonluk kayan pencere |
| Disk | 16,05 GB (indirilecek) | 15,61 GB (`~/.lmstudio/models` altında; dosya boyutları HF ile bayt bayt aynı) |
| En yüksek bellek | Ölçülmüş: 15,4 / 16,7 / 18,3 GB (1k / 4k / 8k bağlam) [K3] | Tahmin: ~16-17,5 GB (8-10k bağlam); kuru koşuda ölçülür |
| Hız (bu makine sınıfı) | Ölçülmüş: önek işleme ~189-198 jeton/sn, üretim ~20-21 jeton/sn [K3] | Topluluk verisi çelişkili: önek ~900-1.065, üretim ~40-76 jeton/sn [K7] |
| Bağlam | 262.144 jeton [K1] | 256K jeton [K5] |
| Lisans | Apache-2.0 [K1] | Apache-2.0 [K5] |
| Eğitim verisi zaman sınırı | Kesim belirtilmemiş. Üst sınır: depo 2026-04-21'de açıldı, ağırlıklar 2026-04-22'de yüklendi [K4] | Ön eğitim kesimi Ocak 2025 (üretici beyanı). Yayım 2026-04-02; QAT deposu 2026-04-29 [K5] |
| Çalışma zamanı | mlx 0.32.0 + mlx_lm 0.31.3, sabitlenmiş ayrı sanal ortam (§8) | Aynı |
| Seçim güveni | Orta | Orta |

**Gerekçe (kısa):**
1. İsim görevine dair bulunabilen tek aile düzeyi kanıt Qwen'den yana. REBench (2026), değerlendirdiği açık modeller arasında fonksiyon adı kurtarmada en yüksek F1'i Qwen3 ve Qwen2.5'in verdiğini yazıyor [K12]. Gemma 4 ve Qwen3.6 için doğrudan bir isim kıyası **bulunamadı**.
2. Bellek bütçesine sığan ve görülmemiş dilim için yeterince erken yayımlanmış adaylar arasında kod kıyasları en yüksek olan Qwen3.6-27B. LiveCodeBench v6: Qwen3.6-27B 83,9; Gemma 4 31B 80,0; Gemma 4 26B-A4B 77,1. Sayıların hepsi üretici beyanı [K1][K5][K8].
3. **LLM lehine okuma ilkesi** (`pilot_protokolu.md` §11). G8 kuralı, Karadul'u bir LLM'e karşı sınar. Zayıf bir model seçmek Karadul'u olduğundan iyi gösterir. Bu yüzden birincil model, sınırlar içindeki en güçlü aday olmalı.
4. Yedek başka bir aileden (Google) geliyor ve diskte hazır. 3-4 kat daha hızlı ve ön eğitim kesimini açıkça beyan ediyor. Birincil model kuru koşudaki kapılardan geçemezse indirme beklenmeden devreye girer. Ürün izindeki KaradulLM için de hızlı bir aday.
5. İki modelin ağırlıkları da Nisan 2026'da yayımlandı. Görülmemiş dilimin sınır tarihi (2026-06-01) ikisi için de geçerli. Model değişirse dilimi yeniden tasarlamak gerekmez.

**Pilot süresi (yalnız model zamanı):** Birincil için ~14 saat (aralık 12,1-15,4 saat), yedek için 3,4-5,1 saat. Ayrıntılar `pilot_protokolu.md` §13'te.

## 1. Kısıtlar

### 1.1 Makine (2026-10-19'da yerelde doğrulandı)

- `sysctl` ve `system_profiler` çıktısı: Apple M4 Max; 14 çekirdekli CPU (10 performans + 4 verim); 32 çekirdekli GPU; 36 GB birleşik bellek (38.654.705.664 bayt); Metal 4.
- Bu yapılandırmanın bellek bant genişliği 410 GB/sn [K9]. Üretim hızı bant genişliğiyle sınırlıdır. Hız tahminlerinin üst sınırı buradan gelir (§4.1).
- Disk: `/System/Volumes/Data` üzerinde 385 GB boş (`df -h`).
- Bütçe (görev metni): Modelin bellekteki kalıcı payı (ağırlık + KV önbelleği) ~20 GB'ı aşmamalı, çünkü aynı anda Ghidra (JVM) çalışabilir.

### 1.2 Çalışma zamanları (yerelde doğrulandı)

| Çalışma zamanı | Sürümler | Qwen3.5/3.6/3.8 mimarisi (`qwen3_5`) | Gemma 4 (`gemma4`) |
|---|---|---|---|
| Sistem Python (`/opt/anaconda3`) | mlx 0.30.4, mlx_lm 0.30.5 | **Yok** | **Yok** |
| LM Studio'nun gömülü MLX ortamı (`~/.lmstudio/extensions/backends/vendor/_amphibian/app-mlx-generate-mac14-arm64@34`) | Python 3.11; mlx 0.32.0; mlx_lm 0.31.3; mlx_vlm 0.6.5; transformers 5.14.1; tokenizers 0.22.2; huggingface_hub 1.24.0 | Var (`qwen3_5.py`, `qwen3_5_moe.py`) | Var (`gemma4.py`, `gemma4_text.py`) |
| LM Studio llama.cpp motoru | 2.50.0'a kadar | GGUF ile | GGUF ile |
| Ollama | İstemci 0.35.0; sunucu çalışmıyor | Denenmedi | Denenmedi |
| **LM Studio 0.4.25+1 yerel sunucusu (sürüm 2'de kullanılan)** | Seçili motorlar: llama.cpp 2.60.0 (GGUF), mlx-llm 1.13.1 (MLX). Görev metninde 2.50.0 ve 1.11.0 yazıyordu; LM Studio 2026-10-19 sabahı motorları güncellemiş | `qwen35` (GGUF) | `gemma4` (MLX) |

Sonuç: Sistemdeki mlx_lm 0.30.5, iki modelden hiçbirini yükleyemez. Sürüm 2'de LM Studio'nun sunucusu kullanılıyor (§8).

### 1.3 Diskte zaten bulunan modeller (görev metniyle çelişki)

Görev metninde "Önceki modeller 13 Ekim'de silindi" yazıyor. Dosya sistemi başka bir tablo gösteriyor: `~/.lmstudio/models` 53 GB tutuyor ve içinde dört model var. Dördü de Ağustos 2026'da indirilmiş.

| Dizin | Boyut | Dosya tarihi | Not |
|---|---|---|---|
| `lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit` | 15 GB | 2026-08-12 | Yedek öneri. Üç safetensors dosyasının, `config.json`'un (33.376 B) ve `chat_template.jinja`'nın (18.245 B) boyutu HF deposundakilerle bayt bayt aynı. sha256 karşılaştırması yapılmadı |
| `lmstudio-community/gemma-4-12B-it-QAT-GGUF` | 6,7 GB | 2026-08-13 | Daha küçük model; pilotta kullanılmaz |
| `lmstudio-community/Qwen3.8-27B-GGUF` (Q4_K_M) | 17 GB | 2026-08-17 | Ağustos 2026'da yayımlandı. Görülmemiş dilim için geç (§3.1) |
| `orcarouter/Qwen3.8-27B-Uncensored-MLX` | 15 GB | 2026-08-20 | Üçüncü tarafın değiştirdiği ağırlıklar ("uncensored"), kökeni belirsiz. Araştırmada **kullanılmaz** (ölçüt Ö4) |

- `~/.cache/huggingface/hub` altındaki `LLM4Binary/llm4decompile-6.7b-v1.5` ve `moonshotai/Kimi-K3` girdileri 4 KB'tır, ağırlık içermez. `~/.ollama` 64 KB.
- CLAUDE.md §28'deki "3 yerel model silindi (54 GB)" kaydı başka modellere ait olmalı. Hafıza kaydını düzeltmek ana oturumun işi.

## 2. Ölçütler

| # | Ölçüt | Tür | Eşik ya da yöntem |
|---|---|---|---|
| Ö1 | Bellek | Eleme | 4 bit nicemlemede, 8k bağlamda en yüksek bellek ≤ ~20 GB |
| Ö2 | Eğitim verisinin zaman sınırı | Eleme | Ağırlıkların ilk yayımı ≤ 2026-05-31 olmalı. Böylece 2026-06-01'den sonra açılmış projeler kesinlikle görülmemiş olur. Beyan edilmiş bir kesim varsa ayrıca kaydedilir |
| Ö3 | Lisans | Eleme | Araştırma, sonuç yayımı ve ürün denemesi serbest olmalı: Apache-2.0, MIT ya da eşdeğeri |
| Ö4 | Değişmemiş ağırlık | Eleme | Üreticinin ağırlığı ya da onun bilinen bir nicemleme dönüşümü. "uncensored" ya da "abliterated" gibi üçüncü taraf değişiklikleri kabul edilmez |
| Ö5 | Görev kalitesi | Sıralama | Önce fonksiyon adı kurtarma kıyaslarında aile düzeyi kanıta bakılır. Yoksa kod kıyaslarına (LiveCodeBench vb.) bakılır |
| Ö6 | Talimat izleme | Eleme | Serbest istemle JSON üretebilmeli ve "çekimser kal" talimatını izleyebilmeli |
| Ö7 | Hız | Sıralama | Bu makine sınıfında ölçülmüş değer; yoksa bant genişliğinden hesap |
| Ö8 | Bağlam | Eleme | ≥ 16K jeton. Pilottaki en uzun istem ~7,6K jeton; üstüne düşünme bütçesi gelir |
| Ö9 | Reddetme | Kapı | Kamuya açık veri bulunamadı (§6). Kuru koşuda ölçülür |

## 3. Aday havuzu (Ekim 2026)

### 3.1 Genel modeller

| Model (HF deposu) | Tür | 4 bit disk / bellek | Bağlam | Lisans | Kesim / ilk yayım | Kod kıyasları (üretici beyanı) | Karar |
|---|---|---|---|---|---|---|---|
| Qwen3.6-27B (`Qwen/Qwen3.6-27B`) | Yoğun 27B | 16,05 GB / 15,4-18,3 GB, ölçülmüş [K3] | 262K | Apache-2.0 | Belirtilmemiş / 2026-04-22 [K4] | SWE-bench Verified 77,2; LiveCodeBench v6 83,9 [K1] | Sürüm 1'in birincili; sürüm 2'de indirilmedi |
| Gemma 4 26B-A4B (`google/gemma-4-26B-A4B-it`, QAT) | MoE; 25,2B toplam, 3,8B etkin | 15,61 GB / ~16-17,5 GB, tahmin | 256K | Apache-2.0 | Ocak 2025 / 2026-04-02; QAT 2026-04-29 [K5] | LiveCodeBench v6 77,1; Codeforces ELO 1718 [K5] | Sürüm 1'de yedek; **sürüm 2'de ikinci model** |
| Gemma 4 31B (`google/gemma-4-31B-it`) | Yoğun 30,7B | ~17-18 GB / ~19-20 GB ve üstü, tahmin | 256K | Apache-2.0 | Ocak 2025 / 2026-04-02 | LiveCodeBench v6 80,0; Codeforces ELO 2150 [K8] | Elendi (Ö1). Bellek sınırda. Üretim hızı ~15-19 jeton/sn; bu sayılar topluluktan ve daha büyük bellekli makinelerden [K10] |
| Qwen3.6-35B-A3B (`Qwen/Qwen3.6-35B-A3B`) | MoE; 35,95B toplam, ~3B etkin | ~20,2 GB (hesap: 35,95e9 × 4,5 bit) | 262K | Apache-2.0 | Belirtilmemiş / 2026-04-15 [K24] | — | Elendi (Ö1). 4 bitte bütçeyi aşıyor |
| Qwen3.8-27B (`Qwen/Qwen3.8-27B`) | Yoğun 27B, Qwen3.6 ile aynı mimari ailesi | GGUF Q4_K_M 16,8 GB (diskte) | 262K | Apache-2.0 | Belirtilmemiş / depo 2026-08-05, son değişiklik 2026-08-14 [K20] | LiveCodeBench v6 90,3; SWE-bench Pro 61,7 [K20] | Sürüm 1'de elenmişti (Ö2). **Sürüm 2'de birincil** (Berke'nin kararı, §0); görülmemiş dilim sınırı S = 2026-08-05 |
| gpt-oss-20b (`openai/gpt-oss-20b`) | MoE; 21B toplam, 3,6B etkin; MXFP4 | Disk doğrulanmadı / ≤ 16 GB (kart) | 131.072 | Apache-2.0 | Haziran 2024 / 2025-08-04 [K21] | Kartta kod kıyası yok | Üçüncü sırada. Eski bir model; "harmony" biçimi ayrı bir istem düzeni ister |
| Devstral Small 2 (`mistralai/Devstral-Small-2-24B-Instruct-2512`) | Yoğun 24B; FP8 dağıtılıyor | ~14 GB / ~15-16 GB, tahmin | 256K | Apache-2.0 | Belirtilmemiş / 2025-11-28 [K22] | SWE-bench Verified 68,0 [K22] | Dördüncü sırada. Ajan işleri için yapılmış; isim görevine dair kanıt yok |
| OLMo 3.1 32B Instruct (`allenai/Olmo-3.1-32B-Instruct`) | Yoğun 32,2B | ~18 GB / ~20 GB ve üstü, tahmin | 65.536 (ikincil kaynak) | Apache-2.0 | Kesim belirtilmemiş, ama eğitim verisi açık (Dolma 3, Dolci) / 2025-12-10 [K23] | — | Pilotta yok (Ö1 sınırda). Eğitim verisi açık olan tek aday: görülmemiş dilimde sızıntı doğrudan denetlenebilir. Makale için not edildi |

Notlar:
- "4 bit bellek" sütunundaki tahminlerin hesabı: parametre sayısı × ~4,5 bit (grup ölçekleri dahil) + 8k bağlamın KV önbelleği. Ölçülmüş tek değer Qwen3.6-27B'ninki.
- HF'deki `createdAt`, deponun açıldığı tarihtir. Depo önce gizli açılıp sonra herkese açılmış olabilir. Ağırlıklar bu tarihten önce herkese açık olamayacağı için tarih, güvenli bir alt sınırdır.

### 3.2 Tersine mühendisliğe özgü modeller

| Model | Ne yapıyor | Neden pilotta yok |
|---|---|---|
| LLM4Decompile v1.5, v1.6, v2 (`LLM4Binary/llm4decompile-*`; 1,3B-22B) | Derleme kodunu ya da Ghidra sözde kodunu derlenebilir C'ye çeviriyor [K14] | Fonksiyon adı önermiyor: örnek girdi `<func0>:` ile başlıyor, fonksiyon adı yer tutucuyla geçiyor. Yalnız Linux x86-64 destekleniyor [K14] |
| SK²Decompile (`LLM4Binary/sk2decompile-struct-6.7b` ve `-ident-6.7b`; ICLR 2026) | İki aşamalı: önce yapı iskeleti, sonra tanımlayıcı adları [K15] | IDA sözde kodu ve Linux x64 ile eğitilmiş; girdi özel bir normalleştirmeden geçiyor. Model kartı değişken adlarını anıyor, fonksiyon adını açıkça anmıyor. Talimat izlemediği için kanıt paketi (koşul C) verilemiyor |
| SymGen (OSUSecLab; NDSS 2025) | Ghidra çıktısından fonksiyon adı üretiyor; Code Llama tabanı üstüne LoRA [K16] | LoRA ağırlıkları depoda. Eğitim verisi ELF: x86-64, x86-32, ARM, MIPS; arm64 Mach-O yok. 34B taban, 4 bitte ~19 GB. Plan G33'teki literatür kıyası için kendi veri setinde anlamlı |
| ReCopilot (QI-ANXIN; arXiv 2505.16366) | Qwen2.5-Coder-7B tabanlı; fonksiyon adı ve tip tahmini | Herkese açık ağırlık **bulunamadı** [K17] |
| Idioms (Dramko vd., 2025) | Kod ve tip tanımını birlikte tahmin eden ince ayarlı modeller | Yayımlanan modellerin fonksiyon adı önerip önermediği doğrulanamadı |

Sonuç: Özel modellerin her biri tek bir girdi biçimine (IDA ya da Ghidra çıktısı, Linux x86-64) ve tek bir çıktı biçimine (kodun tamamı) göre eğitilmiş. Pilotun üç ihtiyacını karşılamıyorlar: arm64 Mach-O girdisi, talimatla verilen kanıt paketi ve çekimser kalabilen JSON çıktısı.

### 3.3 İsim görevine dair kanıt

- **REBench (arXiv 2604.27319, AIWare 2026'nın genişletilmiş sürümü):** Makaleye göre fonksiyon adı kurtarmada Qwen3 ve Qwen2.5, x86'da da ARM'da da tutarlı biçimde en yüksek F1'i alıyor. Qwen3 (14B), WizardCoder'ı (15B) geçiyor; Qwen2.5'in ince ayarlı türevi DeepSeek-R1 ise Qwen2.5'in gerisinde kalıyor [K12].
- **Shang vd. (arXiv 2504.21803; ICSME 2024 makalesinin genişletilmiş sürümü):** Kod modelleri genel modellerden biraz daha iyi. Büyüklük tek başına belirleyici değil: x64 O0'da Code Llama-34B'nin F1'i 26,75, Code Llama-70B'ninki 24,90 (IDA çıktısı, token F1) [K11].
- **Ge vd. (FITEE 2026, cilt 27, sayı 8):** Kod odaklı modeller genel modelleri tutarlı biçimde geçiyor. Büyüklük tek başına tekdüze kazanç getirmiyor. Fonksiyonlar arası bağlam yardımcı oluyor. Yalnız özet okunabildi [K13].
- **REFORGE (arXiv 2607.07738):** Qwen3 Coder dahil 7 modelin ortalama token F1'i 0,18-0,29, medyanı 0. Tam eşleşme %1,9-7,1 (`docs/arge/2026-10-15_makale/veri_setleri.md`, satır 60) [K18].
- **Sonuç:** Gemma 4 ve Qwen3.6 için doğrudan bir isim kıyası **bulunamadı**. Seçim aile düzeyi kanıta ve genel kod kıyaslarına dayanıyor; güvenin "orta" olmasının nedeni bu.
- Ge vd.'nin "fonksiyonlar arası bağlam yardımcı oluyor" bulgusu, koşul C'nin (kanıt paketi) neden ayrıca ölçüldüğünü destekliyor.

## 4. Hız, bellek ve süre

### 4.1 Ölçülmüş ve hesaplanmış değerler

| Model | Kaynak | Önek işleme (jeton/sn) | Üretim (jeton/sn) | En yüksek bellek |
|---|---|---|---|---|
| Qwen3.6-27B, 4 bit | oMLX v0.4.1; M4 Max, 32 çekirdekli GPU, 36 GB; 2026-06-04 [K3] | 189,1 (1k), 197,5 (4k), 198,1 (8k) | 20,9 / 20,5 / 19,8 | 15,4 / 16,7 / 18,3 GB |
| Qwen3.6-27B, 6 bit | oMLX v0.3.6; aynı makine sınıfı; 2026-04-24 [K3] | 177,0 (1k) / 156,8 (4k) | 13,2 / 12,0 | 22,1 / 23,5 GB (bütçe dışı) |
| Gemma 4 26B-A4B, 4 bit | İki arama özeti çelişiyor. Biri 32 çekirdek / 36 GB için bir satır veriyor (4k: önek 1.065, üretim 75,7), öteki bu yapılandırmada satır bulamıyor. 40 çekirdekte 1k'da üretim 51-99 [K7] | ~900-1.065 (tahmin) | ~40-76 (tahmin) | Ölçüm yok |

Bant genişliğinden üst sınır (hesap): Üretimde her jeton için etkin ağırlıkların tamamı bellekten okunur.
- Qwen3.6-27B: jeton başına ~15 GB → 410 / 15 ≈ 27 jeton/sn üst sınır. Ölçülen 20,5, yani verim ~%75.
- Gemma 4 26B-A4B: 3,8B etkin parametre × ~5 bit ≈ 2,4 GB; paylaşılan katmanlarla jeton başına ~2,5-3,4 GB → 120-165 jeton/sn üst sınır. Topluluk değerleri bunun yarısı dolayında.

### 4.2 İstem uzunluğu (geliştirme seti, ölçüldü)

Ölçüm yöntemi: 15 Ekim Apple strip koşularındaki (`workspaces/2026-10-15_oturum_scratchpad/macho/runs_apple/`) isim bekleyen fonksiyonların Ghidra C'si, yerel tokenizer dosyalarıyla sayıldı. Koşular eski: htop o gün Go programı sanılıyordu. Sayılar yalnız boyut tahmini içindir.

| Program | Fonksiyon | Ortalama | Medyan | p90 | p95 | > 6.000 jeton |
|---|---|---|---|---|---|---|
| htop | 597 | 1.959 | 968 | 4.009 | 6.311 | 31 (%5,2) |
| tmux | 2.560 | 2.398 | 1.197 | 5.159 | 8.034 | 215 (%8,4) |

- Tablo Gemma 4 tokenizer'ıyla sayıldı; Qwen3.5 ailesinin tokenizer'ı %1-2 daha az jeton veriyor.
- Kod 6.000 jetonda kırpılınca ortalama: htop 1.581, tmux 1.883.
- Kanıt paketi (komşu adları olmadan): ortalama 182 jeton (htop) ve 250 jeton (tmux); p99 sırasıyla 751 ve 1.065.
- İstem şablonları (`pilot_protokolu.md` §4): sistem metni 309-318 jeton; yanıt biçimi 42-102 jeton; kullanıcı çerçevesi 15-174 jeton.
- Ortalama istem uzunluğu: B ≈ 2.120, B-Ç ≈ 2.180, C ≈ 2.570, C-Ç ≈ 2.630 jeton. En uzun istem ≈ 7.600 jeton.

### 4.3 Pilot süresi (özet)

Ayrıntılı hesap: `pilot_protokolu.md` §13. 300 fonksiyon; dört koşul (B, B-Ç, C, C-Ç); B ve C'nin belirlenimcilik tekrarı; 100 fonksiyonda düşünme kipi; kuru koşu.

| Model | Ana koşular | Belirlenimcilik tekrarı | Düşünme kipi alt kümesi | Kuru koşu | Toplam |
|---|---|---|---|---|---|
| Qwen3.6-27B | 5,5 sa | 2,7 sa | 5,0 sa (3,1-6,5) | 0,7 sa | **~14 sa** (12,1-15,4) |
| Gemma 4 26B-A4B | 1,3-1,7 sa | 0,6-0,9 sa | 1,3-2,4 sa | 0,2 sa | **3,4-5,1 sa** |

Model yükleme, araç yükü ve aynı anda koşan Ghidra için %20 pay eklenmelidir. Etiketleme süresi bu tabloya dahil değil (`pilot_protokolu.md` §13).

## 5. Lisans

- İki model de Apache-2.0 [K1][K5]. Araştırma, sonuçların yayımı ve ürün denemesi serbest. Gemma 4 ile Google, önceki Gemma Kullanım Koşulları'ndan Apache-2.0'a geçti (ikincil kaynaklar [K5]).
- Nicemlenmiş türevler aynı lisansla dağıtılıyor (`lmstudio-community` sayfası Apache-2.0 diyor [K26]).
- Ağırlıklar yeniden dağıtılmayacak. Makalede model kimliği, revizyon ve sha256 değerleri verilir.

## 6. Reddetme eğilimi

- **Bulunamadı:** Gemma 4'ün ya da Qwen3.6'nın decompile edilmiş kodda isim isteklerini reddetme oranını ölçen bir çalışma.
- Öncü modellerde aşırı reddetmeye dair tek bir anekdot bulundu: arama özetine göre arXiv 2605.17046, ön denemelerde Claude Opus 4.7'nin belirgin biçimde aşırı reddettiğini yazıyor; makale açılıp okunmadı [K19]. Bu, Berke'nin endişesini destekleyen ama genellenemeyecek tek bir gözlem.
- Önlemler:
  - Kuru koşuda 20 fonksiyonluk bir reddetme sondası koşulur (`pilot_protokolu.md` §8). Eşik aşılırsa yedeğe geçilir.
  - İstem, işin gerçek bağlamını tek cümleyle söyler ("academic study", "open-source program").
- "Uncensored" türevler kullanılmaz (Ö4). Ağırlık değişikliği sonucu etkiler ve tekrarlanabilirliği bozar.

## 7. Öneri ve gerekçe (ayrıntılı)

**Birincil: Qwen3.6-27B, 4 bit MLX.**
- Eleme ölçütlerinin (Ö1-Ö4, Ö6, Ö8) hepsini geçiyor. Bellek ve hız, bu makine sınıfında ölçülmüş tek aday.
- Görev kanıtı aile düzeyinde (REBench) ve kod kıyaslarında, bütçeye sığan adaylar arasında en güçlüsü.
- Zayıf yanları: Eğitim kesimi beyan edilmemiş; görülmemiş dilimin sınırı yalnız yayım tarihine dayanıyor. Yoğun bir model olduğu için yedekten 3-4 kat yavaş. 4 bitin bf16'ya göre kalite kaybı bu makinede ölçülemez (8 bit sürüm ~28 GB, bütçe dışı).

**Yedek: Gemma 4 26B-A4B-it, QAT, 4 bit MLX.**
- Diskte var, indirme gerektirmiyor. Nicemleme farkındalıklı eğitimden (QAT) geçmiş bir sürüm, yani 4 bitteki kayıp için üretici önlem almış.
- Ön eğitim kesimini (Ocak 2025) açıkça beyan ediyor. İstenirse görülmemiş dilime, yalnız bu model için geçerli, daha geniş bir "beyan sonrası" katman eklenebilir (`gorulmemis_dilim_onkayit_taslak.md` §1.3).
- Yedeğe geçiş, `pilot_protokolu.md` §8'deki kapılara bağlıdır: yükleme ya da şablon hatası, JSON geçerliliği < %95, reddetme sondasında ≥ 2/40 ret, belirlenimcilik < 19/20, bellek > 20 GB.

**İsteğe bağlı (Berke kararı): Yedeği de tam pilotta koşmak.**
- Maliyet: Model zamanı 3,4-5,1 saat artar. Etiketlenecek benzersiz aday sayısı ~%30-40 büyür.
- Kazanç: İki ayrı aileden sonuç alınır. G8 kararı, LLM lehine ilkeyle, yakın oranı yüksek olan modelle okunur. Ayrıca KaradulLM için hızlı modelin tabanı ölçülmüş olur.

**Neden Qwen3.8-27B değil:**
- En güçlü aday bu (LiveCodeBench v6 90,3) ve diskte GGUF kopyası var.
- Ancak ağırlıkları Ağustos 2026'da yayımlandı. Görülmemiş dilimin sınırı Eylül 2026'ya kayar; dilim yalnız 1-3 aylık, olgunlaşmamış projelerden oluşur.
- Diskteki MLX kopyası üçüncü tarafın değiştirdiği bir sürüm.
- İstenirse geliştirme setinde duyarlılık koşusu olarak eklenebilir; o durumda görülmemiş dilim bu modelle okunmaz.

**Neden Gemma 4 31B değil:** 4 bitte bellek ~19-20 GB ve üstüne çıkıyor; Ghidra ile birlikte bütçeyi zorlar. Üretim hızı ~15-19 jeton/sn. Kod kıyaslarında da Qwen3.6-27B'nin gerisinde.

## 8. Kurulum (sürüm 2: LM Studio; indirme yok)

1. **Çalışma zamanı:** Gemma 4 için LM Studio 0.4.25+1 yerel sunucusu, `http://localhost:1234` (LM Studio hizmet olarak çalışıyor). Qwen3.8 için aynı LM Studio kurulumundaki `llama-server` ikilisi (llama.cpp motoru 2.60.0) yalın bayraklarla, `http://127.0.0.1:8137` [K28]. Sistem paketlerine ve anaconda'ya dokunulmadı; Python sanal ortamı kurulmadı; hiçbir şey indirilmedi.
2. **Yükleme:** `lms load <anahtar> -c 10240 --gpu max --parallel 1 --no-speculative-draft-mtp --identifier <kimlik>`. Kimlikler: `g6-qwen38`, `g6-gemma4`. Harness aynı anda tek model yükler; model değiştirirken öncekini boşaltır.
3. **Çağrı:** `/v1/chat/completions` ile sıcaklık 0, tohum 20261019, `logprobs: true`. Düşünme kapalıyken `reasoning_effort: "none"`. Künye için ayrıca `/api/v0/chat/completions` çağrılır; bu uç motor adını ve sürümünü, model bilgisini ve hız istatistiğini veriyor ama log-olasılık vermiyor [K27].
4. **Doğrulama:** Model dosyalarının sha256'sı künyede (`workspaces/2026-10-19_g6_pilot/kunye/`). llama.cpp için LM Studio'nun geçirdiği sohbet şablonu dosyasının sha256'sı da künyeye yazılır; MLX için modelin `chat_template.jinja` dosyasının.
5. **Bilinen risk:** LM Studio motorları kendiliğinden güncelleyebiliyor (bu sabah 2.50.0 → 2.60.0 ve 1.11.0 → 1.13.1 oldu). Her yüklemede künye motor sürümünü yeniden yazar. Koşu sırasında sürüm değişirse bu künyelerde görünür ve raporlanır.
6. **Sürüm 1'in kurulum planı** (`mlx-community/Qwen3.6-27B-4bit` indirmesi ve mlx 0.32.0 + mlx_lm 0.31.3 sanal ortamı) uygulanmadı.

## 9. Kanıt kayıtları

Her kayıt için Date checked: 2026-10-19.

**K1 — Qwen3.6-27B model kartı**
- Claim: Lisans Apache-2.0. 64 katman. 262.144 jetonluk yerel bağlam. Eğitim kesimi belirtilmemiş. SWE-bench Verified 77,2 (iç ajan iskeletiyle); LiveCodeBench v6 83,9. Düşünme kipi varsayılan olarak açık; `enable_thinking: False` ile kapanıyor. Önerilen örnekleme: düşünmesiz kipte sıcaklık 0,7, top_p 0,8, top_k 20, presence_penalty 1,5.
- Evidence: https://huggingface.co/Qwen/Qwen3.6-27B
- Confidence: Kart bilgileri için yüksek. Kıyas sayıları üretici beyanı olduğu için orta.
- What may change: Kart ve depo revizyonu güncellenebilir.

**K2 — mlx-community/Qwen3.6-27B-4bit**
- Claim: Depo var (`createdAt` 2026-04-22T14:07:38Z). Üç safetensors parçası, toplam 16.054.541.599 bayt.
- Evidence: https://huggingface.co/api/models/mlx-community/Qwen3.6-27B-4bit/tree/main ; https://huggingface.co/api/models?search=Qwen3.6-27B&author=mlx-community
- Confidence: Yüksek (HF API).
- What may change: Depo yeniden yüklenebilir. Bu yüzden revizyon sabitlenir.

**K3 — Qwen3.6-27B'nin M4 Max'teki hızı ve belleği**
- Claim: 4 bitte, M4 Max (32 çekirdekli GPU, 36 GB) üzerinde önek işleme 189-198 jeton/sn, üretim 19,8-20,9 jeton/sn, en yüksek bellek 15,4-18,3 GB (1k-8k bağlam). 6 bitte üretim 12-13 jeton/sn, bellek 22-23,5 GB.
- Evidence: https://omlx.ai/benchmarks/68e0ez71 (4 bit, 32 çekirdek, oMLX v0.4.1) ; https://omlx.ai/benchmarks/vtu1646l (6 bit, 32 çekirdek) ; tutarlılık denetimi: https://omlx.ai/benchmarks/2mo1fii4 (Qwen3.6-27B-MTP-4bit, 40 çekirdek: 1k'da 239,5 / 28,6)
- Confidence: Orta. Topluluk ölçümü, tek koşu; oMLX, mlx_lm'den farklı bir sunucu. Değerler aynı donanım sınıfında ve 40 çekirdekli ölçümle bant genişliği oranında tutarlı.
- What may change: mlx ve oMLX sürümleri, istem uzunluğu dağılımı. Kuru koşu ölçümü bu kaydın yerine geçer.

**K4 — Qwen3.6-27B'nin yayım tarihi**
- Claim: Depo 2026-04-21T07:50:43Z'de açıldı. "Upload folder using huggingface_hub" commit'i 2026-04-22 tarihli. Ağırlıklar 2026-04-21'den önce herkese açık olamaz.
- Evidence: https://huggingface.co/api/models/Qwen/Qwen3.6-27B ; https://huggingface.co/Qwen/Qwen3.6-27B/commits/main ; ikincil: https://docs.apiyi.com/en/news/qwen-3-6-opensource-launch
- Confidence: Yüksek (HF kaydı).
- What may change: Değişmez. Ancak ağırlıkları değiştiren yeni bir revizyon gelirse sınır o revizyonun tarihine kayar.

**K5 — Gemma 4 26B-A4B-it model kartı ve yayımı**
- Claim:
  - Lisans Apache-2.0.
  - 25,2B toplam, 3,8B etkin parametre; 256K bağlam.
  - Kartın cümlesi: "with a cutoff date of January 2025" (ön eğitim verisi için).
  - LiveCodeBench v6 77,1; Codeforces ELO 1718.
  - Aile: E2B, E4B, 12B Unified, 26B A4B, 31B.
  - Depo `createdAt` 2026-03-11; "Preparing for release!" commit'i 2026-04-02. Herkese açık yayım 2 Nisan 2026.
  - Google'ın QAT depoları: `google/gemma-4-26B-A4B-it-qat-q4_0-unquantized` (2026-04-29) ve `google/gemma-4-26B-A4B-it-qat-q4_0-gguf` (2026-05-01).
- Evidence: https://huggingface.co/google/gemma-4-26B-A4B-it ; https://huggingface.co/api/models/google/gemma-4-26B-A4B-it ; https://huggingface.co/api/models?search=gemma-4-26B-A4B&author=google ; https://discuss.ai.google.dev/t/gemma-4-launch-announcement/138069 ; https://gigazine.net/gsc_news/en/20260403-google-released-gemma-4
- Confidence: Lisans, büyüklük ve yayım tarihi için yüksek (kart ve birden çok kaynak). Kesim için orta: yalnız ön eğitimi kapsayan bir üretici beyanı; son eğitim verisinin tarihi açıklanmamış.
- What may change: Kart güncellenebilir. QAT eğitiminin verisi açıklanmadı.

**K6 — Gemma 4 sohbet şablonu değişiklikleri**
- Claim: `google/gemma-4-26B-A4B-it` deposunda şablonu ya da araç çağrısı biçimini değiştiren commit'ler var: 2026-04-10 (başlığa göre büyük olasılıkla), 04-28, 05-18 ve 07-15. 2026-07-20'de de `tokenizer_config.json` değişti. Hangi commit'in ağırlık dosyasına dokunduğu sayfadan görülemedi.
- Evidence: https://huggingface.co/google/gemma-4-26B-A4B-it/commits/main
- Confidence: Commit başlıkları için yüksek.
- What may change: Yeni şablon düzeltmeleri gelebilir.

**K7 — Gemma 4 26B-A4B'nin M4 Max'teki hızı**
- Claim: 4 bitte önek işleme ~900-1.065 jeton/sn, üretim ~40-76 jeton/sn.
- Evidence: Arama özetleri (oMLX topluluk listeleri; https://omlx.ai/benchmarks/1q9brity); https://llmcheck.net/models/gemma-4-26b-a4b-on-m4-max/ (bant genişliğinden tahmin: 40 jeton/sn); https://markaicode.com/benchmarks/hugging-face-gemma-4-m4-max-throughput-benchmark/ (75-85 jeton/sn, doğrulanmamış)
- Confidence: Düşük. Kaynaklar çelişiyor; 32 çekirdekli satır sayfa düzeyinde doğrulanamadı.
- What may change: Kuru koşu ölçümü bu kaydın yerine geçer.

**K8 — Gemma 4 31B-it**
- Claim: Apache-2.0; 30,7B parametre; yoğun; 256K bağlam; ön eğitim kesimi Ocak 2025; LiveCodeBench v6 80,0; Codeforces ELO 2150.
- Evidence: https://huggingface.co/google/gemma-4-31B-it
- Confidence: Yüksek (kart). Kıyaslar üretici beyanı.
- What may change: Kart.

**K9 — M4 Max'in bellek bant genişliği**
- Claim: 14 çekirdekli CPU / 32 çekirdekli GPU yapılandırmasında 410 GB/sn. 40 çekirdekli yapılandırmada 546 GB/sn.
- Evidence: https://everymac.com/systems/apple/macbook_pro/specs/macbook-pro-m4-max-14-core-cpu-32-core-gpu-14-2024-specs.html ; https://www.notebookcheck.net/Apple-M4-Max-14-cores-Processor-Benchmarks-and-Specs.920365.0.html ; https://appleinsider.com/articles/24/10/30/new-macbook-pro-arrives-with-m4-pro-m4-max-and-a-black-colorway
- Confidence: Yüksek (birbirinden bağımsız birden çok kaynak).
- What may change: Donanım belirtimi değişmez.

**K10 — Gemma 4 31B'nin hızı**
- Claim: 64 GB ve 128 GB'lık M4 Max'lerde, kısa bağlamda üretim ~15,5-18,9 jeton/sn, önek ~195-198 jeton/sn. 36 GB'ta 4 bitin sığıp sığmadığı tartışmalı.
- Evidence: Arama özeti (oMLX topluluk satırları; https://willitrunai.com/de/can-run/gemma-4-31b-on-m4-max-36gb)
- Confidence: Düşük.
- What may change: —

**K11 — Shang vd., 2504.21803**
- Claim: x64 O0'da (IDA, strip'li, token F1) en iyi kod modeli Code Llama-34B (F1 26,75), en iyi genel model Llama-2-13B (22,68), ChatGPT 18,08. Code Llama-70B (24,90), 34B'nin gerisinde.
- Evidence: https://arxiv.org/html/2504.21803v1 (Tablo 3)
- Confidence: Orta-yüksek. Metnin "Findings 1" bölümü ile Tablo 3 arasında ARM ve MIPS değerlerinde tutarsızlık var; x64 değeri ikisinde de aynı.
- What may change: Hakemli sürümde değerler değişebilir.

**K12 — REBench**
- Claim: Makalenin metnine göre (WebFetch ile sayfadan birebir alınan cümlelerden aktarıldı) fonksiyon adı kurtarmada Qwen3 ve Qwen2.5, x86 ve ARM'da tutarlı biçimde en yüksek F1'i alıyor; Qwen3 (14B), WizardCoder'ı (15B) geçiyor; DeepSeek-R1, Qwen2.5'in gerisinde kalıyor.
- Evidence: https://arxiv.org/html/2604.27319 (Tablo 3 ve ilgili metin)
- Confidence: Orta. Cümleler sayfadan alıntılandı, ama tablo sayıları okunmadı ve kullanılmadı. Hafıza kaydı `karadul-llm-olcek-literatur.md`, WebFetch'in özet katmanının bu makale için daha önce uydurma bir tablo ürettiğini not ediyor.
- What may change: Hakemli sürüm.

**K13 — Ge vd., FITEE 2026**
- Claim: Kod odaklı LLM'ler genel modelleri tutarlı biçimde geçiyor; büyüklük tek başına tekdüze kazanç getirmiyor; yapısal olarak kurtarılabilen fonksiyonlar arası bağlam isim tahminini iyileştiriyor.
- Evidence: https://journal.hep.com.cn/fitee/EN/10.1631/ENG.ITEE.2026.0017
- Confidence: Orta-düşük. Yalnız özet okundu; modeller ve sayılar görülmedi.
- What may change: —

**K14 — LLM4Decompile**
- Claim: Fonksiyon `func0` yer tutucusuyla geçiyor: README, decompile edilecek fonksiyonun adının bu yer tutucunun yerine yazılmasını söylüyor ve örnek girdi `<func0>:` ile başlıyor. Yalnız Linux x86_64 destekleniyor. v2 (Ref) modelleri Ghidra sözde kodunu iyileştiriyor. v1.6 modelleri 2025'te yayımlandı. Proje haberlerinde son olay SK²Decompile (2025-10-04).
- Evidence: https://github.com/albertan017/LLM4Decompile ; https://huggingface.co/LLM4Binary ; https://arxiv.org/abs/2403.05286
- Confidence: Yüksek (README).
- What may change: Yeni sürüm.

**K15 — SK²Decompile**
- Claim: İki model: `LLM4Binary/sk2decompile-struct-6.7b` ve `LLM4Binary/sk2decompile-ident-6.7b`. Lisans MIT; Llama mimarisi. Girdi IDA sözde kodu (Linux x64), önce normalleştirilir. ICLR 2026.
- Evidence: https://huggingface.co/LLM4Binary/sk2decompile-struct-6.7b/blob/main/README.md ; https://iclr.cc/virtual/2026/poster/10007876
- Confidence: Orta. Tanımlayıcı modelinin fonksiyon adını da verip vermediği belgelenmemiş.
- What may change: —

**K16 — SymGen ağırlıkları**
- Claim: LoRA ağırlıkları depodaki `lora_weights/` klasöründe. Taban örneği `codellama/CodeLlama-34b-Instruct-hf`. Lisans Apache-2.0. Girdi Ghidra çıktısı; eğitim verisi x86_64, x86_32, arm, mips.
- Evidence: https://github.com/OSUSecLab/SymGen
- Confidence: Orta. README'den alındı; klasörün içeriği görülmedi.
- What may change: —

**K17 — ReCopilot**
- Claim: Qwen2.5-Coder-7B tabanlı. Checkpoint adları `recopilot-v0.1-beta-*`. Herkese açık ağırlık bulunamadı.
- Evidence: https://arxiv.org/abs/2505.16366 ; https://tqgpt.qianxin.com/recopilot/switch-lang?lang=en
- Confidence: Düşük. "Bulunamadı", "yok" demek değildir.
- What may change: Ağırlıklar yayımlanabilir.

**K18 — REFORGE**
- Claim: 7 model (Claude Sonnet 4.5, GPT-5.1, GPT-4o mini, DeepSeek R1, DeepSeek V3, Qwen3 Coder, Llama-3.1 70B). Ortalama token F1 0,18-0,29, medyan 0; tam eşleşme %1,9-7,1.
- Evidence: `docs/arge/2026-10-15_makale/veri_setleri.md` satır 40 ve 60 (makale gövdesinden okunmuş) ; https://arxiv.org/abs/2607.07738
- Confidence: Orta-yüksek.
- What may change: Konferans sürümü.

**K19 — Öncü modellerde aşırı reddetme**
- Claim: Ön denemelerde Claude Opus 4.7'de belirgin aşırı reddetme gözlendi; ajan kendi çalışma dosyalarını kötü amaçlı kod denetimi gerektiren dosyalar gibi ele aldı.
- Evidence: https://arxiv.org/pdf/2605.17046 (yalnız arama özetinden; makale açılıp okunmadı)
- Confidence: Düşük. Tek bir anekdot; hakemsiz ön baskı; ikinci el aktarım.
- What may change: —

**K20 — Qwen3.8-27B**
- Claim: Apache-2.0. Depo 2026-08-05'te açıldı, son değişiklik 2026-08-14. Kesim belirtilmemiş. LiveCodeBench v6 90,3; SWE-bench Pro 61,7.
- Evidence: https://huggingface.co/Qwen/Qwen3.8-27B ; https://huggingface.co/api/models/Qwen/Qwen3.8-27B
- Confidence: Yüksek (kart ve API).
- What may change: —

**K21 — gpt-oss-20b**
- Claim: Apache-2.0; 21B toplam, 3,6B etkin; MXFP4; 16 GB belleğe sığıyor; bağlam 131.072. Bilgi kesimi 2024-06-01 (OpenAI geliştirici belgesi; OpenRouter 2024-06-30 diyor). Depo 2025-08-04'te açıldı.
- Evidence: https://huggingface.co/openai/gpt-oss-20b ; https://developers.openai.com/api/docs/models/gpt-oss-20b ; https://openrouter.ai/openai/gpt-oss-20b/pricing ; https://huggingface.co/api/models/openai/gpt-oss-20b
- Confidence: Ay için yüksek; gün için orta (iki kaynak farklı gün veriyor).
- What may change: —

**K22 — Devstral Small 2**
- Claim: Apache-2.0; 24B parametre; tabanı Mistral-Small-3.1-24B-Base-2503; 256K bağlam; SWE-bench Verified 68,0; kesim belirtilmemiş; depo 2025-11-28'de açıldı.
- Evidence: https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512 ; https://huggingface.co/api/models?search=Devstral-Small-2&author=mistralai
- Confidence: Yüksek (kart).
- What may change: —

**K23 — OLMo 3.1 32B Instruct**
- Claim: Apache-2.0; 32,2B parametre; ön eğitim Dolma 3, son eğitim Dolci veri setleriyle. Kesim belirtilmemiş. Depo 2025-12-10'da açıldı. Bağlam 65.536 (ikincil kaynak).
- Evidence: https://huggingface.co/allenai/Olmo-3.1-32B-Instruct ; https://huggingface.co/api/models/allenai/Olmo-3.1-32B-Instruct ; https://deepinfra.com/allenai/Olmo-3.1-32B-Instruct
- Confidence: Kart bilgileri için yüksek; bağlam için orta.
- What may change: —

**K24 — Qwen3.6-35B-A3B**
- Claim: 35.951.822.704 parametre; Apache-2.0; depo 2026-04-15'te açıldı.
- Evidence: https://huggingface.co/api/models/Qwen/Qwen3.6-35B-A3B
- Confidence: Yüksek.
- What may change: —

**K25 — LLM yargıcın insan yargısıyla uyumu**
- Claim: İnsan odaklı ikili tersine mühendislik görevlerinde (fonksiyon adı kurtarma, kod özetleme, decompile iyileştirme) LLM yargıcın uzman yargısıyla ortalama korelasyonu %63,20. Geleneksel otomatik ölçütlerde bu oran %35,04. ASE 2026'da kabul edildi.
- Evidence: https://arxiv.org/abs/2608.07038
- Confidence: Orta. Özet okundu; görev başına değerler görülmedi.
- What may change: —

**K26 — lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit**
- Claim: Google'ın gemma-4-26B-A4B-it-QAT sürümünden mlx_vlm ile dönüştürülmüş; lisans Apache-2.0; safetensors toplamı 15.608.838.574 bayt. Yerel kopyadaki üç parçanın boyutları birebir aynı: 5.275.612.587, 5.296.718.232 ve 5.036.507.755 bayt.
- Evidence: https://huggingface.co/lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit ; https://huggingface.co/api/models/lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit/tree/main ; yerel `stat`
- Confidence: Boyutlar için yüksek. QAT kökeni için orta: sayfa kaynağı adıyla veriyor, ama `google/gemma-4-26B-A4B-it-QAT` adresi 401 döndü. Google'ın QAT depoları başka adlarla var (K5).
- What may change: Depo yeniden yüklenebilir. sha256 karşılaştırması yapılmalı.

**K28 — LM Studio'nun Qwen3.8 yüklemesinin belleği ve yalın sunucu (yerel ölçüm, 2026-10-19)**
- Claim:
  - LM Studio, Qwen3.8 GGUF için `llama-server`'ı şu bayraklarla başlatıyor: `--ctx-checkpoints 32`, `--load-mode mmap+mlock`, `--mmproj <görüntü kodlayıcı>`, `--kv-unified`; `--cache-ram` vermiyor, yani llama.cpp varsayılanı 8192 MiB geçerli (`llama-server --help`).
  - Kuru koşunun 40 çağrısından sonra `vmmap -summary`: eşlenmiş dosya (ağırlıklar) 15,4 GB yerleşik; MALLOC_LARGE 8,3 GB sanal, 1,2 GB yerleşik, 6,9 GB takas ya da sıkıştırılmış; fiziksel footprint 10,6 GB (tepe 10,8).
  - Model yeniden yüklenip 4 çağrı yapıldığında `llama-server` RSS'i 20,1 GiB oldu; bekçi (eşik 20 GiB) kuru koşuyu durdurdu.
  - Aynı ikili `--cache-ram 0 --ctx-checkpoints 0` ile ve görüntü kodlayıcı olmadan başlatıldığında RSS ~16,4 GiB, footprint ~1,1 GiB.
  - Kuru kümenin 10 fonksiyonu × 4 koşulda (40 çağrı, koşu 1) yalın sunucunun çıktısı LM Studio'nunkiyle **40 / 40 bayt bayt aynı**; ayrıştırılmış isim ve durum da, girdi jeton sayıları da 40 / 40 aynı.
- Evidence: `workspaces/2026-10-19_g6_pilot/kuru_kosu.log`, `ham/qwen38_lmstudio/`, `ham/qwen38/`; `vmmap -summary`, `footprint -p`, `ps`.
- Confidence: Yüksek (doğrudan ölçüm; eşdeğerlik 40 çağrıda).
- What may change: LM Studio sürümü ya da motor varsayılanları değişirse.

**K27 — LM Studio yerel sunucusunun yetenekleri (yerel sonda, 2026-10-19)**
- Claim:
  - LM Studio 0.4.25+1; seçili motorlar llama.cpp 2.60.0 ve mlx-llm 1.13.1 (`lms runtime ls`).
  - `/v1/chat/completions`, `logprobs: true` ile içerik jetonlarının log-olasılığını ve baytlarını veriyor.
  - `reasoning_effort: "none"` iki modelde de düşünme jetonunu 0'a indiriyor. `chat_template_kwargs`, `enable_thinking` ve `reasoning: {effort}` Qwen3.8'de etkisiz.
  - Aynı istek üç kez gönderildiğinde içerik ve log-olasılıklar iki modelde de bayt bayt aynı.
  - `/api/v0/chat/completions` motor adı ve sürümü, model bilgisi ve hız istatistiği veriyor; log-olasılık vermiyor.
  - Bellek: llama.cpp ağırlıkları mmap ile tutuyor (`llama-server` RSS ~16,3-17,7 GiB, footprint ~3,2 GiB). MLX ağırlıkları Metal tamponlarında tutuyor (LM Studio `node` işçisi footprint ~16 GiB, RSS ~8,5 GiB).
- Evidence: `workspaces/2026-10-19_g6_pilot/sonda/` (istek ve yanıtlar), `lms runtime ls`, `lms ps`, `footprint -p`.
- Confidence: Yüksek (yerelde, doğrudan gözlem). Belirlenimcilik sondası kısa bir istemle yapıldı; asıl ölçüm kuru koşuda ve pilotun koşu 2'sinde.
- What may change: LM Studio sürümü ve motorları güncellenebilir.

## 10. Dürüst sınırlamalar

- **Yerel modelin sonucu öncü modellere genellenemez.** Pilot ≤ 30B parametreli, 4 bit nicemlenmiş iki açık modelle yapılıyor: Qwen3.8-27B (Ağustos 2026, GGUF Q4_K_M) ve Gemma 4 26B-A4B (Nisan 2026, QAT). Kural tetiklenmezse bu, "öncü bir LLM de Karadul'u geçemez" anlamına gelmez. Kural tetiklenirse sonuç güçlüdür. Okuma kuralları `pilot_protokolu.md` §11'de.
- G33 kıyasında öncü model gerekip gerekmediği ayrı bir karardır ve **Berke'ye bırakıldı**. Bu belge o kararı vermiyor.
- 4 bit nicemlemenin bu görevdeki kaybı ölçülemiyor: 8 bit ve bf16 sürümler bütçeye sığmıyor. Gemma 4'ün QAT sürümü bu riski azaltır; birincil Qwen3.8 ise QAT değil, eğitim sonrası Q4_K_M nicemlemesi.
- Kod kıyas sayıları üretici beyanıdır ve isim görevini ölçmez.
- Hız sayıları topluluk ölçümüdür. Kuru koşunun ilk işi, bu sayıları bu makinede yeniden ölçmektir.
- Görev kanıtı aile düzeyinde. Önerinin güveni bu yüzden "orta".

## 11. Ana oturumun ve Berke'nin vereceği kararlar

**Kapananlar (Berke, 2026-10-19):** Birincil model Qwen3.8-27B (GGUF), ikinci model Gemma 4 26B-A4B QAT; Qwen3.6 indirilmeyecek; `orcarouter` kopyası kullanılmayacak; çalışma zamanı LM Studio.

**Bekleyenler:**
1. G33'te öncü model kullanılıp kullanılmayacağı. Kullanılırsa görülmemiş dilim için daha geç bir sınır gerekir (`gorulmemis_dilim_onkayit_taslak.md` §1.4).
2. Diskteki `orcarouter/Qwen3.8-27B-Uncensored-MLX` kopyası (15 GB). Bu belge yalnız "kullanılmaz" diyor; silme kararı Berke'nin.
3. "Modeller 13 Ekim'de silindi" hafıza kaydının düzeltilmesi.
4. LM Studio'nun motorları kendiliğinden güncellemesi (§8 madde 5): Uzun koşular için otomatik güncellemenin kapatılması bir ayar değişikliğidir ve Berke'nin kararıdır.
