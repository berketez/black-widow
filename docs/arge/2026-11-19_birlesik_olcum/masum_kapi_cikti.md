# Masum ikili kapısı — cikti kip

- Zaman: 2026-11-19T09:26:29+03:00 → 2026-11-19T09:27:47+03:00 (78.9 sn)
- Ağaç: `/Users/apple/karadul_olcum/urun-a62f15e` @ `a62f15ee6e` (karadul 1.24.1; `/Users/apple/karadul_olcum/urun-a62f15e/karadul/__init__.py`); kirli: 0 dosya
- Koşu: `/Users/apple/karadul_olcum/runs/urun-onarim-a62f15e` (119 ikili; koşunun ağacı `a62f15ee6e`, karadul 1.24.1)
- Kapı: **GEÇTİ** (çıkış 0)

## Katman × set: yanlış iddia

| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Adet (yanlış) | Eşik |
|---|---|---|---|---|---|---|---|---|---|
| bilesim | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 82 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| algoritma_kod | gelistirme | 119 | calisti 119 | 41 | 41 | 0 | 8 | 84 (84) | 16 ≤ 29 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 25 |
| algoritma_json | gelistirme | 119 | calisti 119 | 56 | 56 | 0 | 13 | 178 (178) | 24 ≤ 45 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 32 |
| security_etiketi | gelistirme | 119 | calisti 119 | 47 | 47 | 0 | 13 | 3352 (3352) | 12 ≤ 22 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 35 |
| sarif | gelistirme | 119 | calisti 119 | 12 | 12 | 0 | 8 | 12 (12) | 7 ≤ 37 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 5 |
| blok_yorumu | gelistirme | 119 | calisti 119 | 1 | 1 | 0 | 1 | 6 (6) | 1 ≤ 10 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| types_h | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 14 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| intel | gelistirme | 119 | calisti 119 | 611 | 455 | 156 | 118 | 611 (455) | 87 ≤ 353 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 368 |
| antidebug_cikti | gelistirme | 119 | calisti 119 | 7 | 7 | 0 | 5 | 7 (7) | 2 ≤ 7 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 5 |
| packer_cikti | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 0 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| yara_cikti | gelistirme | 119 | calisti 119 | 12 | 0 | 12 | 0 | 12 (0) | 0 ≤ 31 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| bilesim_yeniden | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 82 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| algoritma_yeniden | gelistirme | 119 | calisti 119 | 56 | 56 | 0 | 13 | 178 (178) | 24 ≤ 45 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 32 |

## En sık etiketler (ikili sayısı değil, iddia sayısı; bir ikilide etiket bir kez)

- **algoritma_kod / gelistirme**: `algoritma:TLS context` 5, `algoritma:TLS handshake (client)` 5, `algoritma:TLS encrypted read` 4, `algoritma:TLS encrypted write` 4, `algoritma:TLS handshake (server)` 3, `algoritma:TLS session` 3, `algoritma:BLAKE2/SHA-512` 2, `algoritma:SHA-1` 2
- **algoritma_json / gelistirme**: `algoritma:TLS context` 5, `algoritma:TLS encrypted read` 5, `algoritma:TLS encrypted write` 5, `algoritma:TLS handshake (client)` 5, `algoritma:TLS session` 5, `algoritma:SHA-256 (OpenSSL)` 3, `algoritma:SHA-512 (OpenSSL)` 3, `algoritma:TLS certificate verification` 3
- **security_etiketi / gelistirme**: `security:By name only: cryptographic operations (no call evidence)` 12, `security:Handles cryptographic operations` 10, `security:By name only: certificates/TLS (no call evidence)` 5, `security:By name only: sensitive key material (no call evidence)` 5, `security:Handles certificates/TLS` 5, `security:Handles sensitive key material` 5, `security:By name only: authentication/credentials (no call evidence)` 3, `security:By name only: privilege/sandbox operations (no call evidence)` 1
- **sarif / gelistirme**: `KRDL001:OpenSSL_Library` 5, `KRDL007:GCC_Compiler` 2, `KRDL007:Zlib_Library` 2, `KRDL007:Zstd_Library` 2, `KRDL007:LZ4_Library` 1
- **blok_yorumu / gelistirme**: `blok:Iteration loop` 1
- **intel / gelistirme**: `guvenlik:Stack Protection` 119, `altsistem:File System Operations` 118, `altsistem:Memory Management` 118, `altsistem:Localization` 106, `altsistem:Process Management` 11, `altsistem:Cryptographic Hashing` 9, `altsistem:Shell Integration` 7, `algoritma:SHA-1` 6
- **antidebug_cikti / gelistirme**: `teknik:prctl_import` 4, `teknik:Linux_ProcMaps` 2, `teknik:sysctl_import` 1
- **yara_cikti / gelistirme**: `kural:OpenSSL_Library` 5, `kural:GCC_Compiler` 2, `kural:Zlib_Library` 2, `kural:Zstd_Library` 2, `kural:LZ4_Library` 1
- **algoritma_yeniden / gelistirme**: `algoritma:TLS context` 5, `algoritma:TLS encrypted read` 5, `algoritma:TLS encrypted write` 5, `algoritma:TLS handshake (client)` 5, `algoritma:TLS session` 5, `algoritma:SHA-256 (OpenSSL)` 3, `algoritma:SHA-512 (OpenSSL)` 3, `algoritma:TLS certificate verification` 3

## İzlenen yanlış etiketler (rapordaki bulgular; ikili sayısı)

| Ad | Katman | Set | Etiket | İkili / ölçülen | Adet | Rapordaki |
|---|---|---|---|---|---|---|
| bluetooth | intel | gelistirme | `^altsistem:Bluetooth$` | 0 / 119 | 0 | IMZA-01: 119/119 (gelistirme) |
| encryption | intel | gelistirme | `^altsistem:Encryption$` | 0 / 108 | 0 | IMZA-01: 119/119; burada kriptosuz alt küme |
| opengl | intel | gelistirme | `^algoritma:OpenGL$` | 0 / 119 | 0 | IMZA-01: 119/119 |
| sha256_yardim_metni | intel | gelistirme | `^algoritma:SHA-256$` | 3 / 106 | 3 | IMZA-01: 107 (gelistirme, tümü); burada coreutils |
| kernel_riskli | intel | gelistirme | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 0 / 119 | 0 | IMZA-01: SIP 5, Kernel Extension 3 |
| ipsec | intel | gelistirme | `^protokol:IPsec$` | 0 / 119 | 0 | IMZA-01: 46 |
| rdtsc | antidebug_cikti | gelistirme | `^teknik:RDTSC_Timing$` | 0 / 119 | 0 | IMZA-02: 14 (gelistirme, AArch64) |
| sysctl_tek_ithal | antidebug_cikti | gelistirme | `^teknik:sysctl_kinfo_proc$` | 0 / 119 | 0 | IMZA-02: mac/htop, top, sysctl, vim |
| fsg | packer_cikti | gelistirme | `^paketleyici:FSG$` | 0 / 119 | 0 | IMZA-04 |
| mpress | yara_cikti | gelistirme | `^kural:MPRESS_Packed$` | 0 / 119 | 0 | IMZA-05: 13 (gelistirme) |
| aspack | yara_cikti | gelistirme | `^kural:ASPack_Packed$` | 0 / 119 | 0 | IMZA-05: 1 (tree) |
| delphi | yara_cikti | gelistirme | `^kural:Delphi_Compiler$` | 0 / 119 | 0 | IMZA-05: 2 (redis) |
| yara_antidebug | yara_cikti | gelistirme | `^kural:AntiDebug_` | 0 / 119 | 0 | IMZA-05: Timing 23, SysctlCheck 4 |
| stack_string | yara_cikti | gelistirme | `^kural:Stack_String_Construction$` | 0 / 119 | 0 | IMZA-05: 19 |
| cfd | bilesim | gelistirme | `CFD` | 0 / 119 | 0 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| cfd | bilesim_yeniden | gelistirme | `CFD` | 0 / 119 | 0 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| roket | bilesim | gelistirme | `^sablon:Rocket` | 0 / 119 | 0 | MUH-03: 119/119 |
| roket | bilesim_yeniden | gelistirme | `^sablon:Rocket` | 0 / 119 | 0 | MUH-03: 119/119 |
| matris | bilesim | gelistirme | `^sablon:Matrix Solve` | 0 / 119 | 0 | MUH-03: 119/119 |
| matris | bilesim_yeniden | gelistirme | `^sablon:Matrix Solve` | 0 / 119 | 0 | MUH-03: 119/119 |
| vpn | bilesim | gelistirme | `^sablon:VPN Tunnel` | 0 / 119 | 0 | ARAYUZ-01: 16 ikili |
| vpn | bilesim_yeniden | gelistirme | `^sablon:VPN Tunnel` | 0 / 119 | 0 | ARAYUZ-01: 16 ikili |
| ses | bilesim | gelistirme | `^sablon:Audio Codec` | 0 / 119 | 0 | MUH-03: 4 |
| ses | bilesim_yeniden | gelistirme | `^sablon:Audio Codec` | 0 / 119 | 0 | MUH-03: 4 |
| galois_kod | algoritma_kod | gelistirme | `^algoritma:Galois field` | 0 / 119 | 0 | MEK HEAD 14: htop 8, sqlite3 10, redis-cli 2, iki tmux 2'şer |
| galois_json | algoritma_json | gelistirme | `^algoritma:Galois field` | 0 / 119 | 0 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| galois_json | algoritma_yeniden | gelistirme | `^algoritma:Galois field` | 0 / 119 | 0 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| pbkdf2_json | algoritma_json | gelistirme | `^algoritma:Password-based key derivation` | 0 / 119 | 0 | TIP-09: 6 etiket |
| pbkdf2_json | algoritma_yeniden | gelistirme | `^algoritma:Password-based key derivation` | 0 / 119 | 0 | TIP-09: 6 etiket |
| security_kanca | security_etiketi | gelistirme | `^security:Code injection/hooking` | 0 / 119 | 0 | TIP-08: 9 |
| security_kimlik | security_etiketi | gelistirme | `^security:Handles authentication/credentials` | 0 / 119 | 0 | TIP-08: 70 |
| security_anahtar | security_etiketi | gelistirme | `^security:Handles sensitive key material` | 5 / 119 | 16 | TIP-08: 869 |
| row_major | blok_yorumu | gelistirme | `^blok:Row-major matrix access$` | 0 / 119 | 0 | MUH-07: 370 yorum (1.22.1, 119 ikili) |
| recovered_struct | types_h | gelistirme | `^yapi:recovered_struct$` | 0 / 119 | 0 | TIP-07: 5 585 yapı, 116 ikili (1.22.1); MEK HEAD 14: 4 109 |
| sarif_paket_uyarisi | sarif | gelistirme | `^KRDL00[34]:(MPRESS|ASPack|UPX|VMProtect|Themida|PECompact|Enigma)` | 0 / 119 | 0 | ARAYUZ-17 / IMZA-05: SARIF warning |
| sarif_antidebug_uyarisi | sarif | gelistirme | `^KRDL003:AntiDebug_` | 0 / 119 | 0 | MEK HEAD tablosu |

## Gerçek pozitifler

| Set | İkili | Katman | Beklenen | Zorunlu | Sonuç |
|---|---|---|---|---|---|
| pozitif | `upx_pe_t32` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_pe_t32` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `upx_pe_t64` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_pe_t64` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `upx_elf_true` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_elf_true` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:RDTSC_Timing$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:ptrace_pt_deny_attach$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:sysctl_(kinfo_proc|import)$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_SysctlCheck$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_(Ptrace|Timing)$` | hayır | olculmedi  |
| pozitif | `antidebug_x86_64` | bi | `^guvenlik:Anti-Debugging$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:AES$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:RSA$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:SHA-256$` | evet | olculmedi  |
| pozitif | `libcrypto` | yara | `^kural:OpenSSL_Library$` | evet | olculmedi  |
| pozitif | `libcrypto` | yara | `^kural:(AES_SBox|SHA256_Init_Constants|SHA256_Round_Constants)$` | hayır | olculmedi  |
| pozitif | `openssl_cli` | bi | `^algoritma:AES$` | evet | olculmedi  |
| pozitif | `openssl_cli` | bi | `^algoritma:RSA$` | evet | olculmedi  |
| pozitif | `openssl_cli` | yara | `^kural:OpenSSL_Library$` | evet | olculmedi  |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:AES$` | evet | var algoritma:AES |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:RSA$` | evet | var algoritma:RSA |
| gelistirme | `debian/openssl/openssl` | yara | `^kural:OpenSSL_Library$` | evet | var kural:OpenSSL_Library |
| macos | `/usr/bin/ssh` | bi | `^algoritma:(Ed25519|ChaCha20-Poly1305)$` | evet | olculmedi  |
| pe | `/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/w32.exe` | capa | `^yetenek:` | hayır | olculmedi  |

## Karşılaştırma (önce → sonra)

| Katman | Set | Yanlış | İddia | En çok değişen etiketler |
|---|---|---|---|---|
| algoritma_json | gelistirme | 109 → 56 | 109 → 56 | `algoritma:Hash function rounds (SHA, MD5)` 0→1, `algoritma:Modular exponentiation (RSA, DH)` 1→0, `algoritma:Elliptic curve operations (ECDSA, ECDH)` 1→0, `algoritma:Huffman coding` 1→0, `algoritma:Block cipher mode of operation (CBC, CTR, GCM)` 1→0 |
| algoritma_kod | gelistirme | 66 → 41 | 66 → 41 | `algoritma:Hash function rounds (SHA, MD5)` 0→1, `algoritma:Password-based key derivation (PBKDF2, scrypt)` 1→0, `algoritma:Elliptic curve operations (ECDSA, ECDH)` 1→0, `algoritma:Huffman coding` 1→0, `algoritma:Block cipher mode of operation (CBC, CTR, GCM)` 1→0 |
| algoritma_yeniden | gelistirme | 109 → 56 | 109 → 56 | `algoritma:Hash function rounds (SHA, MD5)` 0→1, `algoritma:Modular exponentiation (RSA, DH)` 1→0, `algoritma:Elliptic curve operations (ECDSA, ECDH)` 1→0, `algoritma:Huffman coding` 1→0, `algoritma:Block cipher mode of operation (CBC, CTR, GCM)` 1→0 |
| antidebug_cikti | gelistirme | 23 → 7 | 23 → 7 | `teknik:prctl_import` 0→4, `teknik:sysctl_import` 0→1, `teknik:sysctl_kinfo_proc` 1→0, `teknik:INT3_Cluster` 2→0, `teknik:prctl_set_dumpable` 4→0 |
| bilesim | gelistirme | 451 → 0 | 451 → 0 | `sablon:Certificate Chain Validation` 1→0, `sablon:Options Pricing Pipeline` 2→0, `sablon:Contact Mechanics Solution` 2→0, `sablon:ML Inference Pipeline` 2→0, `sablon:FFT Signal Processing Pipeline` 4→0 |
| bilesim_yeniden | gelistirme | 451 → 0 | 451 → 0 | `sablon:Certificate Chain Validation` 1→0, `sablon:Options Pricing Pipeline` 2→0, `sablon:Contact Mechanics Solution` 2→0, `sablon:ML Inference Pipeline` 2→0, `sablon:FFT Signal Processing Pipeline` 4→0 |
| blok_yorumu | gelistirme | 112 → 1 | 112 → 1 | `blok:Row-major matrix access` 111→0 |
| intel | gelistirme | 1965 → 455 | 2130 → 611 | `altsistem:Document Processing` 1→0, `altsistem:Web Protection` 5→4, `altsistem:Debugger` 4→3, `algoritma:Bloom Filter` 1→0, `altsistem:User Interface` 1→0 |
| packer_cikti | gelistirme | 0 → 0 | 0 → 0 |  |
| sarif | gelistirme | 81 → 12 | 81 → 12 | `KRDL001:OpenSSL_Library` 0→5, `KRDL007:Zstd_Library` 0→2, `KRDL007:Zlib_Library` 0→2, `KRDL007:GCC_Compiler` 0→2, `KRDL007:LZ4_Library` 0→1 |
| security_etiketi | gelistirme | 47 → 47 | 47 → 47 | `security:By name only: cryptographic operations (no call evidence)` 0→12, `security:By name only: sensitive key material (no call evidence)` 0→5, `security:By name only: certificates/TLS (no call evidence)` 0→5, `security:By name only: authentication/credentials (no call evidence)` 0→3, `security:By name only: privilege/sandbox operations (no call evidence)` 0→1 |
| types_h | gelistirme | 117 → 0 | 117 → 0 | `yapi:recovered_struct` 117→0 |
| yara_cikti | gelistirme | 70 → 0 | 81 → 12 | `kural:LZ4_Library` 0→1, `kural:ASPack_Packed` 1→0, `kural:Delphi_Compiler` 2→0, `kural:AntiDebug_SysctlCheck` 4→0, `kural:Zlib_Library` 10→2 |
