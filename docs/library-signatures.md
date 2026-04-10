# Binary Similarity Database -- Library Function Signatures
> Dogrulama: 2026-03-22 | Codex Consultant
> Toplam: 205 fonksiyon | 10 kutuphane

Bu dosya binary analiz sirasinda Ghidra/nm/otool ciktisinda karsilasilan
bilinen kutuphane fonksiyonlarini, amaclarini ve tipik cagirim
oruntularini icerir. Tum isimler gercek C symbol name'dir (Mach-O'da
`_` prefix'i olabilir).

---

## 1. OpenSSL / BoringSSL (30 fonksiyon)

```
OPENSSL: EVP_DigestInit_ex
  Amac: Hash/digest context'ini belirli algoritma ile baslatir (SHA256, MD5 vb.)
  Birlikte: [EVP_MD_CTX_new, EVP_DigestUpdate, EVP_DigestFinal_ex, EVP_MD_CTX_free]

OPENSSL: EVP_DigestUpdate
  Amac: Digest context'ine veri besler (incremental hashing)
  Birlikte: [EVP_DigestInit_ex, EVP_DigestFinal_ex]

OPENSSL: EVP_DigestFinal_ex
  Amac: Hash hesaplamasini tamamlayip sonucu yazar
  Birlikte: [EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free]

OPENSSL: EVP_MD_CTX_new
  Amac: Yeni message digest context'i allocate eder
  Birlikte: [EVP_DigestInit_ex, EVP_MD_CTX_free]

OPENSSL: EVP_MD_CTX_free
  Amac: Message digest context'ini serbest birakir
  Birlikte: [EVP_MD_CTX_new, EVP_DigestFinal_ex]

OPENSSL: EVP_EncryptInit_ex
  Amac: Simetrik sifreleme context'ini anahtar ve IV ile baslatir
  Birlikte: [EVP_CIPHER_CTX_new, EVP_EncryptUpdate, EVP_EncryptFinal_ex]

OPENSSL: EVP_EncryptUpdate
  Amac: Plaintext bloklarini sifreler (streaming encryption)
  Birlikte: [EVP_EncryptInit_ex, EVP_EncryptFinal_ex]

OPENSSL: EVP_EncryptFinal_ex
  Amac: Sifreleme islemini tamamlar, son blogu yazar (padding dahil)
  Birlikte: [EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_CIPHER_CTX_free]

OPENSSL: EVP_DecryptInit_ex
  Amac: Simetrik sifre cozme context'ini anahtar ve IV ile baslatir
  Birlikte: [EVP_CIPHER_CTX_new, EVP_DecryptUpdate, EVP_DecryptFinal_ex]

OPENSSL: EVP_DecryptUpdate
  Amac: Ciphertext bloklarinin sifresini cozer
  Birlikte: [EVP_DecryptInit_ex, EVP_DecryptFinal_ex]

OPENSSL: EVP_DecryptFinal_ex
  Amac: Sifre cozme islemini tamamlar, padding dogrular
  Birlikte: [EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_CIPHER_CTX_free]

OPENSSL: EVP_CIPHER_CTX_new
  Amac: Yeni cipher context allocate eder
  Birlikte: [EVP_EncryptInit_ex, EVP_DecryptInit_ex, EVP_CIPHER_CTX_free]

OPENSSL: EVP_CIPHER_CTX_free
  Amac: Cipher context'ini serbest birakir
  Birlikte: [EVP_CIPHER_CTX_new]

OPENSSL: SSL_CTX_new
  Amac: Yeni SSL/TLS context olusturur (tum baglantilarin ebeveyni)
  Birlikte: [TLS_method, SSL_new, SSL_CTX_free, SSL_CTX_set_verify]

OPENSSL: SSL_new
  Amac: SSL context'inden yeni SSL baglanti nesnesi olusturur
  Birlikte: [SSL_CTX_new, SSL_set_fd, SSL_connect, SSL_free]

OPENSSL: SSL_connect
  Amac: TLS client handshake baslatir
  Birlikte: [SSL_new, SSL_set_fd, SSL_read, SSL_write]

OPENSSL: SSL_accept
  Amac: TLS server handshake'i kabul eder
  Birlikte: [SSL_new, SSL_set_fd, SSL_read, SSL_write]

OPENSSL: SSL_read
  Amac: TLS baglantisinden sifresi cozulmus veri okur
  Birlikte: [SSL_connect, SSL_write, SSL_get_error]

OPENSSL: SSL_write
  Amac: TLS baglantisina veri sifreleyip gonderir
  Birlikte: [SSL_connect, SSL_read, SSL_get_error]

OPENSSL: SSL_free
  Amac: SSL baglanti nesnesini serbest birakir
  Birlikte: [SSL_new, SSL_shutdown]

OPENSSL: SSL_CTX_free
  Amac: SSL context'ini serbest birakir
  Birlikte: [SSL_CTX_new]

OPENSSL: SSL_shutdown
  Amac: TLS baglantisini duzgun kapatir (close_notify gonderir)
  Birlikte: [SSL_free, SSL_connect]

OPENSSL: BIO_new
  Amac: Yeni BIO (Basic I/O) nesnesi olusturur (soket, dosya, bellek)
  Birlikte: [BIO_new_socket, BIO_new_mem_buf, BIO_free]

OPENSSL: BIO_read
  Amac: BIO nesnesinden veri okur
  Birlikte: [BIO_new, BIO_write, BIO_free]

OPENSSL: BIO_write
  Amac: BIO nesnesine veri yazar
  Birlikte: [BIO_new, BIO_read]

OPENSSL: BIO_free
  Amac: BIO nesnesini serbest birakir
  Birlikte: [BIO_new]

OPENSSL: X509_get_subject_name
  Amac: X.509 sertifikasindan subject DN (Distinguished Name) alir
  Birlikte: [SSL_get_peer_certificate, X509_get_issuer_name, X509_NAME_oneline]

OPENSSL: RSA_generate_key_ex
  Amac: RSA anahtar cifti uretir (belirtilen bit uzunlugunda)
  Birlikte: [RSA_new, RSA_free, EVP_PKEY_assign_RSA]

OPENSSL: HMAC
  Amac: Tek cagirimda HMAC hesaplar (key + data -> mac)
  Birlikte: [EVP_sha256, EVP_sha1]

OPENSSL: SHA256
  Amac: Tek cagirimda SHA-256 hash hesaplar
  Birlikte: [SHA256_Init, SHA256_Update, SHA256_Final]
```

---

## 2. zlib (20 fonksiyon)

```
ZLIB: deflateInit
  Amac: Deflate (sikistirma) stream'ini baslatir
  Birlikte: [deflate, deflateEnd]

ZLIB: deflateInit2
  Amac: Deflate stream'ini gelismis parametrelerle baslatir (window bits, mem level, strategy)
  Birlikte: [deflate, deflateEnd]

ZLIB: deflate
  Amac: Veriyi deflate algoritmasiyla sikistirir (streaming)
  Birlikte: [deflateInit, deflateEnd]

ZLIB: deflateEnd
  Amac: Deflate stream'ini kapatir, dahili state'i serbest birakir
  Birlikte: [deflateInit, deflate]

ZLIB: inflateInit
  Amac: Inflate (acma) stream'ini baslatir
  Birlikte: [inflate, inflateEnd]

ZLIB: inflateInit2
  Amac: Inflate stream'ini gelismis parametrelerle baslatir (gzip/raw deflate destegi)
  Birlikte: [inflate, inflateEnd]

ZLIB: inflate
  Amac: Deflate ile sikistirilmis veriyi acar (streaming)
  Birlikte: [inflateInit, inflateEnd]

ZLIB: inflateEnd
  Amac: Inflate stream'ini kapatir
  Birlikte: [inflateInit, inflate]

ZLIB: compress
  Amac: Bellek icinde tek cagirimda veri sikistirir (basit API)
  Birlikte: [uncompress, compressBound]

ZLIB: compress2
  Amac: Sikistirma seviyesi belirterek tek cagirimda sikistirir
  Birlikte: [uncompress, compressBound]

ZLIB: uncompress
  Amac: Tek cagirimda sikistirilmis veriyi acar (basit API)
  Birlikte: [compress, compress2]

ZLIB: uncompress2
  Amac: uncompress gibi, ek olarak tuketilen kaynak boyutunu raporlar
  Birlikte: [compress, compress2]

ZLIB: compressBound
  Amac: Verilen girdi boyutu icin sikistirilmis ciktinin ust sinirini hesaplar
  Birlikte: [compress, compress2]

ZLIB: gzopen
  Amac: gzip dosyasini okuma/yazma icin acar (FILE* benzeri arayuz)
  Birlikte: [gzread, gzwrite, gzclose]

ZLIB: gzread
  Amac: gzip dosyasindan sikistirmayi cozup okur
  Birlikte: [gzopen, gzclose]

ZLIB: gzwrite
  Amac: Veriyi sikistirip gzip dosyasina yazar
  Birlikte: [gzopen, gzclose]

ZLIB: gzclose
  Amac: gzip dosyasini kapatir, buffer'lari flush eder
  Birlikte: [gzopen]

ZLIB: gzprintf
  Amac: printf benzeri formatli veriyi sikistirip gzip dosyasina yazar
  Birlikte: [gzopen, gzclose]

ZLIB: crc32
  Amac: CRC-32 checksum hesaplar (incremental destekli)
  Birlikte: [inflate, deflate]

ZLIB: adler32
  Amac: Adler-32 checksum hesaplar (zlib internal'da kullanilir)
  Birlikte: [inflate, deflate]
```

---

## 3. libcurl (20 fonksiyon)

```
LIBCURL: curl_global_init
  Amac: libcurl global ortamini baslatir (SSL, Winsock vb.)
  Birlikte: [curl_global_cleanup, curl_easy_init]

LIBCURL: curl_global_cleanup
  Amac: libcurl global ortamini temizler (program cikisinda)
  Birlikte: [curl_global_init]

LIBCURL: curl_easy_init
  Amac: Yeni easy handle (tek transfer icin) olusturur
  Birlikte: [curl_easy_setopt, curl_easy_perform, curl_easy_cleanup]

LIBCURL: curl_easy_setopt
  Amac: Transfer secenek/parametresi ayarlar (URL, callback, timeout vb.)
  Birlikte: [curl_easy_init, curl_easy_perform]

LIBCURL: curl_easy_perform
  Amac: Ayarlanan transferi senkron olarak calistirir (bloklayici)
  Birlikte: [curl_easy_init, curl_easy_setopt, curl_easy_getinfo]

LIBCURL: curl_easy_cleanup
  Amac: Easy handle'i ve iliskili kaynaklari serbest birakir
  Birlikte: [curl_easy_init]

LIBCURL: curl_easy_getinfo
  Amac: Tamamlanan transferin bilgisini alir (HTTP kodu, sure, boyut)
  Birlikte: [curl_easy_perform]

LIBCURL: curl_easy_strerror
  Amac: CURLcode hata kodunu okunabilir string'e cevirir
  Birlikte: [curl_easy_perform]

LIBCURL: curl_easy_reset
  Amac: Easy handle'in tum seceneklerini sifirlar (yeniden kullanmak icin)
  Birlikte: [curl_easy_init, curl_easy_setopt]

LIBCURL: curl_easy_duphandle
  Amac: Mevcut easy handle'in kopyasini olusturur
  Birlikte: [curl_easy_init, curl_easy_cleanup]

LIBCURL: curl_multi_init
  Amac: Yeni multi handle (paralel transfer yoneticisi) olusturur
  Birlikte: [curl_multi_add_handle, curl_multi_perform, curl_multi_cleanup]

LIBCURL: curl_multi_add_handle
  Amac: Easy handle'i multi handle'a ekler (paralel transfer icin)
  Birlikte: [curl_multi_init, curl_multi_perform, curl_multi_remove_handle]

LIBCURL: curl_multi_remove_handle
  Amac: Easy handle'i multi handle'dan cikarir
  Birlikte: [curl_multi_add_handle, curl_easy_cleanup]

LIBCURL: curl_multi_perform
  Amac: Tum aktif transferlerde ilerleme saglar (non-blocking)
  Birlikte: [curl_multi_init, curl_multi_add_handle, curl_multi_info_read]

LIBCURL: curl_multi_cleanup
  Amac: Multi handle'i ve kaynaklari serbest birakir
  Birlikte: [curl_multi_init]

LIBCURL: curl_multi_info_read
  Amac: Tamamlanan transferlerin bilgisini kuyruktan okur
  Birlikte: [curl_multi_perform]

LIBCURL: curl_slist_append
  Amac: Linked list'e string ekler (HTTP header'lar icin)
  Birlikte: [curl_easy_setopt, curl_slist_free_all]

LIBCURL: curl_slist_free_all
  Amac: String linked list'i serbest birakir
  Birlikte: [curl_slist_append]

LIBCURL: curl_url
  Amac: Yeni URL handle olusturur (URL parse/build icin)
  Birlikte: [curl_url_set, curl_url_get, curl_url_cleanup]

LIBCURL: curl_easy_escape
  Amac: String'i URL-encoded formata cevirir (percent encoding)
  Birlikte: [curl_easy_unescape, curl_free]
```

---

## 4. SQLite (30 fonksiyon)

```
SQLITE: sqlite3_open
  Amac: SQLite veritabani dosyasini acar (yoksa olusturur)
  Birlikte: [sqlite3_close, sqlite3_exec, sqlite3_prepare_v2]

SQLITE: sqlite3_open_v2
  Amac: Veritabanini gelismis bayraklarla acar (read-only, WAL, URI)
  Birlikte: [sqlite3_close, sqlite3_prepare_v2]

SQLITE: sqlite3_close
  Amac: Veritabani baglantisini kapatir, kaynaklari serbest birakir
  Birlikte: [sqlite3_open, sqlite3_finalize]

SQLITE: sqlite3_close_v2
  Amac: Baglantiya asili statement'lar tamamlaninca otomatik kapanir
  Birlikte: [sqlite3_open_v2]

SQLITE: sqlite3_exec
  Amac: SQL string'ini derle+calistir+sonucla (callback ile), basit islemler icin
  Birlikte: [sqlite3_open, sqlite3_errmsg]

SQLITE: sqlite3_prepare_v2
  Amac: SQL string'ini derlenmi statement'a cevirir (parametre baglama icin)
  Birlikte: [sqlite3_bind_text, sqlite3_step, sqlite3_finalize]

SQLITE: sqlite3_prepare_v3
  Amac: prepare_v2 gibi, ek prepare bayraklari destekler (PERSISTENT vb.)
  Birlikte: [sqlite3_bind_text, sqlite3_step, sqlite3_finalize]

SQLITE: sqlite3_step
  Amac: Derlenmis statement'i bir adim calistirir (sonraki satir veya tamamlama)
  Birlikte: [sqlite3_prepare_v2, sqlite3_column_text, sqlite3_reset]

SQLITE: sqlite3_finalize
  Amac: Derlenmis statement'i yok eder, kaynaklari serbest birakir
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_reset
  Amac: Statement'i baslangic durumuna dondurur (tekrar calistirmak icin)
  Birlikte: [sqlite3_step, sqlite3_bind_text]

SQLITE: sqlite3_bind_int
  Amac: Statement parametresine integer deger baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step, sqlite3_reset]

SQLITE: sqlite3_bind_int64
  Amac: Statement parametresine 64-bit integer deger baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_bind_double
  Amac: Statement parametresine double (kayan nokta) deger baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_bind_text
  Amac: Statement parametresine UTF-8 string baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step, sqlite3_reset]

SQLITE: sqlite3_bind_blob
  Amac: Statement parametresine binary blob baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_bind_null
  Amac: Statement parametresine NULL baglar
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_column_int
  Amac: Sonuc satirindan integer degeri okur
  Birlikte: [sqlite3_step, sqlite3_column_count]

SQLITE: sqlite3_column_int64
  Amac: Sonuc satirindan 64-bit integer okur
  Birlikte: [sqlite3_step]

SQLITE: sqlite3_column_double
  Amac: Sonuc satirindan double (kayan nokta) deger okur
  Birlikte: [sqlite3_step]

SQLITE: sqlite3_column_text
  Amac: Sonuc satirindan UTF-8 string okur
  Birlikte: [sqlite3_step, sqlite3_column_bytes]

SQLITE: sqlite3_column_blob
  Amac: Sonuc satirindan binary blob pointer'i okur
  Birlikte: [sqlite3_step, sqlite3_column_bytes]

SQLITE: sqlite3_column_bytes
  Amac: Sonuc degerinin byte cinsinden boyutunu dondurur
  Birlikte: [sqlite3_column_text, sqlite3_column_blob]

SQLITE: sqlite3_column_count
  Amac: Sonuc kumesindeki sutun sayisini dondurur
  Birlikte: [sqlite3_prepare_v2, sqlite3_step]

SQLITE: sqlite3_column_type
  Amac: Sonuc degerinin tipini dondurur (INTEGER, FLOAT, TEXT, BLOB, NULL)
  Birlikte: [sqlite3_step]

SQLITE: sqlite3_errmsg
  Amac: Son hata icin okunabilir mesaj dondurur
  Birlikte: [sqlite3_exec, sqlite3_step, sqlite3_prepare_v2]

SQLITE: sqlite3_errcode
  Amac: Son hata kodunu dondurur
  Birlikte: [sqlite3_errmsg]

SQLITE: sqlite3_changes
  Amac: Son INSERT/UPDATE/DELETE'in etkiledigi satir sayisini dondurur
  Birlikte: [sqlite3_exec, sqlite3_step]

SQLITE: sqlite3_last_insert_rowid
  Amac: Son INSERT isleminin rowid'sini dondurur
  Birlikte: [sqlite3_exec, sqlite3_step]

SQLITE: sqlite3_busy_timeout
  Amac: Veritabani kilitliyken bekleme suresini milisaniye cinsinden ayarlar
  Birlikte: [sqlite3_open, sqlite3_exec]

SQLITE: sqlite3_free
  Amac: sqlite3_malloc ile ayrilan bellegi serbest birakir
  Birlikte: [sqlite3_mprintf, sqlite3_exec]
```

---

## 5. Protocol Buffers C++ Runtime (15 fonksiyon)

Not: protobuf C++ runtime mangled symbol'leri icerir. Asagidakiler
sinif::metod formundadir; binary'de `_ZN6google8protobuf...` seklinde gorulur.

```
PROTOBUF: google::protobuf::MessageLite::SerializeToString
  Amac: Protobuf mesajini binary wire format'a serialize eder (string'e yazar)
  Birlikte: [ParseFromString, ByteSizeLong]

PROTOBUF: google::protobuf::MessageLite::ParseFromString
  Amac: Binary wire format'tan protobuf mesajini parse eder
  Birlikte: [SerializeToString, IsInitialized]

PROTOBUF: google::protobuf::MessageLite::SerializeToArray
  Amac: Mesaji verilen byte buffer'a serialize eder
  Birlikte: [ParseFromArray, ByteSizeLong]

PROTOBUF: google::protobuf::MessageLite::ParseFromArray
  Amac: Byte buffer'dan protobuf mesaji parse eder
  Birlikte: [SerializeToArray]

PROTOBUF: google::protobuf::MessageLite::ByteSizeLong
  Amac: Mesajin serialize edilmis boyutunu hesaplar (buffer allocation icin)
  Birlikte: [SerializeToString, SerializeToArray]

PROTOBUF: google::protobuf::MessageLite::MergeFromCodedStream
  Amac: CodedInputStream'den protobuf mesaji okuyup mevcut mesajla birlestirir
  Birlikte: [SerializeToCodedStream]

PROTOBUF: google::protobuf::MessageLite::IsInitialized
  Amac: Tum required alanlarin doldurulup doldurulmadigini kontrol eder
  Birlikte: [ParseFromString, SerializeToString]

PROTOBUF: google::protobuf::Message::CopyFrom
  Amac: Baska bir mesajin tum alanlarini bu mesaja kopyalar
  Birlikte: [MergeFrom, Clear]

PROTOBUF: google::protobuf::Message::MergeFrom
  Amac: Baska mesajdaki set edilmis alanlari bu mesajla birlestirir
  Birlikte: [CopyFrom, Clear]

PROTOBUF: google::protobuf::Message::Clear
  Amac: Mesajin tum alanlarini varsayilan degerlere sifirlar
  Birlikte: [CopyFrom, ParseFromString]

PROTOBUF: google::protobuf::Message::GetDescriptor
  Amac: Mesajin runtime type descriptor'unu dondurur (reflection icin)
  Birlikte: [GetReflection]

PROTOBUF: google::protobuf::Message::GetReflection
  Amac: Mesajin reflection arayuzunu dondurur (dinamik alan erisimi)
  Birlikte: [GetDescriptor]

PROTOBUF: google::protobuf::Message::New
  Amac: Ayni tipteki bos bir mesaj nesnesi olusturur (prototype pattern)
  Birlikte: [CopyFrom, GetDescriptor]

PROTOBUF: google::protobuf::io::CodedInputStream::ReadTag
  Amac: Wire format'tan sonraki field tag'ini okur
  Birlikte: [ReadVarint32, ReadString, ReadRaw]

PROTOBUF: google::protobuf::io::CodedOutputStream::WriteTag
  Amac: Wire format'a field tag yazar
  Birlikte: [WriteVarint32, WriteString, WriteRaw]
```

---

## 6. Swift Runtime (20 fonksiyon)

Not: Bunlar `libswiftCore.dylib` icindeki C-linkage fonksiyonlardir.
Mach-O symbol table'da `_swift_*` olarak gorulur.

```
SWIFT_RT: swift_retain
  Amac: Swift nesnesinin reference count'unu 1 arttirir (strong retain)
  Birlikte: [swift_release, swift_allocObject]

SWIFT_RT: swift_release
  Amac: Swift nesnesinin reference count'unu 1 azaltir, sifirda dealloc eder
  Birlikte: [swift_retain, swift_allocObject]

SWIFT_RT: swift_retain_n
  Amac: Reference count'u N kadar arttirir (toplu retain)
  Birlikte: [swift_release_n]

SWIFT_RT: swift_release_n
  Amac: Reference count'u N kadar azaltir (toplu release)
  Birlikte: [swift_retain_n]

SWIFT_RT: swift_allocObject
  Amac: Heap'te yeni Swift nesnesi icin bellek ayirir ve metadata pointer'ini set eder
  Birlikte: [swift_retain, swift_release, swift_deallocObject]

SWIFT_RT: swift_deallocObject
  Amac: Swift nesnesinin bellegini serbest birakir
  Birlikte: [swift_allocObject, swift_release]

SWIFT_RT: swift_slowAlloc
  Amac: Bellek ayirma (malloc wrapper, hizalama destekli)
  Birlikte: [swift_slowDealloc]

SWIFT_RT: swift_slowDealloc
  Amac: Bellek serbest birakma (free wrapper)
  Birlikte: [swift_slowAlloc]

SWIFT_RT: swift_getObjCClassMetadata
  Amac: ObjC sinifinin Swift type metadata pointer'ini dondurur
  Birlikte: [swift_getTypeByMangledNameInContext]

SWIFT_RT: swift_getTypeByMangledNameInContext
  Amac: Mangled type name'den runtime type metadata'sini cozumler
  Birlikte: [swift_getObjCClassMetadata]

SWIFT_RT: swift_dynamicCast
  Amac: Runtime'da guvenli tip donusumu yapar (as? ve as! operatorlerinin arkasi)
  Birlikte: [swift_conformsToProtocol]

SWIFT_RT: swift_conformsToProtocol
  Amac: Bir tipin belirli bir protocol'e uyup uymadigini kontrol eder
  Birlikte: [swift_dynamicCast]

SWIFT_RT: swift_unknownObjectRetain
  Amac: ObjC veya Swift nesnesi (tip belirsiz) icin retain yapar
  Birlikte: [swift_unknownObjectRelease]

SWIFT_RT: swift_unknownObjectRelease
  Amac: ObjC veya Swift nesnesi icin release yapar
  Birlikte: [swift_unknownObjectRetain]

SWIFT_RT: swift_bridgeObjectRetain
  Amac: Bridge object (Swift-ObjC koprusu) icin retain yapar
  Birlikte: [swift_bridgeObjectRelease]

SWIFT_RT: swift_bridgeObjectRelease
  Amac: Bridge object icin release yapar
  Birlikte: [swift_bridgeObjectRetain]

SWIFT_RT: swift_once
  Amac: Bir closure'i yalnizca bir kez calistirir (lazy initialization icin, dispatch_once benzeri)
  Birlikte: [swift_allocObject]

SWIFT_RT: swift_isUniquelyReferenced_nonObjC
  Amac: Nesnenin tek referansa sahip olup olmadigini kontrol eder (COW icin)
  Birlikte: [swift_retain, swift_release]

SWIFT_RT: swift_beginAccess
  Amac: Exclusivity enforcement: bellek erisimini baslatir, cakismayi kontrol eder
  Birlikte: [swift_endAccess]

SWIFT_RT: swift_endAccess
  Amac: Exclusivity enforcement: bellek erisim kaydini sonlandirir
  Birlikte: [swift_beginAccess]
```

---

## 7. Objective-C Runtime (15 fonksiyon)

Not: `libobjc.A.dylib` icindeki fonksiyonlar. Mach-O'da `_objc_*` olarak gorulur.

```
OBJC_RT: objc_msgSend
  Amac: ObjC mesaj gondermesinin temel mekanizmasi -- metod cagrisini yapar
  Birlikte: [objc_msgSendSuper2, objc_retain, objc_release]

OBJC_RT: objc_msgSendSuper2
  Amac: Super class'a mesaj gonderir (super.method() cagrisi)
  Birlikte: [objc_msgSend]

OBJC_RT: objc_msgSend_stret
  Amac: Struct donduren metod cagrilari icin mesaj gonderir (x86_64)
  Birlikte: [objc_msgSend]

OBJC_RT: objc_retain
  Amac: ObjC nesnesinin retain count'unu arttirir (ARC tarafindan eklenir)
  Birlikte: [objc_release, objc_autorelease, objc_msgSend]

OBJC_RT: objc_release
  Amac: ObjC nesnesinin retain count'unu azaltir (ARC tarafindan eklenir)
  Birlikte: [objc_retain, objc_autorelease]

OBJC_RT: objc_autorelease
  Amac: Nesneyi autorelease pool'a ekler (scope sonunda release edilecek)
  Birlikte: [objc_autoreleasePoolPush, objc_autoreleasePoolPop]

OBJC_RT: objc_autoreleasePoolPush
  Amac: Yeni autorelease pool scope'u baslatir
  Birlikte: [objc_autoreleasePoolPop, objc_autorelease]

OBJC_RT: objc_autoreleasePoolPop
  Amac: Autorelease pool scope'unu kapatir, icindeki nesneleri release eder
  Birlikte: [objc_autoreleasePoolPush]

OBJC_RT: objc_alloc
  Amac: ObjC nesnesi icin bellek ayirir (+alloc mesajinin hizlandirilmis yolu)
  Birlikte: [objc_msgSend, objc_opt_new]

OBJC_RT: objc_alloc_init
  Amac: alloc+init'i tek cagirimda yapar (optimizasyon)
  Birlikte: [objc_release]

OBJC_RT: objc_opt_new
  Amac: +new mesajinin hizlandirilmis yolu (alloc+init)
  Birlikte: [objc_release]

OBJC_RT: objc_storeStrong
  Amac: Strong referansi atomik olarak gunceller (eski release, yeni retain)
  Birlikte: [objc_retain, objc_release]

OBJC_RT: class_getInstanceMethod
  Amac: Sinifin belirli selector icin Method yapisini dondurur (introspection)
  Birlikte: [method_getImplementation, sel_registerName]

OBJC_RT: sel_registerName
  Amac: C string'den ObjC selector (SEL) olusturur/kaydeder
  Birlikte: [objc_msgSend, class_getInstanceMethod]

OBJC_RT: object_getClass
  Amac: Nesnenin isa pointer'ini (Class) dondurur
  Birlikte: [class_getInstanceMethod, class_getName]
```

---

## 8. Grand Central Dispatch / libdispatch (15 fonksiyon)

Not: `libdispatch.dylib` icindeki fonksiyonlar. Mach-O'da `_dispatch_*` olarak gorulur.

```
GCD: dispatch_async
  Amac: Blogu belirtilen kuyruga asenkron olarak ekler (hemen doner)
  Birlikte: [dispatch_get_global_queue, dispatch_get_main_queue, dispatch_queue_create]

GCD: dispatch_sync
  Amac: Blogu belirtilen kuyrukta senkron calistirir (tamamlanana kadar bekler)
  Birlikte: [dispatch_queue_create, dispatch_get_main_queue]

GCD: dispatch_queue_create
  Amac: Yeni dispatch kuyrugu olusturur (serial veya concurrent)
  Birlikte: [dispatch_async, dispatch_sync, dispatch_release]

GCD: dispatch_get_main_queue
  Amac: Ana thread'in (UI thread) dispatch kuyrugunu dondurur
  Birlikte: [dispatch_async, dispatch_sync]

GCD: dispatch_get_global_queue
  Amac: Sistem global concurrent kuyruklarindan birini dondurur (priority'ye gore)
  Birlikte: [dispatch_async, dispatch_sync]

GCD: dispatch_once
  Amac: Blogu uygulama omru boyunca yalnizca bir kez calistirir (singleton pattern)
  Birlikte: [dispatch_once_f]

GCD: dispatch_once_f
  Amac: dispatch_once'in fonksiyon pointer versiyonu (C uyumlu)
  Birlikte: [dispatch_once]

GCD: dispatch_after
  Amac: Blogu belirtilen gecikme sonrasinda kuyruga ekler
  Birlikte: [dispatch_time, dispatch_async, dispatch_get_main_queue]

GCD: dispatch_time
  Amac: Dispatch zamani olusturur (nanosaniye cinsinden gecikme)
  Birlikte: [dispatch_after]

GCD: dispatch_group_create
  Amac: Dispatch grubu olusturur (birden fazla async islemi takip etmek icin)
  Birlikte: [dispatch_group_enter, dispatch_group_leave, dispatch_group_notify]

GCD: dispatch_group_enter
  Amac: Gruptaki bekleyen is sayisini arttirir
  Birlikte: [dispatch_group_leave, dispatch_group_notify]

GCD: dispatch_group_leave
  Amac: Gruptaki bekleyen is sayisini azaltir
  Birlikte: [dispatch_group_enter, dispatch_group_notify]

GCD: dispatch_group_notify
  Amac: Gruptaki tum isler tamamlandiginda blogu calistirir
  Birlikte: [dispatch_group_create, dispatch_group_enter, dispatch_group_leave]

GCD: dispatch_semaphore_create
  Amac: Sayma semaforu olusturur (esitleme icin)
  Birlikte: [dispatch_semaphore_wait, dispatch_semaphore_signal]

GCD: dispatch_semaphore_wait
  Amac: Semafor degerini azaltir, sifirsa bloklar (bekleme)
  Birlikte: [dispatch_semaphore_create, dispatch_semaphore_signal]
```

---

## 9. CommonCrypto (15 fonksiyon)

Not: macOS/iOS `libcommonCrypto.dylib` (veya Security framework araciligiyla).
Header: `<CommonCrypto/CommonCrypto.h>`

```
COMMONCRYPTO: CCCrypt
  Amac: Tek cagirimda simetrik sifreleme/cozme yapar (AES, DES, 3DES, vb.)
  Birlikte: [CCCryptorCreate, kCCAlgorithmAES128]

COMMONCRYPTO: CCCryptorCreate
  Amac: Yeni cryptor nesnesi olusturur (streaming encryption icin)
  Birlikte: [CCCryptorUpdate, CCCryptorFinal, CCCryptorRelease]

COMMONCRYPTO: CCCryptorCreateFromData
  Amac: Kullanici belleginde cryptor nesnesi olusturur (heap allocation'siz)
  Birlikte: [CCCryptorUpdate, CCCryptorFinal, CCCryptorRelease]

COMMONCRYPTO: CCCryptorUpdate
  Amac: Cryptor'a veri besler, sifrelenmis/cozulmus ciktiyi yazar
  Birlikte: [CCCryptorCreate, CCCryptorFinal]

COMMONCRYPTO: CCCryptorFinal
  Amac: Sifreleme/cozme islemini tamamlar, kalan veriyi yazar
  Birlikte: [CCCryptorCreate, CCCryptorUpdate, CCCryptorRelease]

COMMONCRYPTO: CCCryptorRelease
  Amac: Cryptor nesnesini serbest birakir
  Birlikte: [CCCryptorCreate]

COMMONCRYPTO: CC_SHA256_Init
  Amac: SHA-256 hash context'ini baslatir
  Birlikte: [CC_SHA256_Update, CC_SHA256_Final]

COMMONCRYPTO: CC_SHA256_Update
  Amac: SHA-256 context'ine veri besler
  Birlikte: [CC_SHA256_Init, CC_SHA256_Final]

COMMONCRYPTO: CC_SHA256_Final
  Amac: SHA-256 hash'ini tamamlar, 32-byte digest yazar
  Birlikte: [CC_SHA256_Init, CC_SHA256_Update]

COMMONCRYPTO: CC_SHA256
  Amac: Tek cagirimda SHA-256 hash hesaplar (convenience)
  Birlikte: []

COMMONCRYPTO: CC_SHA1
  Amac: Tek cagirimda SHA-1 hash hesaplar
  Birlikte: []

COMMONCRYPTO: CC_MD5
  Amac: Tek cagirimda MD5 hash hesaplar
  Birlikte: []

COMMONCRYPTO: CCHmac
  Amac: Tek cagirimda HMAC hesaplar (key + data -> mac)
  Birlikte: [CCHmacInit, CCHmacUpdate, CCHmacFinal]

COMMONCRYPTO: CCHmacInit
  Amac: HMAC context'ini anahtar ve algoritma ile baslatir
  Birlikte: [CCHmacUpdate, CCHmacFinal]

COMMONCRYPTO: CCKeyDerivationPBKDF
  Amac: PBKDF2 ile sifre tabanli anahtar turetir (password hashing)
  Birlikte: [CCCrypt, CC_SHA256]
```

---

## 10. Apple Security Framework (15 fonksiyon)

Not: `Security.framework` icindeki fonksiyonlar. Mach-O'da `_Sec*` olarak gorulur.

```
SECURITY: SecItemAdd
  Amac: Keychain'e yeni item (sifre, sertifika, anahtar) ekler
  Birlikte: [SecItemCopyMatching, SecItemUpdate, SecItemDelete]

SECURITY: SecItemCopyMatching
  Amac: Keychain'den sorgu kriterlerine uyan item'lari okur
  Birlikte: [SecItemAdd, SecItemUpdate]

SECURITY: SecItemUpdate
  Amac: Keychain'deki mevcut item'i gunceller
  Birlikte: [SecItemCopyMatching, SecItemAdd]

SECURITY: SecItemDelete
  Amac: Keychain'den item siler
  Birlikte: [SecItemCopyMatching]

SECURITY: SecKeyCreateRandomKey
  Amac: Rastgele asimetrik anahtar cifti uretir (RSA, EC)
  Birlikte: [SecKeyCopyPublicKey, SecKeyCreateSignature, SecKeyCreateEncryptedData]

SECURITY: SecKeyCopyPublicKey
  Amac: Private key'den public key'i cikarir
  Birlikte: [SecKeyCreateRandomKey, SecKeyCreateEncryptedData]

SECURITY: SecKeyCreateSignature
  Amac: Private key ile dijital imza olusturur
  Birlikte: [SecKeyVerifySignature, SecKeyCreateRandomKey]

SECURITY: SecKeyVerifySignature
  Amac: Public key ile dijital imzayi dogrular
  Birlikte: [SecKeyCreateSignature, SecKeyCopyPublicKey]

SECURITY: SecKeyCreateEncryptedData
  Amac: Public key ile veri sifreler (asimetrik encryption)
  Birlikte: [SecKeyCreateDecryptedData, SecKeyCopyPublicKey]

SECURITY: SecKeyCreateDecryptedData
  Amac: Private key ile sifreli veriyi cozer
  Birlikte: [SecKeyCreateEncryptedData]

SECURITY: SecTrustEvaluateWithError
  Amac: X.509 sertifika zincirini dogrular (trust evaluation)
  Birlikte: [SecTrustCreateWithCertificates, SecTrustSetAnchorCertificates]

SECURITY: SecTrustCreateWithCertificates
  Amac: Sertifika ve policy'den trust nesnesi olusturur
  Birlikte: [SecTrustEvaluateWithError, SecPolicyCreateSSL]

SECURITY: SecCertificateCopySubjectSummary
  Amac: Sertifikanin subject ozetini okunabilir string olarak dondurur
  Birlikte: [SecTrustCopyResult, SecCertificateCreateWithData]

SECURITY: SecCertificateCreateWithData
  Amac: DER-encoded data'dan SecCertificate nesnesi olusturur
  Birlikte: [SecTrustCreateWithCertificates, SecCertificateCopySubjectSummary]

SECURITY: SecPolicyCreateSSL
  Amac: SSL/TLS sertifika dogrulama policy'si olusturur
  Birlikte: [SecTrustCreateWithCertificates, SecTrustEvaluateWithError]
```

---

## Ozet Tablosu

| # | Kutuphane | Fonksiyon Sayisi | Mach-O Symbol Prefix |
|---|-----------|-----------------|---------------------|
| 1 | OpenSSL/BoringSSL | 30 | `_EVP_`, `_SSL_`, `_BIO_`, `_X509_`, `_RSA_`, `_HMAC`, `_SHA256` |
| 2 | zlib | 20 | `_deflate*`, `_inflate*`, `_compress*`, `_gz*`, `_crc32`, `_adler32` |
| 3 | libcurl | 20 | `_curl_easy_*`, `_curl_multi_*`, `_curl_slist_*`, `_curl_global_*` |
| 4 | SQLite | 30 | `_sqlite3_*` |
| 5 | protobuf (C++) | 15 | `_ZN6google8protobuf*` (mangled) |
| 6 | Swift Runtime | 20 | `_swift_*` |
| 7 | ObjC Runtime | 15 | `_objc_*`, `_sel_*`, `_class_*`, `_object_*` |
| 8 | GCD / libdispatch | 15 | `_dispatch_*` |
| 9 | CommonCrypto | 15 | `_CC*`, `_CCCrypt*`, `_CCHmac*` |
| 10 | Apple Security | 15 | `_Sec*` |
| | **TOPLAM** | **195** | |

---

## Ek: Symbol Matching Notlari

### Mach-O'da underscore prefix
macOS Mach-O binary'lerinde C fonksiyon symbol'leri `_` prefix'i ile saklanir.
Ornegin `sqlite3_open` -> `_sqlite3_open`. Eslestirme yaparken her iki hali de kontrol edilmeli.

### C++ name mangling (protobuf)
protobuf gibi C++ kutuphanelerde symbol'ler Itanium ABI mangling kullanir.
`c++filt` veya Ghidra'nin dahili demangler'i ile okunabilir hale gelir.
Ornek: `_ZN6google8protobuf11MessageLite17SerializeToStringEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE`
-> `google::protobuf::MessageLite::SerializeToString(std::string*)`

### Swift mangling
Swift symbol'leri `$s` veya `_$s` prefix'i ile baslar (Swift 5+).
`swift demangle` komutu ile okunabilir hale gelir. Ancak runtime fonksiyonlari
(`swift_retain`, `swift_release` vb.) C linkage'dir ve mangling yoktur.

### Tipik binary'de en sik gorulen symbol'ler (Avast RealtimeProtection ornegi)
1. `_objc_msgSend` (binlerce cagri)
2. `_swift_retain` / `_swift_release` (yuzlerce)
3. `_dispatch_once` / `_dispatch_once_f`
4. `_objc_msgSendSuper2`
5. `_swift_retain_n` / `_swift_release_n`
