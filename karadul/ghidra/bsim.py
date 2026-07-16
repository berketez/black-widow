"""BSim fonksiyon benzerlik analiz modulu.

Ghidra'nin BSim altyapisini kullanarak fonksiyon hash'leri olusturur
ve cross-binary benzerlik sorgusu yapar. H2 file-based veritabani
kullanir, harici DB sunucusu gerektirmez.

Iki mod destekler:
  1. BSim native: Ghidra BSim API (ghidra.features.bsim) erisilebiliyorsa
     gercek feature vector hash'leri kullanir.
  2. BSim lite (fallback): API yoksa decompiled C kodu + opcode histogram
     uzerinden SHA256 hash'i hesaplayarak JSON-based basit benzerlik
     index'i tutar.

Kullanim:
    bsim = BSimDatabase(config)
    bsim.create_database("my_db")
    bsim.ingest_program(program, "my_db")
    matches = bsim.query_all_functions(program, min_similarity=0.7)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    pass  # Ghidra type'lari runtime'da import edilir

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BSim API kullanilabilirlik kontrolu (graceful degradation)
# ---------------------------------------------------------------------------
_BSIM_AVAILABLE: Optional[bool] = None


def _check_bsim() -> bool:
    """Ghidra BSim API'sinin erisilebilir olup olmadigini kontrol et.

    Sonuc cache'lenir — modül omru boyunca bir kez kontrol edilir.
    PyGhidra disinda calisiyorsak veya BSim modulleri yuklenmemisse
    False doner ve bsim_lite moduna dusulur.
    """
    global _BSIM_AVAILABLE
    if _BSIM_AVAILABLE is None:
        try:
            from ghidra.features.bsim.query import BSimServerInfo  # noqa: F401
            _BSIM_AVAILABLE = True
        except (ImportError, Exception):
            _BSIM_AVAILABLE = False
    return _BSIM_AVAILABLE


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------

@dataclass
class BSimMatch:
    """Tek bir fonksiyon eslesmesi."""
    query_function: str       # Sorgulanan fonksiyon adi
    query_address: str        # Sorgulanan fonksiyon adresi (hex)
    matched_function: str     # Eslesen fonksiyon adi
    matched_program: str      # Eslesen program/binary adi
    similarity: float         # Benzerlik skoru [0.0, 1.0]
    # KISIT: significance [0,1] DEGILDIR -- 0.0'dan baslar, UST SINIRI YOK
    # (olculdu: /bin/zsh'de 8.23..6262.77). Fonksiyon boyutuyla olceklenir.
    # Iki modun degerleri AYNI OLCEKTE DEGIL: native gercek BSim skoru
    # (sinirsiz), lite ise elle atanmis 0.5/0.8/1.0 sabitleri. Iki modun
    # significance'ini KARSILASTIRMA / esikleme.
    significance: float


@dataclass
class BSimResult:
    """Toplu sorgu sonucu."""
    total_queries: int        # Sorgulanan fonksiyon sayisi
    total_matches: int        # Bulunan esleme sayisi
    matches: list[BSimMatch]  # Esleme listesi
    database_name: str        # Kullanilan veritabani adi
    query_duration: float     # Sorgu suresi (saniye)


# ---------------------------------------------------------------------------
# BSim Lite: fallback hash + JSON index
# ---------------------------------------------------------------------------

class _BSimLiteIndex:
    """BSim API yokken kullanilan basit benzerlik index'i.

    Her fonksiyon icin iki hash uretir:
      - structural_hash: Decompiled C kodunun normalize edilmis SHA256'si.
        Degisken isimleri, bosluklar ve yorumlar temizlendikten sonra
        hash'lenir.
      - opcode_hash: Instruction opcode histograminin SHA256'si.
        Benzer algoritmalar benzer opcode dagilimlarina sahip olur.

    Benzerlik hesabi:
      - Iki hash de eslesirse similarity = 1.0
      - Sadece structural eslesirse similarity = 0.85
      - Sadece opcode eslesirse similarity = 0.65
      - Hicbiri eslesmezse sorgu sonucuna dahil edilmez
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.index_file = db_path / "bsim_lite_index.json"
        self._index: dict[str, Any] = self._load_index()

    def _load_index(self) -> dict[str, Any]:
        """Mevcut JSON index'i yukle veya bos olustur."""
        if self.index_file.exists():
            try:
                return json.loads(self.index_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("BSim lite index okunamadi, sifirdan olusturuluyor: %s", exc)
        return {"version": 1, "databases": {}}

    def _save_index(self) -> None:
        """Index'i diske kaydet."""
        self.db_path.mkdir(parents=True, exist_ok=True)
        self.index_file.write_text(
            json.dumps(self._index, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def create_database(self, name: str) -> None:
        """Yeni bos veritabani girisi olustur."""
        if name not in self._index["databases"]:
            self._index["databases"][name] = {"programs": {}, "created": time.time()}
            self._save_index()

    def has_database(self, name: str) -> bool:
        return name in self._index["databases"]

    def list_databases(self) -> list[dict[str, Any]]:
        """Mevcut veritabanlarini listele."""
        result = []
        for db_name, db_data in self._index["databases"].items():
            program_count = len(db_data.get("programs", {}))
            total_functions = sum(
                len(prog.get("functions", {}))
                for prog in db_data.get("programs", {}).values()
            )
            result.append({
                "name": db_name,
                "program_count": program_count,
                "function_count": total_functions,
                "created": db_data.get("created", 0),
                "mode": "bsim_lite",
            })
        return result

    @staticmethod
    def _normalize_code(code: str) -> str:
        """Decompiled C kodunu normalize et.

        Degisken isimlerini (local_X, param_X, FUN_XXX, DAT_XXX),
        bosluklari, yorumlari ve satir numaralarini temizleyerek
        yapisi ayni ama isimleri farkli fonksiyonlarin eslesebilmesini saglar.
        """
        import re
        # Yorum temizle
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # Ghidra otomatik isimleri normalize et
        code = re.sub(r'\blocal_[0-9a-fA-F]+\b', 'LOCAL', code)
        code = re.sub(r'\bparam_\d+\b', 'PARAM', code)
        code = re.sub(r'\bFUN_[0-9a-fA-F]+\b', 'FUNC', code)
        code = re.sub(r'\bDAT_[0-9a-fA-F]+\b', 'DATA', code)
        code = re.sub(r'\buVar\d+\b', 'VAR', code)
        code = re.sub(r'\biVar\d+\b', 'VAR', code)
        code = re.sub(r'\blVar\d+\b', 'VAR', code)
        code = re.sub(r'\bsVar\d+\b', 'VAR', code)
        code = re.sub(r'\bcVar\d+\b', 'VAR', code)
        code = re.sub(r'\bpuVar\d+\b', 'VAR', code)
        # Hex sabitleri normalize et
        code = re.sub(r'0x[0-9a-fA-F]+', 'HEX', code)
        # Bosluk normalize et
        code = re.sub(r'\s+', ' ', code).strip()
        return code

    @staticmethod
    def _compute_structural_hash(code: str) -> str:
        """Normalize edilmis C kodundan yapisal hash uret."""
        normalized = _BSimLiteIndex._normalize_code(code)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_opcode_hash(instructions: list[dict[str, Any]]) -> str:
        """Instruction listesinden opcode histogram hash'i uret.

        Her instruction'in mnemonic'ini sayar, siralayip hash'ler.
        Benzer algoritmalar benzer opcode dagilimi gosterir.
        """
        histogram: dict[str, int] = {}
        for instr in instructions:
            mnemonic = instr.get("mnemonic", instr.get("op", "UNK"))
            histogram[mnemonic] = histogram.get(mnemonic, 0) + 1
        # Siralanmis histogram string'i
        hist_str = "|".join(f"{k}:{v}" for k, v in sorted(histogram.items()))
        return hashlib.sha256(hist_str.encode("utf-8")).hexdigest()

    def ingest_function(
        self,
        db_name: str,
        program_name: str,
        func_name: str,
        func_address: str,
        decompiled_code: str = "",
        instructions: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        """Tek bir fonksiyonu veritabanina ekle."""
        if db_name not in self._index["databases"]:
            self.create_database(db_name)

        db = self._index["databases"][db_name]
        if program_name not in db["programs"]:
            db["programs"][program_name] = {"functions": {}}

        entry: dict[str, Any] = {
            "name": func_name,
            "address": func_address,
        }
        if decompiled_code:
            entry["structural_hash"] = self._compute_structural_hash(decompiled_code)
        if instructions:
            entry["opcode_hash"] = self._compute_opcode_hash(instructions)

        db["programs"][program_name]["functions"][func_address] = entry

    def save(self) -> None:
        """Degisiklikleri diske yaz."""
        self._save_index()

    def query_function(
        self,
        db_name: str,
        func_address: str,
        structural_hash: str = "",
        opcode_hash: str = "",
        exclude_program: str = "",
        min_similarity: float = 0.7,
        max_results: int = 5,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin benzer fonksiyonlari ara."""
        if db_name not in self._index["databases"]:
            return []

        db = self._index["databases"][db_name]
        matches: list[BSimMatch] = []

        for prog_name, prog_data in db["programs"].items():
            if prog_name == exclude_program:
                continue
            for addr, func_entry in prog_data.get("functions", {}).items():
                if addr == func_address and prog_name == exclude_program:
                    continue

                sim = 0.0
                sig = 0.0
                entry_struct = func_entry.get("structural_hash", "")
                entry_opcode = func_entry.get("opcode_hash", "")

                # Benzerlik hesapla
                struct_match = structural_hash and entry_struct and structural_hash == entry_struct
                opcode_match = opcode_hash and entry_opcode and opcode_hash == entry_opcode

                if struct_match and opcode_match:
                    sim = 1.0
                    sig = 1.0
                elif struct_match:
                    sim = 0.85
                    sig = 0.8
                elif opcode_match:
                    sim = 0.65
                    sig = 0.5
                else:
                    continue

                if sim < min_similarity:
                    continue

                matches.append(BSimMatch(
                    query_function=func_address,
                    query_address=func_address,
                    matched_function=func_entry.get("name", addr),
                    matched_program=prog_name,
                    similarity=sim,
                    significance=sig,
                ))

        # Benzerlige gore sirala, max_results kadar dondur
        matches.sort(key=lambda m: (-m.similarity, -m.significance))
        return matches[:max_results]


# ---------------------------------------------------------------------------
# BSim Native: Ghidra BSim API wrapper
# ---------------------------------------------------------------------------

# Ghidra 12.1.2 BSim ayar sablonu. Ghidra/Features/BSim/data/ altindaki
# medium_*.xml dosyalarindan biri olmali; isim degil DOSYA ADI (uzantisiz)
# beklenir. "nosize" varyanti fonksiyon boyutunu feature'a katmaz -> ayni
# algoritmanin farkli optimizasyon seviyelerindeki halleri eslesebilir.
_BSIM_CONFIG_TEMPLATE = "medium_nosize"

# significance ESIGI -- DIKKAT, OLCEK SEZGISEL DEGIL.
#
# Ghidra javadoc'u (SimilarityNote.getSignificance): deger 0.0'dan baslar ve
# UST SINIRI YOKTUR. similarity [0,1] arasidir, significance DEGILDIR.
# Kucuk fonksiyonlar dusuk significance alir cunku cok sayida kucuk fonksiyonun
# tesaduefen benzer vektor uretme ihtimali yuksektir. Filtrenin amaci bu
# tesadueffi eslesmeleri elemektir.
#
# OLCUM (2026-07-16, /bin/zsh, 1073 fonksiyon, self-match significance):
#   min/maks        : 8.23 / 6262.77
#   <32 byte fonks. : en fazla 45.06
#   esik 0.5        -> 1073/1073 kalir  (yani 0.5 HICBIR SEY elemez!)
#   esik 20.0       ->  883/1073 kalir
#   esik 40.0       ->  657/1073 kalir
#
# Bu yuzden varsayilan Ghidra'nin kendi degeri olan 0.0'da BIRAKILDI: uydurma
# bir sayi koymaktansa Ghidra ile ayni davranmak durust. Anlamli bir esik
# secmek icin cross-binary ground-truth (precision/recall) deneyi gerekir --
# yukaridaki olcum SELF-match'tir, yani her fonksiyonun alabilecegi EN YUKSEK
# significance'tir; cop eslesmelerin dagilimini GOSTERMEZ.
# Cagiran taraf query_similar(significance_threshold=...) ile yukseltebilir.
_DEFAULT_SIGNIFICANCE_THRESHOLD = 0.0


class _BSimNativeWrapper:
    """Ghidra BSim API'si uzerinde wrapper.

    PyGhidra icinden calistiginda Ghidra'nin gercek BSim feature
    vector engine'ini kullanir. H2 file-based veritabani ile calısır.

    NOT: Bu sinif sadece PyGhidra JVM icinde import edilebilir.
    Dogrudan Python'dan calistirilirsa ImportError verir.

    KISIT (Ghidra 12.1.2, javap ile dogrulandi): `FunctionDatabase` bir
    INTERFACE'tir ve `openDatabase(...)` diye bir static metodu YOKTUR.
    Istemci `BSimClientFactory.buildClient(BSimServerInfo, boolean)` ile
    kurulur. Ayni sekilde `GenSignatures`'ta `setProgram`/`openDatabase`/
    `flush` YOKTUR; dogrusu `openProgram(...)` + `scanFunction(...)` +
    `getDescriptionManager()`, ve yazma `InsertRequest.execute(db)` ile olur.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._database = None

    # -- yardimcilar --------------------------------------------------

    def _server_info(self, name: str) -> Any:
        """H2 dosya-tabanli BSimServerInfo uret.

        KISIT: tek-String ctor DBType.file secer ve cleanupFilename() ile
        yolu dogrular. Yol MUTLAK olmali ("/" ile baslamali), "/" ile
        BITMEMELI ve "file:" prefix'i ICERMEMELI -> aksi halde
        "Invalid absolute file path". ".mv.db" uzantisini Ghidra KENDI
        ekler, biz eklemiyoruz (iki kez eklenmesin).
        """
        from ghidra.features.bsim.query import BSimServerInfo

        return BSimServerInfo((self.db_path / name).resolve().as_posix())

    def _last_error(self, database: Any) -> str:
        """FunctionDatabase.getLastError()'dan okunabilir mesaj cikar."""
        try:
            err = database.getLastError()
            if err is not None:
                return str(err.message)
        except Exception:  # noqa: BLE001
            pass
        return "bilinmeyen BSim hatasi"

    def _build_client(self, name: str, initialize: bool = True) -> Any:
        """BSimClientFactory ile istemci kur (openDatabase DEGIL).

        initialize=False sadece CreateDatabase icin: DB dosyasi henuz yokken
        initialize() basarisiz olur, once CreateDatabase.execute() calismali.
        """
        from ghidra.features.bsim.query import BSimClientFactory

        # async=False -> sorgular cagiran thread'de calisir. PyGhidra tek
        # JVM thread'inde ilerledigi icin async kuyruk gereksiz.
        database = BSimClientFactory.buildClient(self._server_info(name), False)
        if initialize and not database.initialize():
            msg = self._last_error(database)
            try:
                database.close()
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f"BSim DB initialize basarisiz ({name}): {msg}")
        return database

    def _gen_signatures(self, database: Any, program: Any) -> Any:
        """Program icin GenSignatures kur.

        KISIT: setVectorFactory() DB'nin LSHVectorFactory'si ile cagrilmali,
        yoksa uretilen vektorler DB'nin ayarlariyla uyusmaz ve insert/query
        "settings" hatasi verir.
        """
        from ghidra.features.bsim.query import GenSignatures

        gen = GenSignatures(True)
        gen.setVectorFactory(database.getLSHVectorFactory())
        # Kanonik cagri (SimilarFunctionQueryService ile birebir ayni):
        # openProgram(prog, nmover, archover, compover, repo, path)
        # nmover/archover/compover None -> Ghidra degerleri program'dan okur
        # (override etmiyoruz). repo/path None -> yerel dosya, repo yok.
        gen.openProgram(program, None, None, None, None, None)
        return gen

    @staticmethod
    def _iter_real_functions(program: Any) -> list[Any]:
        """Thunk/external olmayan fonksiyonlari topla."""
        funcs = []
        func_iter = program.getFunctionManager().getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            if func.isThunk() or func.isExternal():
                continue
            funcs.append(func)
        return funcs

    # -- public -------------------------------------------------------

    def create_database(self, name: str) -> Path:
        """H2 file-based BSim veritabani olustur."""
        from ghidra.features.bsim.query.description import DatabaseInformation
        from ghidra.features.bsim.query.protocol import CreateDatabase

        db_file = self.db_path / f"{name}.mv.db"
        # DB dosyasi henuz yok -> initialize() etme, CreateDatabase halleder.
        database = self._build_client(name, initialize=False)
        try:
            cmd = CreateDatabase()
            cmd.info = DatabaseInformation()
            # None birakilan alanlari config template dolduruyor.
            cmd.info.databasename = name
            cmd.info.owner = "karadul"
            cmd.info.description = "Karadul BSim fonksiyon benzerlik veritabani"
            cmd.info.trackcallgraph = True
            cmd.config_template = _BSIM_CONFIG_TEMPLATE

            # KISIT: execute() hata halinde exception ATMAZ, None doner.
            # Gercek sebep getLastError()'dadir.
            if cmd.execute(database) is None:
                raise RuntimeError(
                    f"BSim CreateDatabase basarisiz ({name}): {self._last_error(database)}"
                )
            logger.info("BSim native DB olusturuldu: %s", db_file)
        except Exception as exc:
            logger.warning("BSim native DB olusturulamadi: %s, lite moda dusecek", exc)
            raise
        finally:
            try:
                database.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)

        return db_file

    def ingest_program(self, program: Any, db_name: str) -> int:
        """Programdaki fonksiyonlari BSim veritabanina ekle."""
        from ghidra.features.bsim.query.protocol import InsertRequest

        # TUZAK: headless.py (asil app yolu) create_database'i HIC cagirmaz,
        # dogrudan ingest_program'a girer -- create_database yalnizca
        # `karadul bsim create` CLI komutundan cagriliyor. DB dosyasi yoksa
        # initialize() basarisiz olur, BSimDatabase.ingest_program exception'i
        # yutup lite moda duser ve native yol SESSIZCE hic calismaz.
        # Bu yuzden eksikse burada kendimiz olusturuyoruz (idempotent).
        if not (self.db_path / f"{db_name}.mv.db").exists():
            logger.info("BSim DB yok, olusturuluyor: %s", db_name)
            self.create_database(db_name)

        database = self._build_client(db_name)
        gen = None
        try:
            gen = self._gen_signatures(database, program)

            func_count = 0
            for func in self._iter_real_functions(program):
                try:
                    gen.scanFunction(func)
                    func_count += 1
                except Exception:
                    logger.debug(
                        "BSim fonksiyon taramasi basarisiz, atlaniyor", exc_info=True
                    )

            if func_count == 0:
                logger.warning("BSim ingest: taranabilen fonksiyon yok (%s)", db_name)
                return 0

            manager = gen.getDescriptionManager()

            # TUZAK (canli testte yakalandi, Ghidra 12.1.2):
            # callgraphtable'da (src,dest) PRIMARY KEY'dir. Bir fonksiyon ayni
            # hedefi birden fazla kez cagiriyorsa GenSignatures AYNI kenari
            # tekrar tekrar kaydeder ve insert
            #   "Unique index or primary key violation: PRIMARY_KEY_50
            #    ON public.callgraphtable(src, dest)"
            # ile patlar.
            # Bu kenarlari tekillestiren tek yer FunctionDescription.
            # sortCallgraph()'tir ve Ghidra onu SADECE DescriptionManager.
            # saveXml() icinden cagirir. Ghidra'nin kanonik ingest yolu
            # (BulkSignatures) imzalari once XML'e yazip geri okudugu icin
            # dedup'i "bedava" alir; biz DescriptionManager'i dogrudan
            # InsertRequest'e verdigimiz icin XML round-trip'i yok ->
            # dedup'i ELIMIZLE yapmak ZORUNDAYIZ.
            for fdesc in manager.listAllFunctions():
                fdesc.sortCallgraph()

            # Uretilen imzalar GenSignatures'in DescriptionManager'inda birikir;
            # DB'ye yazan sey InsertRequest.
            req = InsertRequest()
            req.manage = manager
            if req.execute(database) is None:
                raise RuntimeError(
                    f"BSim InsertRequest basarisiz ({db_name}): {self._last_error(database)}"
                )
            return func_count
        finally:
            if gen is not None:
                try:
                    gen.dispose()
                except Exception:  # noqa: BLE001
                    logger.debug("GenSignatures dispose basarisiz", exc_info=True)
            try:
                database.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)

    def query_similar(
        self,
        program: Any,
        function_name: str,
        db_name: str,
        min_similarity: float = 0.7,
        max_results: int = 5,
        significance_threshold: float = _DEFAULT_SIGNIFICANCE_THRESHOLD,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin benzer fonksiyonlari sorgula."""
        from ghidra.features.bsim.query.protocol import QueryNearest

        database = self._build_client(db_name)
        gen = None
        try:
            target_func = None
            for func in self._iter_real_functions(program):
                if func.getName() == function_name:
                    target_func = func
                    break
            if target_func is None:
                return []

            # Sorgu vektoru de GenSignatures ile uretilir; sorgulanan
            # fonksiyon(lar) QueryNearest.manage icinde tasinir.
            gen = self._gen_signatures(database, program)
            try:
                gen.scanFunction(target_func)
            except Exception:
                logger.debug("BSim sorgu fonksiyonu taranamadi", exc_info=True)
                return []

            query = QueryNearest()
            query.manage = gen.getDescriptionManager()
            query.thresh = float(min_similarity)
            query.signifthresh = float(significance_threshold)
            query.max = int(max_results)

            response = query.execute(database)
            if response is None:
                logger.warning(
                    "BSim QueryNearest basarisiz (%s): %s",
                    db_name,
                    self._last_error(database),
                )
                return []

            query_addr = str(target_func.getEntryPoint())
            matches: list[BSimMatch] = []
            # ResponseNearest.result -> List<SimilarityResult>
            # SimilarityResult iterable -> SimilarityNote (similarity+significance)
            for sim_result in response.result:
                for note in sim_result:
                    fdesc = note.getFunctionDescription()
                    exe = fdesc.getExecutableRecord()
                    matches.append(BSimMatch(
                        query_function=function_name,
                        query_address=query_addr,
                        matched_function=str(fdesc.getFunctionName()),
                        matched_program=str(exe.getNameExec()) if exe else "",
                        similarity=float(note.getSimilarity()),
                        significance=float(note.getSignificance()),
                    ))
            return matches
        finally:
            if gen is not None:
                try:
                    gen.dispose()
                except Exception:  # noqa: BLE001
                    logger.debug("GenSignatures dispose basarisiz", exc_info=True)
            try:
                database.close()
            except Exception:  # noqa: BLE001
                logger.debug("BSim DB close basarisiz", exc_info=True)

    def close(self) -> None:
        """Acik veritabani baglantisini kapat."""
        if self._database is not None:
            try:
                self._database.close()
            except Exception:
                logger.debug("Session/kaynak kapatma basarisiz, atlaniyor", exc_info=True)
            self._database = None


# ---------------------------------------------------------------------------
# Ana BSimDatabase sinifi
# ---------------------------------------------------------------------------

class BSimDatabase:
    """BSim fonksiyon benzerlik veritabani yoneticisi.

    Otomatik olarak BSim native veya BSim lite modunu secer:
    - Ghidra BSim API erisilebiliyorsa native mod (gercek feature vector)
    - Degilse lite mod (SHA256 hash + JSON index)

    Attributes:
        config: Karadul konfigurasyonu
        db_path: Veritabani dizini
        mode: "native" veya "lite"
    """

    def __init__(self, config: Any) -> None:
        """BSimDatabase baslat.

        Args:
            config: Config nesnesi (config.bsim.db_path kullanilir).
                    Bos ise ~/.cache/karadul/bsim/ varsayilir.
        """
        bsim_cfg = getattr(config, "bsim", None)
        if bsim_cfg and bsim_cfg.db_path:
            self.db_path = Path(bsim_cfg.db_path)
        else:
            self.db_path = Path.home() / ".cache" / "karadul" / "bsim"
        self.db_path.mkdir(parents=True, exist_ok=True)

        self.config = config
        self._closed = False

        # Mod secimi
        if _check_bsim():
            self.mode = "native"
            self._native: Optional[_BSimNativeWrapper] = _BSimNativeWrapper(self.db_path)
            self._lite: Optional[_BSimLiteIndex] = None
            logger.info("BSim native mod aktif")
        else:
            self.mode = "lite"
            self._native = None
            self._lite = _BSimLiteIndex(self.db_path)
            logger.info("BSim lite mod aktif (Ghidra BSim API bulunamadi)")

    def create_database(self, name: str) -> Path:
        """Yeni BSim veritabani olustur.

        Args:
            name: Veritabani adi

        Returns:
            Olusturulan veritabani dosyasinin Path'i
        """
        self.db_path.mkdir(parents=True, exist_ok=True)

        if self.mode == "native" and self._native is not None:
            try:
                return self._native.create_database(name)
            except Exception as exc:
                logger.warning(
                    "BSim native DB olusturulamadi, lite moda dusulecek: %s", exc
                )
                self.mode = "lite"
                self._lite = _BSimLiteIndex(self.db_path)

        # Lite mod
        if self._lite is not None:
            self._lite.create_database(name)
        return self.db_path / f"{name}.bsim_lite.json"

    def ingest_program(self, program: Any, db_name: str) -> int:
        """Programdaki tum fonksiyonlari hash'leyerek veritabanina ekle.

        Args:
            program: Ghidra program nesnesi (FlatProgramAPI uzerinden)
            db_name: Hedef veritabani adi

        Returns:
            Eklenen fonksiyon sayisi
        """
        if self.mode == "native" and self._native is not None:
            try:
                return self._native.ingest_program(program, db_name)
            except Exception as exc:
                logger.warning("BSim native ingest basarisiz, lite'a dusulecek: %s", exc)
                self.mode = "lite"
                self._lite = _BSimLiteIndex(self.db_path)

        # Lite mod: Ghidra API'den fonksiyonlari cek, hash'le
        if self._lite is None:
            self._lite = _BSimLiteIndex(self.db_path)

        func_count = 0
        try:
            program_name = program.getName()
            func_manager = program.getFunctionManager()
            func_iter = func_manager.getFunctions(True)

            # Decompiler lazim
            decomp_iface = None
            try:
                from ghidra.app.decompiler import DecompInterface
                decomp_iface = DecompInterface()
                decomp_iface.openProgram(program)
            except (ImportError, Exception) as exc:
                logger.debug("Decompiler acilamadi: %s", exc)

            while func_iter.hasNext():
                func = func_iter.next()
                if func.isThunk() or func.isExternal():
                    continue

                func_name = func.getName()
                func_addr = str(func.getEntryPoint())

                # Decompile
                decompiled_code = ""
                if decomp_iface is not None:
                    try:
                        result = decomp_iface.decompileFunction(func, 30, None)
                        if result and result.decompileCompleted():
                            decompiled_func = result.getDecompiledFunction()
                            if decompiled_func:
                                decompiled_code = decompiled_func.getC()
                    except Exception:
                        logger.debug("BSim fonksiyon decompile basarisiz, atlaniyor", exc_info=True)

                # Instruction histogram icin instruction'lari topla
                instructions = []
                try:
                    listing = program.getListing()
                    instr_iter = listing.getInstructions(func.getBody(), True)
                    while instr_iter.hasNext():
                        instr = instr_iter.next()
                        instructions.append({
                            "mnemonic": instr.getMnemonicString(),
                        })
                except Exception:
                    logger.debug("BSim instruction toplama basarisiz, atlaniyor", exc_info=True)

                self._lite.ingest_function(
                    db_name=db_name,
                    program_name=program_name,
                    func_name=func_name,
                    func_address=func_addr,
                    decompiled_code=decompiled_code,
                    instructions=instructions,
                )
                func_count += 1

            if decomp_iface is not None:
                try:
                    decomp_iface.dispose()
                except Exception:
                    logger.debug("Decompiler interface dispose basarisiz, atlaniyor", exc_info=True)

            self._lite.save()
        except Exception as exc:
            logger.error("BSim lite ingest hatasi: %s", exc)
            # Kismen eklenmis fonksiyonlar kaybolmasin
            if self._lite is not None:
                self._lite.save()

        return func_count

    def query_similar(
        self,
        program: Any,
        function_name: str,
        min_similarity: float = 0.7,
        max_results: int = 5,
    ) -> list[BSimMatch]:
        """Tek fonksiyon icin veritabaninda benzer fonksiyonlari ara.

        Args:
            program: Ghidra program nesnesi
            function_name: Sorgulanacak fonksiyon adi
            min_similarity: Minimum benzerlik esigi [0.0, 1.0]
            max_results: Maksimum sonuc sayisi

        Returns:
            Eslesen fonksiyonlarin listesi (benzerlige gore sirali)
        """
        bsim_cfg = getattr(self.config, "bsim", None)
        db_name = bsim_cfg.default_database if bsim_cfg else "karadul_bsim"

        if self.mode == "native" and self._native is not None:
            # KISIT: BSimConfig'de henuz min_significance alani YOK (config.py
            # bu ajanin yetkisi disinda). getattr ile okuyoruz: alan sonradan
            # eklenirse kod degismeden devreye girer, yoksa modul varsayilani.
            signif = getattr(bsim_cfg, "min_significance", None)
            if signif is None:
                signif = _DEFAULT_SIGNIFICANCE_THRESHOLD
            try:
                return self._native.query_similar(
                    program, function_name, db_name, min_similarity, max_results,
                    significance_threshold=float(signif),
                )
            except Exception as exc:
                logger.warning("BSim native sorgu basarisiz: %s", exc)
                return []

        # Lite mod
        if self._lite is None:
            return []

        # Fonksiyonu bul ve hash'ini hesapla
        try:
            program_name = program.getName()
            func_manager = program.getFunctionManager()
            target_func = None
            func_iter = func_manager.getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                if func.getName() == function_name:
                    target_func = func
                    break

            if target_func is None:
                return []

            func_addr = str(target_func.getEntryPoint())

            # Decompile
            decompiled_code = ""
            try:
                from ghidra.app.decompiler import DecompInterface
                decomp_iface = DecompInterface()
                decomp_iface.openProgram(program)
                result = decomp_iface.decompileFunction(target_func, 30, None)
                if result and result.decompileCompleted():
                    decompiled_func = result.getDecompiledFunction()
                    if decompiled_func:
                        decompiled_code = decompiled_func.getC()
                decomp_iface.dispose()
            except (ImportError, Exception):
                pass

            # Instruction'lar
            instructions = []
            try:
                listing = program.getListing()
                instr_iter = listing.getInstructions(target_func.getBody(), True)
                while instr_iter.hasNext():
                    instr = instr_iter.next()
                    instructions.append({"mnemonic": instr.getMnemonicString()})
            except Exception:
                logger.debug("BSim query instruction toplama basarisiz, atlaniyor", exc_info=True)

            structural_hash = ""
            opcode_hash = ""
            if decompiled_code:
                structural_hash = _BSimLiteIndex._compute_structural_hash(decompiled_code)
            if instructions:
                opcode_hash = _BSimLiteIndex._compute_opcode_hash(instructions)

            return self._lite.query_function(
                db_name=db_name,
                func_address=func_addr,
                structural_hash=structural_hash,
                opcode_hash=opcode_hash,
                exclude_program=program_name,
                min_similarity=min_similarity,
                max_results=max_results,
            )
        except Exception as exc:
            logger.warning("BSim lite sorgu hatasi: %s", exc)
            return []

    def query_all_functions(
        self,
        program: Any,
        min_similarity: float = 0.7,
    ) -> BSimResult:
        """Programdaki tum fonksiyonlar icin toplu benzerlik sorgusu.

        Args:
            program: Ghidra program nesnesi
            min_similarity: Minimum benzerlik esigi [0.0, 1.0]

        Returns:
            BSimResult: Toplam sorgu istatistikleri ve eslesmeler
        """
        bsim_cfg = getattr(self.config, "bsim", None)
        db_name = bsim_cfg.default_database if bsim_cfg else "karadul_bsim"
        max_results = bsim_cfg.max_results_per_function if bsim_cfg else 5

        start_time = time.monotonic()
        all_matches: list[BSimMatch] = []
        total_queries = 0

        try:
            func_manager = program.getFunctionManager()
            func_iter = func_manager.getFunctions(True)
            func_names: list[str] = []

            while func_iter.hasNext():
                func = func_iter.next()
                if func.isThunk() or func.isExternal():
                    continue
                func_names.append(func.getName())

            total_queries = len(func_names)

            for func_name in func_names:
                try:
                    matches = self.query_similar(
                        program, func_name,
                        min_similarity=min_similarity,
                        max_results=max_results,
                    )
                    all_matches.extend(matches)
                except Exception:
                    logger.debug("BSim tek fonksiyon sorgusu basarisiz, atlaniyor", exc_info=True)

        except Exception as exc:
            logger.error("BSim toplu sorgu hatasi: %s", exc)

        duration = time.monotonic() - start_time

        return BSimResult(
            total_queries=total_queries,
            total_matches=len(all_matches),
            matches=all_matches,
            database_name=db_name,
            query_duration=round(duration, 3),
        )

    def list_databases(self) -> list[dict[str, Any]]:
        """Mevcut BSim veritabanlarini listele.

        Returns:
            Her veritabani icin {name, program_count, function_count, mode}
            iceren sozluk listesi
        """
        if self.mode == "lite" and self._lite is not None:
            return self._lite.list_databases()

        # Native modda da dosya sistemi taranabilir
        databases = []
        if self.db_path.exists():
            for f in self.db_path.iterdir():
                if f.suffix == ".db" and f.stem.endswith(".mv"):
                    db_name = f.stem.replace(".mv", "")
                    databases.append({
                        "name": db_name,
                        "path": str(f),
                        "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                        "mode": "native",
                    })

        # Lite index'te de veritabani olabilir
        lite_index = _BSimLiteIndex(self.db_path)
        databases.extend(lite_index.list_databases())

        return databases

    def close(self) -> None:
        """Tum kaynaklari serbest birak. Birden fazla cagri guvenlidir."""
        if self._closed:
            return
        self._closed = True

        if self._native is not None:
            self._native.close()
        if self._lite is not None:
            try:
                self._lite.save()
            except Exception:
                logger.debug("BSim lite DB save basarisiz, atlaniyor", exc_info=True)

    def __enter__(self) -> BSimDatabase:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            logger.debug("BSim destructor close basarisiz, atlaniyor", exc_info=True)
