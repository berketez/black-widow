"""Black Widow — native macOS pencere (pywebview / WKWebView).

UI'ı TARAYICI yerine gerçek bir uygulama penceresinde açar. ``ui/server.py``'yi
alt-süreç olarak başlatır (env'i miras alır: GHIDRA_INSTALL_DIR, KARADUL_DATA_DIR,
JAVA_HOME), yanıt vermesini bekler, sonra WKWebView penceresini açar. Pencere
kapanınca server sonlandırılır ve uygulama kapanır. .app launcher bunu exec eder.
"""
from __future__ import annotations

import atexit
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"

# `git remote get-url origin` -> git@github.com:berketez/black-widow.git.
# Sabit: paketlenmiş .app'te git yok, remote çalışma anında sorulamaz.
# Ad "REPO_URL" değil: scripts/gen_mingw_headers_sigs.py'deki REPO_URL
# mingw-w64 upstream klon adresi -- farklı kavram, karışmasın.
PROJECT_REPO_URL = "https://github.com/berketez/black-widow"
PROJECT_ISSUES_URL = f"{PROJECT_REPO_URL}/issues"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# Sabit 8000 iki şekilde kırılıyordu: (1) portta başka bir HTTP servisi varsa
# pencere onun arayüzünü açıyordu, (2) eski bir öksüz server'a bağlanıyordu.
# Artık boş port seçilir ve kimlik jetonuyla "bizim server" doğrulanır.
PORT = int(os.environ["KARADUL_PORT"]) if os.environ.get("KARADUL_PORT") else _free_port()
TOKEN = os.environ.get("KARADUL_TOKEN") or secrets.token_hex(16)
os.environ["KARADUL_PORT"] = str(PORT)
os.environ["KARADUL_TOKEN"] = TOKEN
URL = f"http://127.0.0.1:{PORT}"


def _up() -> bool:
    """Yalnızca BİZİM server'ımız için True (yabancı/öksüz servis eşleşmesin)."""
    try:
        with urllib.request.urlopen(f"{URL}/api/ping", timeout=1) as r:
            return json.load(r).get("token") == TOKEN
    except Exception:
        return False


def _data_dir() -> Path:
    """server.py'nin _DATA_ROOT'u ile aynı kural (env yoksa repo kökü).

    expanduser().resolve() ZORUNLU, süs değil: server.py:53 aynısını yapıyor.
    Olmazsa KARADUL_DATA_DIR="~/x" verildiğinde server /Users/.../x'e yazarken
    burası "~" adında GERÇEK bir klasör açardı (mkdir literal '~' oluşturur) ->
    "Veri Klasörünü Göster" boş bir klasör, "Günlüğü Göster" hiçbir şey açardı.
    TEK fark: server yazılamayan dizinde PROJECT_ROOT'a düşer (server.py:54-57);
    o durumda launcher'ın mkdir'i zaten patlamış olur, buraya gelinmez.
    """
    return Path(os.environ.get("KARADUL_DATA_DIR") or HERE.parent).expanduser().resolve()


# create_window dönüşü: menü eylemleri sayfaya JS'i bunun üzerinden gönderir.
_window = None
# Pencere kapandı: _patch_app_menu'nun bekleme döngüsü buna bakıp erken çıkar.
_closed = threading.Event()


def _js(call: str) -> None:
    """Sayfaya JS gönder; başarısızlığı yut.

    evaluate_js sayfa hazır olana kadar 20 sn bekler, sonra istisna atar
    (window.py:_pywebview_ready_call). Menü eylemleri pywebview tarafından ayrı
    bir thread'de çalıştırıldığı için (cocoa.py:MenuHandler) burada bloklamak
    pencereyi dondurmaz; ama istisna thread'i çökertmesin.
    """
    try:
        if _window is not None:
            _window.evaluate_js(call)
    except Exception:
        pass


def _open_path(path: Path) -> None:
    """Finder/varsayılan uygulamada aç. `open` yoksa/başarısızsa sessiz geç."""
    try:
        subprocess.run(["open", str(path)], check=False)
    except Exception:
        pass


def _act_about() -> None:
    _js("window.bwOpenAbout && window.bwOpenAbout()")


def _act_settings() -> None:
    _js("window.bwOpenSettings && window.bwOpenSettings()")


def _act_data_dir() -> None:
    d = _data_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)   # ilk açılışta henüz olmayabilir
    except OSError:
        pass
    _open_path(d)


def _act_log() -> None:
    """ui.log (bu süreç yazar) yoksa app.log (.app launcher yazar), o da yoksa klasör.

    Tıklandığında hiçbir şey yapmayan madde bırakmamak için zincir sonda
    veri klasörüne düşer.
    """
    d = _data_dir()
    for name in ("ui.log", "app.log"):
        p = d / name
        if p.exists():
            _open_path(p)
            return
    _act_data_dir()


def _open_url(url: str) -> None:
    """Tarayıcıda aç; başarısızlığı yut.

    Guard şart: menü eylemleri pywebview'in ayrı thread'inde koşuyor
    (cocoa.py:MenuHandler) -> buradan sızan istisna sessizce app.log'a traceback
    basar, kullanıcı tıklamanın neden bir şey yapmadığını anlamaz.
    """
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _act_readme() -> None:
    _open_url(PROJECT_REPO_URL)


def _act_issues() -> None:
    _open_url(PROJECT_ISSUES_URL)


class _JsApi:
    """Sayfadan (WKWebView) Python'a köprü: pencerede açılan güncelleme
    bildirimindeki "İndir" düğmesi bunu çağırır.

    NEDEN köprü: WKWebView içinden ``<a target=_blank>`` harici bağlantısı
    güvenilmez açılıyor (bkz. _open_url notu) -> tıklama Python'a gelir,
    tarayıcı sistem tarafında açılır. Güvenlik: JS'ten KEYFİ URL almaz;
    yalnızca sabit releases sayfasını açar (enjeksiyon yüzeyi yok).
    """

    def bw_open_releases(self) -> bool:      # window.pywebview.api.bw_open_releases()
        _open_url(f"{PROJECT_REPO_URL}/releases")
        return True


def _check_update_async() -> None:
    """Arka planda (daemon) yeni sürüm var mı bak; varsa sayfada banner göster.

    ASLA UI'ı bloklamaz, ASLA istisna yaymaz. Kendi server'ımızın
    ``/api/update-check`` ucunu çağırır (semver mantığı orada, tek yerde).
    Güncelleme yoksa/ağ yoksa sessizce döner -- kullanıcı hiçbir şey görmez.
    """
    try:
        with urllib.request.urlopen(f"{URL}/api/update-check", timeout=8) as r:
            info = json.load(r)
    except Exception:
        return
    if not isinstance(info, dict) or info.get("status") != "update_available":
        return
    payload = {
        "latest": info.get("latest"),
        "current": info.get("current"),
        "url": info.get("url") or f"{PROJECT_REPO_URL}/releases",
    }
    # _js sayfa hazır olana kadar bekler (evaluate_js); daemon thread'te güvenli.
    _js("window.bwShowUpdate && window.bwShowUpdate(%s)" % json.dumps(payload))


def _credits_file() -> Path | None:
    """Bileşen/lisans özeti. Bundle: Resources/Credits.html (HERE=Resources/ui).

    Dev: repo'daki paketleme kaynağı. Yoksa None -> menü maddesi hiç eklenmez
    (tıklanınca hiçbir şey yapmayan madde bırakmayız).
    """
    for p in (HERE.parent / "Credits.html",                          # bundle
              HERE.parent / "packaging" / "macos" / "app" / "Credits.html"):  # dev
        if p.is_file():
            return p
    return None


def _act_credits() -> None:
    """Credits.html'i tarayıcıda aç.

    NEDEN standart Cocoa "Hakkında" paneli DEĞİL: About maddesi zaten web
    modalına bağlandı (_act_about), standart panel hiç açılmıyor. Ayrıca
    NSBundle.mainBundle() = Resources/python/bin olduğundan Cocoa Credits'i
    kendiliğinden bulamıyor (build_mac_app.sh'teki nota bak).
    """
    p = _credits_file()
    if p is not None:
        _open_url(p.resolve().as_uri())


# Menü çubuğu Türkçeleştirme. Anahtarlar webview/localization.py'den (13 cocoa.menu.*).
# KISIT: cocoa.py:_append_app_name about/hide/quit sonuna CFBundleName ekler ->
# "Gizle Black Widow" gibi bozuk Türkçe üretirdi. Süreç .app olarak değil düz
# script olarak başladığından mainBundle.infoDictionary() boş, o yüzden ek yapılmıyor.
# KISIT: cocoa.menu.fullscreen etkisiz (cocoa.py:1141'de upstream TODO).
LOCALIZATION = {
    "cocoa.menu.about": "Hakkında",
    "cocoa.menu.services": "Servisler",
    "cocoa.menu.view": "Görünüm",
    "cocoa.menu.edit": "Düzen",
    "cocoa.menu.hide": "Gizle",
    "cocoa.menu.hideOthers": "Diğerlerini Gizle",
    "cocoa.menu.showAll": "Tümünü Göster",
    "cocoa.menu.quit": "Çık",
    "cocoa.menu.fullscreen": "Tam Ekran",
    "cocoa.menu.cut": "Kes",
    "cocoa.menu.copy": "Kopyala",
    "cocoa.menu.paste": "Yapıştır",
    "cocoa.menu.selectAll": "Tümünü Seç",
    "global.quitConfirmation": "Çıkmak istediğinize emin misiniz?",
    "global.ok": "Tamam",
    "global.quit": "Çık",
    "global.cancel": "Vazgeç",
    "global.saveFile": "Dosyayı kaydet",
}

_APP_TITLE = "Black Widow"
_ABOUT_TITLE = "Black Widow Hakkında"
_SETTINGS_TITLE = "Ayarlar…"
_ABOUT_ACTION_ID = "bw_about.menu"   # menu_handler.representedObject anahtarı


def _build_menu() -> list:
    """Menü ağacını kur (pencere açmadan çağrılabilir -- test edilebilirlik).

    "__app__" başlıklı Menu, cocoa.py:_add_app_menu tarafından ayrıştırılıp
    uygulama menüsüne About ile Services ARASINA yerleştirilir.
    KISIT: MenuAction kısayol desteklemiyor (menu.py'de upstream TODO);
    ⌘, _patch_app_menu içinde setKeyEquivalent_ ile ekleniyor.
    """
    from webview.menu import Menu, MenuAction, MenuSeparator

    help_items = [
        MenuAction("README (GitHub)", _act_readme),
        MenuAction("Sorun Bildir (GitHub)", _act_issues),
    ]
    # Sadece dosya GERÇEKTEN varsa ekle: core build'de de kopyalanıyor ama
    # olmayan bir dosya için ölü menü maddesi bırakmayalım.
    if _credits_file() is not None:
        help_items.append(MenuAction("Bileşenler ve Lisanslar…", _act_credits))
    help_items += [
        MenuSeparator(),
        # About yaması tutmazsa modale ulaşan tek yol bu madde kalır.
        MenuAction("Sürüm ve Bileşenler…", _act_about),
    ]

    return [
        Menu("__app__", [
            MenuAction(_SETTINGS_TITLE, _act_settings),
            MenuSeparator(),
            MenuAction("Veri Klasörünü Göster", _act_data_dir),
            MenuAction("Günlüğü Göster", _act_log),
        ]),
        Menu("Yardım", help_items),
    ]


def _patch_app_menu() -> None:
    """İki maddeyi yamala: standart About -> bizim modal, Ayarlar -> ⌘,.

    Baştan sona guardlı: yama tutmazsa standart About paneli kalır ve uygulama
    çökmez.

    İki zamanlama tuzağı var:
    1) start(func=...) thread'i menü HENÜZ kurulmadan başlar (menü
       cocoa.py:first_show'da, app.run()'dan hemen önce kurulur).
    2) İlk windowDidBecomeKey_ olayında current_menu (başlangıçta None) bizim
       menümüzden farklı olduğu için menü BİR KEZ yeniden kurulur ve yama
       silinir (cocoa.py:82-86).
    İkisi de aşağıdaki "bir süre boyunca idempotent tekrar uygula" döngüsüyle
    karşılanıyor. AppKit ana thread dışından güvenli olmadığından yama
    callAfter ile ana thread'e gönderilir.
    """
    try:
        import AppKit
        from PyObjCTools import AppHelper
        from webview.platforms import cocoa
    except Exception:
        return

    def _apply() -> None:
        """Yamayı uygula. Ana thread'de (callAfter) çalışır, idempotenttir."""
        try:
            main_menu = AppKit.NSApplication.sharedApplication().mainMenu()
            if main_menu is None or main_menu.numberOfItems() == 0:
                return          # menü henüz kurulmadı; sonraki turda yeniden dene

            # Menü çubuğunda kalın uygulama adı: yamasız "python3.12" yazıyor.
            # Sebep: bw_launch.sh .app'i değil doğrudan python'u exec ediyor ->
            # mainBundle Resources/python/bin'i gösteriyor, CFBundleName okunmuyor.
            # NSProcessInfo.setProcessName_ ETKİSİZ (ölçüldü); menü maddesinin
            # başlığını yazmak çalışıyor.
            main_menu.itemAtIndex_(0).setTitle_(_APP_TITLE)

            app_menu = main_menu.itemAtIndex_(0).submenu()
            if app_menu is None or app_menu.numberOfItems() == 0:
                return

            about = app_menu.itemAtIndex_(0)   # _add_app_menu About'u ilk ekler
            if about.representedObject() != _ABOUT_ACTION_ID:
                cocoa.menu_handler.register_action(_ABOUT_ACTION_ID, _act_about)
                about.setTitle_(_ABOUT_TITLE)
                about.setTarget_(cocoa.menu_handler)
                about.setAction_("handleMenuAction:")
                about.setRepresentedObject_(_ABOUT_ACTION_ID)

            # NOT: keyEquivalent sonradan "," okunmayabilir -- AppKit menüdeki
            # kısayolu aktif klavye düzenine göre yeniden eşler
            # (allowsAutomaticKeyEquivalentLocalization, varsayılan açık).
            # Türkçe-Q düzeninde ⌘, -> ⌘ö görünür; sistem uygulamalarıyla aynı
            # davranış, hata değil. Guard bu yüzden "boş mu" diye bakıyor.
            item = app_menu.itemWithTitle_(_SETTINGS_TITLE)
            if item is not None and not item.keyEquivalent():
                item.setKeyEquivalent_(",")
                item.setKeyEquivalentModifierMask_(AppKit.NSCommandKeyMask)
        except Exception:
            pass            # yama tutmadı -> standart About paneli kalır

    # _apply idempotent; erken çıkma YOK. Yeniden kurulum ile bizim ilk
    # yamamızın sırası belirsiz (ikisi de app.run() sonrası aynı event loop'ta
    # işlenir) -> "3 kez tuttu" görüp bırakırsak geç gelen kurulum yamayı
    # silebilir. Sabit bir pencere boyunca tekrar uygulamak hem daha basit hem
    # daha sağlam; kontrol ucuz ve arka planda.
    # _closed.wait() KULLAN, time.sleep() DEĞİL: pywebview bu fonksiyonu
    # daemon OLMAYAN bir thread'de koşturuyor (webview/__init__.py:294-301) ->
    # CPython önce non-daemon thread'leri join eder, atexit'i SONRA çalıştırır
    # (ölçüldü). sleep ile: pencere 1. saniyede kapatılırsa server+Ghidra'yı
    # öldüren atexit 6. saniyeye kadar beklerdi; kullanıcı kapattığı uygulamanın
    # Dock'ta takılı kaldığını görürdü. wait() pencere kapanınca hemen döner.
    deadline = time.time() + 6
    while time.time() < deadline:
        try:
            AppHelper.callAfter(_apply)
        except Exception:
            return
        if _closed.wait(0.3):
            return


def main() -> int:
    global _window
    proc: subprocess.Popen | None = None
    if not _up():
        data_dir = _data_dir()
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            log = open(data_dir / "ui.log", "w")
        except OSError:
            log = subprocess.DEVNULL  # type: ignore[assignment]
        proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdout=log, stderr=subprocess.STDOUT, env=os.environ.copy(),
            # Kendi süreç grubu -> kapanışta tüm ağacı killpg ile götürebilelim.
            # start_new_session DEĞİL: posix_spawn setsid'i desteklemediğinden
            # Python fork_exec'e düşer ve macOS'ta fork deadlock riski doğar.
            process_group=0,
        )

        def _shutdown(_p: subprocess.Popen = proc) -> None:
            """Server'ı VE altındaki analiz/JVM ağacını götür.

            terminate() yalnız server'a SIGTERM atıyordu; ``karadul analyze`` ve
            Ghidra JVM onun çocukları -> öksüz kalıp saatlerce CPU yiyorlardı.
            atexit: pywebview kapanışında ``finally`` her zaman unwind edilmiyor.
            """
            if _p.poll() is not None:
                return
            try:
                os.killpg(os.getpgid(_p.pid), signal.SIGTERM)
                _p.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(_p.pid), signal.SIGKILL)
                except Exception:
                    pass

        atexit.register(_shutdown)

        for _ in range(80):          # ~24 sn: Ghidra'sız server anında kalkar
            if _up():
                break
            if proc.poll() is not None:   # server öldü (ör. port bind hatası)
                sys.stderr.write("server başlatılamadı; ui.log'a bakın\n")
                return 1
            time.sleep(0.3)
        else:
            sys.stderr.write("server zamanında yanıt vermedi; ui.log'a bakın\n")

    import webview  # pywebview -> macOS'ta WKWebView (pyobjc)

    _window = webview.create_window(
        "Black Widow",
        URL,
        width=1280,
        height=840,
        min_size=(960, 640),
        background_color="#06080d",   # Black Widow koyu tema (beyaz flash olmasın)
        js_api=_JsApi(),              # güncelleme banner'ındaki "İndir" köprüsü
    )
    # Menü yama döngüsü pencere kapanınca beklemeyi bıraksın (bkz. _patch_app_menu).
    # Guardlı: bu event olmasa da işleyiş aynı, sadece kapanış 6 sn'ye kadar gecikir.
    try:
        _window.events.closed += _closed.set
    except Exception:
        pass
    # Güncelleme kontrolü: pencere açıldıktan sonra BİR KEZ, arka planda (daemon ->
    # pencere erken kapanırsa ölür), bloklamadan. Sonucu sayfada banner gösterir.
    try:
        threading.Thread(target=_check_update_async, daemon=True).start()
    except Exception:
        pass
    # menü/localization kurulamazsa pencere yine de açılsın (menüsüz > açılmayan).
    try:
        menu = _build_menu()
    except Exception:
        menu = []
    webview.start(                    # Cocoa event loop -- pencere kapanana kadar bloklar
        func=_patch_app_menu,
        menu=menu,
        localization=LOCALIZATION,
    )
    return 0                          # temizlik atexit ile (finally atlanabiliyor)


if __name__ == "__main__":
    sys.exit(main())
