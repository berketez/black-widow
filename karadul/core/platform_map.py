"""Platform map: TargetType -> signature platform string.

v1.10.0 M2 pre-cleanup: stages.py ve pipeline/steps/ghidra_metadata.py'daki
duplikasyon bu modulde merkezilestirildi. CLAUDE.md kural 11 (magic number
consistency) geregidir.

v1.10.0 E9: JS bundle, Electron, .NET, Delphi, Go, Bun, APK/JAR ve Python
paketli hedefler haritaya eklendi. Onceden bu tipler haritada yoktu ve
imza arama adimlari "unknown" platform ile yanlis sonuc ureiyordu.
"""

from karadul.core.target import TargetType

TARGET_PLATFORM_MAP: dict = {
    # Native binary'ler
    TargetType.MACHO_BINARY: "macho",
    TargetType.UNIVERSAL_BINARY: "macho",
    TargetType.ELF_BINARY: "elf",
    TargetType.PE_BINARY: "pe",
    # JS tabanli hedefler (Electron, Node bundle)
    TargetType.JS_BUNDLE: "js",
    TargetType.ELECTRON_APP: "js",
    # macOS .app bundle (icindeki main executable Mach-O)
    TargetType.APP_BUNDLE: "macho",
    # JVM / Android
    TargetType.JAVA_JAR: "java",
    TargetType.ANDROID_APK: "android",
    # .NET CLR
    TargetType.DOTNET_ASSEMBLY: "dotnet",
    # Delphi PE binary (Windows)
    TargetType.DELPHI_BINARY: "pe",
    # Go (stripped native)
    TargetType.GO_BINARY: "go",
    # Bun (JS runtime'i Mach-O'ya embed ediyor)
    TargetType.BUN_BINARY: "macho",
    # Python packer (PyInstaller/cx_Freeze)
    TargetType.PYTHON_PACKED: "python",
}
