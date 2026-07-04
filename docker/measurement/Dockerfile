# Karadul ölçüm container'ı — Ghidra 12.1.2 + ARM64 native decompiler + karadul
# Hedef platform: linux/arm64 (Apple Silicon native, Colima VM)
# Build context = proje kökü:  docker build -f docker/measurement/Dockerfile -t karadul-meas:latest .

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=12.1.2
ENV GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Sistem bağımlılıkları:
#   openjdk-21-jdk     -> Ghidra 12.x Java 21 (+ native build için)
#   python3.12         -> ubuntu:24.04 default (jpype aarch64 wheel cp312 var)
#   build-essential    -> native decompiler/sleigh derleme (g++/make)
#   bison, flex        -> sleigh parser üretimi (yoksa native build patlar)
#   binutils, file     -> nm/strip/readelf (ground truth + ELF metadata)
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-21-jdk \
        python3.12 python3.12-dev python3-pip python3.12-venv \
        build-essential g++ make bison flex \
        wget unzip ca-certificates \
        binutils file \
    && rm -rf /var/lib/apt/lists/*

# Ghidra indir + SHA256 doğrula + unzip (573 MB — ayrı katman, cache'lenir)
RUN wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC "$GHIDRA_INSTALL_DIR"

# ARM64 native decompiler + sleigh derle ve kurulu layout'a (os/linux_arm_64) yerleştir.
# PUBLIC release linux_arm_64 native içermez; sadece :Decompiler:buildNatives derlenir
# (global `buildNatives` ARM64'te başka bir GPL native projede patlıyor; karadul'un
# ihtiyacı yalnızca decompile + sleigh). gradle çıktıyı build/os/ altına koyar;
# Ghidra runtime os/ altından okur -> kopyalanır. test -x ile gerçekten oluştuğu
# doğrulanır, aksi halde build burada durur.
RUN cd "$GHIDRA_INSTALL_DIR/support/gradle" \
    && ./gradlew --no-daemon --console=plain :Decompiler:buildNatives \
    && D="$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler" \
    && mkdir -p "$D/os/linux_arm_64" \
    && cp "$D/build/os/linux_arm_64/decompile" "$D/build/os/linux_arm_64/sleigh" "$D/os/linux_arm_64/" \
    && chmod 755 "$D/os/linux_arm_64/decompile" "$D/os/linux_arm_64/sleigh" \
    && test -x "$D/os/linux_arm_64/decompile" \
    && test -x "$D/os/linux_arm_64/sleigh" \
    && file "$D/os/linux_arm_64/decompile" \
    && rm -rf /root/.gradle "$D/build"

# Bundled PyGhidra + jpype wheel'lerini kur (PyPI'dan değil — Java tarafıyla hizalı).
RUN python3.12 -m pip install --break-system-packages --no-index \
        --find-links="$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra

# Karadul kaynağı + bağımlılıklar (en son katman: kod değişince Ghidra layer'ı bozulmaz)
COPY . /app/karadul
WORKDIR /app/karadul
RUN python3.12 -m pip install --break-system-packages -e ".[ghidra,perf,computation,binary]"

# Container içi config (Ghidra path + LMDB path override)
RUN cp /app/karadul/docker/measurement/karadul.yaml /root/karadul.yaml

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
WORKDIR /work
