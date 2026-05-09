# GNU coreutils benchmark fixture builder (v1.15-A)
#
# Karadul benchmark altyapisi icin GNU coreutils binary'lerini Ubuntu 24.04
# base image'tan cikarir. Hem stripped hem non-stripped versiyonlar uretir.
#
# Neden Ubuntu image'tan kopyalama (kaynak derleme yerine):
#   - Source build configure + make ~5 dk; bu yaklasim ~30 sn.
#   - Apt'in saglagi binary'ler universal Linux distrolarinda calisan
#     gerçek dunya örnekleridir.
#   - Tam paket reproducibility icin imaj versiyonu (24.04) sabit.
#
# Build:
#   docker build -t karadul-coreutils -f tests/fixtures/coreutils/Dockerfile .
#
# Extract:
#   docker run --rm -v $(pwd)/tests/fixtures/coreutils/binaries:/host \
#       karadul-coreutils cp -r /out/. /host/

FROM ubuntu:24.04

# Reproducible build: apt cache temizle, sadece coreutils + binutils
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        coreutils \
        binutils \
        file \
        && rm -rf /var/lib/apt/lists/*

# 30 yaygin coreutils binary kopyala (Ubuntu apt'tan gelen versiyonlar
# zaten stripped; gercek dunya HARD MODE fixture).
# Easy mode (non-stripped + debug info) v1.15.5'te source-build ile eklenir.
RUN mkdir -p /out/stripped /out/meta && \
    for f in ls cat cp mv rm mkdir rmdir touch echo pwd head tail sort uniq \
             wc cut tr expr seq sleep date true false env tee cmp test \
             readlink basename dirname stat ; do \
        if [ -f /usr/bin/$f ]; then \
            cp /usr/bin/$f /out/stripped/$f && \
            file /usr/bin/$f >> /out/meta/file_info.txt; \
        fi; \
    done

# Boyut + hash metadata uret (reproducibility kanit) + dynamic symbol
# count (ground truth taban cizgisi)
RUN cd /out && \
    (echo "=== stripped ELF binaries (real-world Ubuntu 24.04 apt) ===" && \
     ls -la stripped/ && \
     echo "" && echo "=== sha256 ===" && \
     sha256sum stripped/* && \
     echo "" && echo "=== nm -D dynamic symbol counts ===" && \
     for f in stripped/*; do \
         echo "$(basename $f): $(nm -D $f 2>/dev/null | wc -l) dyn symbols"; \
     done) > /out/meta/manifest.txt

CMD ["/bin/sh", "-c", "echo Coreutils fixture image hazir, /out icerigini cp et"]
