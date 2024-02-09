# Docker file for shim-review request from WAXAR
FROM debian:bookworm

# install appropriate dependencies
RUN apt-get -y -q update
RUN apt-get -y -q install gcc make gcc-aarch64-linux-gnu git

# clone shim
WORKDIR /build
RUN git clone --recursive -b 15.8 https://github.com/rhboot/shim.git shim-15.8
WORKDIR /build/shim-15.8

# copy patch files to workdir
ADD Patches/626.patch .

RUN git config user.email "jurij.ivastsuk@waxar.eu"
RUN git config user.name "Jurij Ivastsuk-Kienbaum"

# apply Patch
RUN git am 626.patch

# include certificate and custom sbat
ADD waxar.cer .
ADD waxar_sbat.csv .

# add custom data to the original sbat.csv
RUN cat waxar_sbat.csv >> data/sbat.csv

# Create build directories
RUN mkdir build-x86_64
RUN mkdir build-aarch64

# Build x86_64
RUN make -C build-x86_64 ARCH=x86_64 VENDOR_CERT_FILE=../waxar.cer TOPDIR=.. -f ../Makefile

# Build aarch64
RUN make -C build-aarch64 ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu- VENDOR_CERT_FILE=../waxar.cer TOPDIR=.. -f ../Makefile

# Print the SHA256 of the shims.
RUN sha256sum build-x86_64/shimx64.efi
RUN sha256sum build-aarch64/shimaa64.efi

