FROM ubuntu:18.04

# e.g. uuu_1.3.191
ARG git_tag

RUN set -eux;\
apt-get update;\
apt-get install -y nfs-common netbase libusb-1.0.0 wget bsdmainutils --no-install-recommends;\
rm -rf /var/lib/apt/lists/*;\
wget --no-check-certificate -O /bin/uuu https://github.com/NXPmicro/mfgtools/releases/download/$git_tag/uuu;\
chmod +x /bin/uuu
