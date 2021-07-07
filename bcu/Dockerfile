FROM ubuntu:18.04

# e.g. bcu_1.1.28
ARG git_tag

RUN set -eux;\
apt-get update;\
apt-get install -y libftdi1-2 libyaml-dev openssl --no-install-recommends;\
rm -rf /var/lib/apt/lists/*;\
wget --no-check-certificate -O /bin/bcu https://github.com/NXPmicro/bcu/releases/download/$git_tag/bcu_Ubuntu18;\
chmod +x /bin/bcu
