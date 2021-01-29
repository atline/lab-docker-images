FROM ubuntu:18.04

RUN set -eux;\
apt-get update;\
apt-get install --no-install-recommends -y python python-pip telnet libnet-telnet-perl libftdi1-dev libyaml-dev libssl1.0-dev sudo;\
pip install pexpect;\
rm -rf /var/lib/apt/lists/*
