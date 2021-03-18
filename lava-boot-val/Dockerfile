FROM ubuntu:18.04

RUN set -eux;\
apt-get update;\
apt-get install --no-install-recommends -y python python-pip telnet libnet-telnet-perl libftdi1-dev libyaml-dev libssl1.0-dev sudo python3 python3-pip;\
pip install pexpect;\
pip3 install pytest==6.2.2 requests==2.22.0 pyserial==3.5;\
rm -rf /var/lib/apt/lists/*
