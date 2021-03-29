FROM python:3.9.2-slim-buster

RUN set -eux;\
apt-get update;\
apt-get install --no-install-recommends -y python3-certifi;\
pip install lavacli; rm -fr /root/.cache

COPY scripts /usr/local/bin
RUN chmod +x /usr/local/bin/lava-role-wait
