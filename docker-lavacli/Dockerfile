FROM python:3.9.2-slim-buster

ENV REQUESTS_CA_BUNDLE='/etc/ssl/certs/ca-certificates.crt'

RUN pip install lavacli; rm -fr /root/.cache

COPY scripts /usr/local/bin
RUN chmod +x /usr/local/bin/lava-role-wait
