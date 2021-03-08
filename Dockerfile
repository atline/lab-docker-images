FROM 3.9.2-slim-buster

RUN pip install lavacli; rm -fr /root/.cache
