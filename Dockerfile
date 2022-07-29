FROM python:3.9-alpine

COPY aws_push.py gcp_push.py output_report.py requirements.txt run.sh mail_to.py /
COPY contrib /contrib
COPY shared /shared

#    apk del git && \

RUN apk add --no-cache nmap nmap-scripts git && \
    pip install --no-cache-dir -r requirements.txt && \
    git clone https://github.com/vulnersCom/nmap-vulners \
      /usr/share/nmap/scripts/vulners && \
    nmap --script-updatedb && \
    chmod +x /run.sh

ENTRYPOINT ["/bin/sh","-c","/run.sh"]
