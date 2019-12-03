FROM python:3.5-alpine

RUN apk add --no-cache nmap nmap-scripts git build-base libffi-dev openssl-dev

RUN pip install --no-cache-dir xmltodict google-cloud-storage boto3 azure-storage-blob

RUN apk del build-base

RUN git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners && nmap --script-updatedb
RUN mkdir /shared

COPY run.sh output_report.py latex_header.tex gcp_push.py aws_push.py az_push.py /
COPY shared /shared

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
