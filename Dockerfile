FROM python:3.7-alpine

RUN apk add --no-cache nmap nmap-scripts git

RUN pip install --no-cache-dir xmltodict google-cloud-storage google-api-python-client boto3

RUN git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners && nmap --script-updatedb
RUN mkdir /shared

COPY run.sh output_report.py latex_header.tex gcp_push.py aws_push.py list_ip.py /
COPY shared /shared

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
