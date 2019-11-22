FROM python:3.5-alpine

RUN apk add nmap nmap-scripts git

RUN pip install xmltodict google-cloud-storage boto3

RUN git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners && nmap --script-updatedb
RUN mkdir /shared

COPY run.sh output_report.py latex_header.tex gcp_push.py aws_push.py /
COPY shared /shared

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
