FROM python:3.5-alpine

RUN apk add --no-cache nmap nmap-scripts git
COPY requirements.txt /
RUN pip install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners && nmap --script-updatedb
RUN mkdir /shared

COPY run.sh output_report.py gcp_push.py aws_push.py /
COPY contrib /contrib
COPY shared /shared

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
