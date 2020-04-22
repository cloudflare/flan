import csv
from typing import Any, Dict

from contrib.descriptions import VulnDescriptionProvider
from contrib.internal_types import ScanResult
from contrib.report_builders import ReportBuilder

class CSVReportBuilder(ReportBuilder):
    def __init__(self, description_provider: VulnDescriptionProvider):
        self.description_provider = description_provider
        self._buffer = ''

    def build(self) -> Any:
        return self._buffer
        pass

    def add_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        with open('tempcsv.csv', "w+") as csvfile:
            wr = csv.writer(csvfile, dialect='excel')
            for app_name, result in scan_results.items():
                for vulnResult in result.vulns:
                    for addr, ports in result.locations.items():
                        description = self.description_provider.get_description(vulnResult.name, vulnResult.vuln_type)
                        csvRow = [addr, ports, app_name, vulnResult.name, description.text, vulnResult.severity, vulnResult.severity_str, description.url]
                        wr.writerow(csvRow)
        with open('tempcsv.csv', "r+") as csvfile:
            reader = csv.reader(csvfile, delimiter=' ', quotechar='|', skipinitialspace=True)
            data = []
            VulnData = 'IP, Port, Title, CVE,Description,Risk Score,Severity,References\n'
            for row in reader:
                data = ' '.join(row)
                VulnData = VulnData + data + '\n'
        self._buffer = VulnData
        return self._buffer