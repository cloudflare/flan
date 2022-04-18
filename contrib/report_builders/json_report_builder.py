import json
from collections import defaultdict
from typing import Any, Dict, List

from contrib.descriptions import VulnDescriptionProvider
from contrib.internal_types import ScanResult
from contrib.report_builders import ReportBuilder


class JsonReportBuilder(ReportBuilder):
    def __init__(self, description_provider: VulnDescriptionProvider):
        self.description_provider = description_provider
        self._buffer = {'ips': [], 'vulnerable': {}, 'not_vulnerable': {}}

    def init_report(self, start_date: str, nmap_command: str):
        self._buffer['start_date'] = start_date
        self._buffer['nmap_command'] = nmap_command

    def build(self) -> Any:
        return json.dumps(self._buffer)

    def add_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        for app_name, result in scan_results.items():
            self._buffer['vulnerable'][app_name] = {
                'vulnerabilities': defaultdict(list),
                'locations': self._serialize_locations(result.locations)
            }

            for vuln_cpe, vuln in result.vulns.items():
                for v in vuln:
                    data = v.to_dict()
                    description = self.description_provider.get_description(v.name, v.vuln_type)
                    data['description'], data['url'] = description.text, description.url
                    self._buffer['vulnerable'][app_name]['vulnerabilities'][vuln_cpe].append(data)

    def add_non_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        for app_name, result in scan_results.items():
            self._buffer['not_vulnerable'][app_name] = {
                'locations': self._serialize_locations(result.locations)
            }

    def add_ip_address(self, ip: str):
        self._buffer['ips'].append(ip)

    @staticmethod
    def _serialize_locations(locations: Dict[str, List[str]]):
        return {loc: [int(port) for port in ports] for loc, ports in locations.items()}
