from datetime import datetime
from typing import Any, Dict, List

from contrib.descriptions import VulnDescriptionProvider
from contrib.internal_types import ScanResult
from contrib.report_builders import ReportBuilder

__all__ = ['MarkdownReportBuilder']


class MarkdownReportBuilder(ReportBuilder):
    def __init__(self, description_provider: VulnDescriptionProvider):
        self.description_provider = description_provider
        self._buffer = ''

    def init_report(self, start_date: str, nmap_command: str):
        self._append_line(self.header)
        self._append_line('## {date:%B %d, %Y}'.format(date=datetime.utcnow()))
        self._append_line('### **Summary**')
        self._append_line('Flan Scan ran a network vulnerability scan with the following Nmap command on {date}'
                          .format(date=start_date))
        self._append_line('`{command}`'.format(command=nmap_command))

    def build(self) -> Any:
        return self._buffer

    def add_vulnerable_section(self):
        self._append_line('### Services with vulnerabilities')

    def add_non_vulnerable_section(self):
        self._append_line('### Services with no *known* vulnerabilities')

    def add_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        for i, pair in enumerate(scan_results.items(), start=1):
            app_name, report = pair  # type: str, ScanResult
            self._append_service(i, app_name)
            num_vulns = len(report.vulns)

            for v in report.vulns:
                description = self.description_provider.get_description(v.name, v.vuln_type)
                self._append_line('- [**{name}** {severity} ({severity_num})]({link} "{title}")'
                                  .format(name=v.name, severity=v.severity_str, severity_num=v.severity,
                                          link=description.url, title=v.name), spaces=4)
                self._append_line('```text', separators=1, spaces=6)
                self._append_line(description.text, separators=1, spaces=6)
                self._append_line('```', spaces=6)

            self._append_line('The above {num} vulnerabilities apply to these network locations'.format(num=num_vulns),
                              spaces=4)
            self._append_line('```text', separators=1, spaces=4)
            for addr, ports in report.locations.items():
                self._append_location(addr, ports, spaces=4)
            self._append_line('```', spaces=4)

    def add_non_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        for i, pair in enumerate(scan_results.items(), start=1):
            app_name, report = pair  # type: str, ScanResult
            self._append_service(i, app_name)

            for addr, ports in report.locations.items():
                self._append_location(addr, ports, spaces=4)
            self._append('\n')

    def initialize_section(self):
        pass

    def add_ips_section(self):
        self._append_line('### List of IPs Scanned')

    def add_ip_address(self, ip: str):
        self._append_line('- {ip}'.format(ip=ip), separators=1)

    def finalize(self):
        pass

    @property
    def header(self) -> Any:
        return '# Flan scan report'

    def _append(self, text: str, spaces: int = 0):
        if spaces:
            self._buffer += ' ' * spaces
        self._buffer += text

    def _append_line(self, text: str, separators: int = 2, spaces: int = 0):
        self._append(text, spaces)
        self._append('\n' * separators)

    def _append_service(self, index: int, name: str, spaces: int = 0):
        self._append_line('{index}. **{service}**'.format(index=index, service=name.strip()), spaces=spaces,
                          separators=1)

    def _append_location(self, address: str, ports: List[str], spaces: int):
        self._append_line('- {address} Ports: {ports}'.format(address=address, ports=', '.join(ports)), spaces=spaces,
                          separators=1)
