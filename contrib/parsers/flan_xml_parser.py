from collections import defaultdict
from typing import Dict, Any, List, Set

import xmltodict

from contrib.internal_types import ScanResult, Vuln


__all__ = ['FlanXmlParser']


class FlanXmlParser:
    """
    NMAP XML file reader and contents parser
    """
    def __init__(self):
        self.results = defaultdict(ScanResult)
        self.vulnerable_services = []  # type: List[str]

    @property
    def vulnerable_dict(self) -> Dict[str, ScanResult]:
        """
        :return: Map {app_name -> scan result} for vulnerable services
        """
        return {service: self.results[service] for service in self.vulnerable_services}

    @property
    def non_vulnerable_dict(self) -> Dict[str, ScanResult]:
        """
        :return: Map {app_name -> scan result} for services without detected vulnerabilities
        """
        return {service: self.results[service] for service in self.non_vuln_services}

    @property
    def non_vuln_services(self) -> Set[str]:
        """
        :return: App names for services without detected vulnerabilities
        """
        return set(self.results) - set(self.vulnerable_services)

    def parse(self, data: Dict[str, Any]):
        """
        Parse xmltodict output and fill internal collections
        :param data: xmltodict output
        """
        if 'host' not in data['nmaprun']:
            return

        hosts = data['nmaprun']['host']

        if isinstance(hosts, list):
            for h in hosts:
                self.parse_host(h)
        else:
            self.parse_host(hosts)

    def parse_vuln(self, app_name: str, vuln: List[Dict[str, Any]]):
        vuln_name = ''
        severity = ''
        vuln_type = ''
        for field in vuln:
            if field['@key'] == 'cvss':
                severity = float(field['#text'])
            elif field['@key'] == 'id':
                vuln_name = field['#text']
            elif field['@key'] == 'type':
                vuln_type = field['#text']

        self.results[app_name].vulns.append(Vuln(vuln_name, vuln_type, severity))

    def parse_script(self, ip_addr: str, port: str, app_name: str, script: Dict[str, Any]):
        if 'table' not in script:
            print('ERROR in script: ' + script['@output'] + " at location: " + ip_addr + " port: " + port + " app: " +
                  app_name)
            return
        self.vulnerable_services.append(app_name)
        script_table = script['table']['table']
        if isinstance(script_table, list):
            for vuln in script_table:
                self.parse_vuln(app_name, vuln['elem'])
        else:
            self.parse_vuln(app_name, script_table['elem'])

    def parse_port(self, ip_addr: str, port: Dict[str, Any]):
        if port['state']['@state'] == 'closed':
            return

        app_name = self.get_app_name(port['service'])
        port_num = port['@portid']
        new_app = app_name not in self.results
        self.results[app_name].locations[ip_addr].append(port_num)

        if new_app and 'script' in port:  # vulnerabilities parsed only if this app didn't appear before
            scripts = port['script']
            if isinstance(scripts, list):
                for s in scripts:
                    if s['@id'] == 'vulners':
                        self.parse_script(ip_addr, port_num, app_name, s)
            else:
                if scripts['@id'] == 'vulners':
                    self.parse_script(ip_addr, port_num, app_name, scripts)

    def parse_host(self, host: Dict[str, Any]):
        addresses = host['address']
        ip_addr = ''
        if isinstance(addresses, list):
            for addr in addresses:
                if "ip" in addr['@addrtype']:
                    ip_addr = addr['@addr']
        else:
            ip_addr = addresses['@addr']

        if not ip_addr:
            return

        if host['status']['@state'] == 'up' and 'ports' in host.keys() and 'port' in host['ports']:
            ports = host['ports']['port']
            if isinstance(ports, list):
                for p in ports:
                    self.parse_port(ip_addr, p)
            else:
                self.parse_port(ip_addr, ports)

    def read_xml_file(self, path: str) -> Dict[str, Any]:
        """
        Read file and convert to dictionary. To read raw contents use `read_xml_contents`

        :param path: path to .xml file
        :return: parsed contents
        """
        with open(path) as f:
            contents = f.read()
            return self.read_xml_contents(contents)

    @staticmethod
    def get_app_name(service: Dict[str, Any]) -> str:
        app_name = ''
        if '@product' in service:
            app_name += service['@product'] + ' '
            if '@version' in service:
                app_name += service['@version'] + ' '
        elif '@name' in service:
            app_name += service['@name'] + ' '

        if 'cpe' in service:
            if isinstance(service['cpe'], list):
                for cpe in service['cpe']:
                    app_name += '(' + cpe + ') '
            else:
                app_name += '(' + service['cpe'] + ') '
        return app_name

    @staticmethod
    def read_xml_contents(contents: str) -> Dict[str, Any]:
        return xmltodict.parse(contents)
