from collections import defaultdict
from typing import List, Dict

__all__ = ['SeverityLevels', 'Vuln', 'ScanResult']


class SeverityLevels:
    """
    Just constants
    """
    Low = 'Low'
    Medium = 'Medium'
    High = 'High'


class Vuln:
    """
    Descriptor for vulnerability
    """
    def __init__(self, name: str, vuln_type: str, severity: float):
        self.name = name
        self.vuln_type = vuln_type
        self.severity = severity

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.vuln_type,
            'severity': self.severity,
            'severity_str': self.severity_str
        }

    @staticmethod
    def convert_severity(severity: float) -> str:
        """
        :return: Float severity value to text
        """
        if severity < 4:
            return 'Low'
        if severity < 7:
            return 'Medium'
        return 'High'

    @property
    def severity_str(self) -> str:
        """
        :return: Text severity representation
        """
        return self.convert_severity(self.severity)


class ScanResult:
    """
    Scan result representation
    """
    def __init__(self):
        self.locations = defaultdict(list)  # type: Dict[str, List[str]]
        self.vulns = []  # type: List[Vuln]
