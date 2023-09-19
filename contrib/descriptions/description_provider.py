import abc
from typing import Optional

__all__ = ['VulnDescriptionProvider', 'VulnDescription']


class VulnDescription:
    def __init__(self, text: str, url: Optional[str] = None):
        self.text = text
        self.url = url


class VulnDescriptionProvider(metaclass=abc.ABCMeta):
    """
    Provides extended vulnerability description by vulnerablity identifier and type
    """
    @abc.abstractmethod
    def get_description(self, vuln: str, vuln_type: str) -> VulnDescription:
        pass
