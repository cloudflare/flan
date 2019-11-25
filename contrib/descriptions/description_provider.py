import abc

__all__ = ['VulnDescriptionProvider']


class VulnDescriptionProvider(metaclass=abc.ABCMeta):
    """
    Provides extended vulnerability description by vulnerablity identifier and type
    """
    @abc.abstractmethod
    def get_description(self, vuln: str, vuln_type: str) -> str:
        pass