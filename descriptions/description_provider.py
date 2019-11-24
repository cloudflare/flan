import abc
from requests import Session, HTTPError

__all__ = ['VulnDescriptionProvider', 'CveProjectProvider']


class VulnDescriptionProvider(metaclass=abc.ABCMeta):
    """
    Provides extended vulnerability description by vulnerablity identifier and type
    """
    @abc.abstractmethod
    def get_description(self, vuln: str, vuln_type: str) -> str:
        pass


class CveProjectProvider(VulnDescriptionProvider):
    """
    Provides vulnerability descriptions using requests to CVEProject
    """
    uri_template = 'https://raw.githubusercontent.com/CVEProject/cvelist/master/{}/{}/{}.json'

    def __init__(self, session: Session):
        self.sess = session

    def get_description(self, vuln: str, vuln_type: str) -> str:
        try:
            if vuln_type == 'cve':
                year = vuln[4:8]
                section = vuln[9:-3] + 'xxx'
                url = self.uri_template.format(year, section, vuln)
                response = self.sess.get(url)
                response.raise_for_status()
                cve_json = response.json()
                return cve_json['description']['description_data'][0]['value']
        except HTTPError as he:
            return 'Description fetching error: ' + str(he)

        return ''
