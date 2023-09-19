from requests import Session, HTTPError

from contrib.descriptions import VulnDescriptionProvider, VulnDescription

__all__ = ['CveProjectProvider']


class CveProjectProvider(VulnDescriptionProvider):
    """
    Provides vulnerability descriptions using requests to CVEProject
    """
    uri_template = 'https://raw.githubusercontent.com/CVEProject/cvelist/master/{}/{}/{}.json'
    nist_uri_template = 'https://nvd.nist.gov/vuln/detail/{}'

    def __init__(self, session: Session):
        self.sess = session
        self.cache = {}

    def get_description(self, vuln: str, vuln_type: str) -> VulnDescription:
        if vuln in self.cache:
            return self.cache[vuln]

        try:
            if vuln_type == 'cve':
                year = vuln[4:8]
                section = vuln[9:-3] + 'xxx'
                url = self.uri_template.format(year, section, vuln)
                response = self.sess.get(url)
                response.raise_for_status()
                cve_json = response.json()
                description = cve_json['description']['description_data'][0]['value']
                vuln_description = VulnDescription(description, self.nist_uri_template.format(vuln))
                self.cache[vuln] = vuln_description
                return vuln_description
        except HTTPError as he:
            return VulnDescription('', 'Description fetching error: ' + str(he))

        return VulnDescription('', '')
