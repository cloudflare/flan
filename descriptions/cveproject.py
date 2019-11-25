from requests import Session, HTTPError

from descriptions import VulnDescriptionProvider


__all__ = ['CveProjectProvider']


class CveProjectProvider(VulnDescriptionProvider):
    """
    Provides vulnerability descriptions using requests to CVEProject
    """
    uri_template = 'https://raw.githubusercontent.com/CVEProject/cvelist/master/{}/{}/{}.json'

    def __init__(self, session: Session):
        self.sess = session
        self.cache = {}

    def get_description(self, vuln: str, vuln_type: str) -> str:
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
                self.cache[vuln] = description
                return description
        except HTTPError as he:
            return 'Description fetching error: ' + str(he)

        return ''
