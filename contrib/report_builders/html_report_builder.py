import os
from typing import Any

from jinja2 import Template, FileSystemLoader, Environment

from contrib.descriptions import VulnDescriptionProvider
from contrib.report_builders import JsonReportBuilder


class JinjaHtmlReportBuilder(JsonReportBuilder):
    def __init__(self, description_provider: VulnDescriptionProvider):
        super().__init__(description_provider)
        self.template_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')
        self.template_name = 'jinja2_report.html'
        self._read_template()  # type: Template

    def build(self) -> Any:
        return self._template.render(data=self._buffer)

    def _read_template(self):
        template_loader = FileSystemLoader(searchpath=self.template_path)
        template_env = Environment(loader=template_loader, autoescape=True)
        self._template = template_env.get_template(self.template_name)
