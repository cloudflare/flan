import os
import sys
import json

from os import path
from neo4j import GraphDatabase

location_stm = """
MERGE (location:Location {ip:{ip}})
RETURN location.ip;
"""

service_stm = """
CREATE (service:Service {name:{name}}) 
RETURN service.name;
"""

vulnerability_stm = """
MERGE (vulnerability:Vulnerability {name:{name}, type:{type}})
RETURN vulnerability.name;
"""

svc_location_edge_stm = """
MATCH (s:Service), (l:Location)
WHERE s.name = {name} AND l.ip = {ip}
CREATE (s)-[r:IS_IN {port:{port}}]->(l)
RETURN r.port;
"""

svc_vuln_edge_stm = """
MATCH (s:Service), (v:Vulnerability)
WHERE s.name = {name} AND v.name = {vulnName}
CREATE (s)-[r:HAS {severity:{severity}}]->(v)
RETURN r.severity;
"""


######### UTILS ###############################
def read_file(filename):
    f = open(filename)
    content = f.read()
    f.close()

    return content


############## Data manipulation #################
def create_location(tx, ip):
	tx.run(location_stm, ip=ip)

def create_service(tx, service_name):
	tx.run(service_stm, name=service_name)

def create_vulnerability(tx, name, vuln_type):
	tx.run(vulnerability_stm, name=name, type=vuln_type)

def create_svc_location_edge(tx, service_name, ip, port):
	tx.run(svc_location_edge_stm, name=service_name, ip=ip, port=port)

def create_svc_vuln_edge(tx, service_name, vuln_name, severity):
	tx.run(svc_vuln_edge_stm, name=service_name, vulnName=vuln_name, severity=severity)





def main():
	neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
	neo4j_password = os.getenv("NEO4J_PASSWORD", "neo4j")
	neo4j_user = os.getenv("NEO4J_USER", "neo4j")

	dirname = sys.argv[1]

	driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

	with driver.session() as session:
		raw_report_file = dirname.split("/")

		report_file = raw_report_file[-1]

		report_data = json.loads(read_file(dirname +  report_file + ".json"))

		tx = session.begin_transaction()

		for service_name in report_data.keys():
			service_data = report_data[service_name]
			service_locations = {}
			service_vulns = []

			if "locations" in service_data:
				service_locations = service_data["locations"]
			
			if "vulns" in service_data:
				service_vulns = service_data["vulns"]

			create_service(tx, service_name)

			for location in service_locations.keys():
				create_location(tx, location)

				for port in service_locations[location]:
					create_svc_location_edge(tx, service_name, location, port)

			for vuln in service_vulns:
				vuln_name = vuln["name"]
				vuln_type = vuln["type"]
				vuln_severity = vuln["severity"]

				create_vulnerability(tx, name=vuln_name, vuln_type=vuln_type)
				create_svc_vuln_edge(tx, service_name, vuln_name, vuln_severity)

		tx.commit()
		session.close()


if __name__ == '__main__':
	main()