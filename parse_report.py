import sys
import json
import os
import xmltodict
from os import path

results = {}
vulnerable_services = []


def parse_vuln(ip_addr, port, app_name, vuln):
    vuln_name = ''
    severity = ''
    type = ''
    for field in vuln:
        if field['@key'] == 'cvss':
            severity = float(field['#text'])
        elif field['@key'] == 'id':
            vuln_name = field['#text']
        elif field['@key'] == 'type':
            type = field['#text']
    if 'vulns'in results[app_name].keys():
        results[app_name]['vulns'].append({'name': vuln_name,
                                           'type': type,
                                           'severity': severity})
    else:
        results[app_name]['vulns'] = [{'name': vuln_name,
                                       'type': type,
                                       'severity': severity}]


def parse_script(ip_addr, port, app_name, script):
    if 'table' in script.keys():
        vulnerable_services.append(app_name)
        script_table = script['table']['table']
        if isinstance(script_table, list):
            for vuln in script_table:
                parse_vuln(ip_addr, port, app_name, vuln['elem'])
        else:
            parse_vuln(ip_addr, port, app_name, script_table['elem'])
    else:
        print('ERROR in script: ' + script['@output'] + " at location: " + ip_addr + " port: " + port + " app: " + app_name)


def get_app_name(service):
    app_name = ''
    if '@product' in service.keys():
        app_name += service['@product'] + " "
        if '@version' in service.keys():
            app_name += service['@version'] + " "
    elif '@name' in service.keys():
        app_name += service['@name'] + " "

    if('cpe' in service.keys()):
        if isinstance(service['cpe'], list):
            for cpe in service['cpe']:
                app_name += '(' + cpe + ") "
        else:
            app_name += '(' + service['cpe'] + ") "
    return app_name


def parse_port(ip_addr, port):
    if port['state']['@state'] == 'closed':
        return
    app_name = get_app_name(port['service'])

    port_num = port['@portid']

    if app_name in results.keys():
        if ip_addr in results[app_name]['locations'].keys():
            results[app_name]['locations'][ip_addr].append(port_num)
        else:
            results[app_name]['locations'][ip_addr] = [port_num]
    else:
        results[app_name] = {'locations': {ip_addr: [port_num]}}
        if 'script' in port.keys():
            scripts = port['script']
            if isinstance(scripts, list):
                for s in scripts:
                    if s['@id'] == 'vulners':
                        parse_script(ip_addr, port_num, app_name, s)
            else:
                if scripts['@id'] == 'vulners':
                    parse_script(ip_addr, port_num, app_name, scripts)


def parse_host(host):
    addresses = host['address']
    if isinstance(addresses, list):
        for addr in addresses:
            if "ip" in addr['@addrtype']:
                ip_addr = addr['@addr']
    else: 
        ip_addr = addresses['@addr']

    if host['status']['@state'] == 'up' and 'port' in host['ports'].keys():
        ports = host['ports']['port']
        if isinstance(ports, list):
            for p in ports:
                parse_port(ip_addr, p)
        else:
            parse_port(ip_addr, ports)


def parse_results(data):
    if 'host' in data['nmaprun'].keys(): 
        hosts = data['nmaprun']['host']

        if isinstance(hosts, list):
            for h in hosts:
                parse_host(h)
        else:
            parse_host(hosts)

def main():
    dirname = sys.argv[1]

    for i, filename in enumerate(os.listdir(dirname)):
        if path.splitext(filename)[1] == ".xml":
            f = open(dirname + "/" + filename)
            xml_content = f.read()
            f.close()
            data = xmltodict.parse(xml_content)

            parse_results(data)

    raw_report_file = dirname.split("/")

    report_file = raw_report_file[-2]

    vuln_svc_file = report_file + ".services"

    with open(dirname +  report_file + ".json", "w") as report_data:
        report_data.write(json.dumps(results))
        report_data.close()

    with open(dirname + vuln_svc_file  + ".json", "w") as svc_data:
        svc_data.write(json.dumps(vulnerable_services))
        svc_data.close()




if __name__ == "__main__":
    main()
