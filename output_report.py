import sys
import json
import urllib.request as urllib
import os
import xmltodict

results = {}
vulnerable_services = []
colors = {'High': 'FD6864', 'Medium': 'F8A102', 'Low': '34CDF9'}


def parse_vuln(app_name, vuln):
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
    if 'vulns'in results[app_name].keys():
        results[app_name]['vulns'].append({'name': vuln_name,
                                           'type': vuln_type,
                                           'severity': severity})
    else:
        results[app_name]['vulns'] = [{'name': vuln_name,
                                       'type': vuln_type,
                                       'severity': severity}]


def parse_script(ip_addr, port, app_name, script):
    if 'table' in script.keys():
        vulnerable_services.append(app_name)
        script_table = script['table']['table']
        if isinstance(script_table, list):
            for vuln in script_table:
                parse_vuln(app_name, vuln['elem'])
        else:
            parse_vuln(app_name, script_table['elem'])
    else:
        print('ERROR in script: {} at location: {} port: {} app: {}'.format(
            script['@output'], ip_addr, port, app_name))


def get_app_name(service):
    app_name = ''
    if '@product' in service.keys():
        app_name += service['@product'] + " "
        if '@version' in service.keys():
            app_name += service['@version'] + " "
    elif '@name' in service.keys():
        app_name += service['@name'] + " "

    if 'cpe' in service.keys():
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
                for script in scripts:
                    if script['@id'] == 'vulners':
                        parse_script(ip_addr, port, app_name, script)
            else:
                if scripts['@id'] == 'vulners':
                    parse_script(ip_addr, port, app_name, scripts)


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
            for port in ports:
                parse_port(ip_addr, port)
        else:
            parse_port(ip_addr, ports)


def parse_results(data):
    if 'host' not in data['nmaprun'].keys():
        return
    hosts = data['nmaprun']['host']

    if isinstance(hosts, list):
        for host in hosts:
            parse_host(host)
    else:
        parse_host(hosts)


def convert_severity(sev):
    if sev < 4:
        return 'Low'
    if sev < 7:
        return 'Medium'
    return 'High'


def get_description(vuln, vuln_type):
    if vuln_type == 'cve':
        year = vuln[4:8]
        section = vuln[9:-3] + 'xxx'
        url = "https://raw.githubusercontent.com/CVEProject/cvelist/master/" \
              "{}/{}/{}.json".format(year, section, vuln)
        cve_json = json.loads(urllib.urlopen(url).read().decode("utf-8"))
        return cve_json["description"]["description_data"][0]["value"]
    return ''


def create_latex(nmap_command, start_date):
    with open('./latex_header.tex') as head_f:
        write_buffer = head_f.read()

    output_file = sys.argv[2]
    ip_file = sys.argv[3]

    write_buffer += "Flan Scan ran a network vulnerability scan with the " \
                    + "following Nmap command on " \
                    + start_date \
                    + "UTC.\n\\begin{lstlisting}\n" \
                    + nmap_command \
                    + "\n\\end{lstlisting}\nTo find out what IPs were " \
                    + "scanned see the end of this report.\n"
    write_buffer += "\\section*{Services with Vulnerabilities}\n"
    if vulnerable_services:
        write_buffer += """\\begin{enumerate}[wide, labelwidth=!,
                        labelindent=0pt, label=\\textbf{\\large \\arabic{enumi}
                        \\large}]\n"""
        for service in vulnerable_services:
            write_buffer += '\\item \\textbf{\\large ' + service + ' \\large}'
            vulns = results[service]['vulns']
            locations = results[service]['locations']
            num_vulns = len(vulns)

            for _, vuln in enumerate(vulns):
                write_buffer += '\\begin{figure}[h!]\n'
                severity_name = convert_severity(vuln['severity'])
                write_buffer += (
                    '\\begin{tabular}{|p{16cm}|}\\rowcolor[HTML]{'
                    + colors[severity_name] +
                    '} \\begin{tabular}{@{}p{15cm}>{\\raggedleft'
                    '\\arraybackslash} p{0.5cm}@{}}\\textbf{'
                    + vuln['name'] + ' ' + severity_name + ' ('
                    + str(vuln['severity']) +
                    ')} & \\href{https://nvd.nist.gov/vuln/detail/'
                    + vuln['name'] + '}{\\large \\faicon{link}}'
                    '\\end{tabular}\\\\\n Summary:'
                    + get_description(vuln['name'], vuln['type']) +
                    '\\\\ \\hline \\end{tabular}  \\end{figure}\n')

            write_buffer += (
                '\\FloatBarrier\n\\textbf{The above ' + str(num_vulns) +
                ' vulnerabilities apply to these network locations:}\n'
                '\\begin{itemize}\n')
            for addr in locations.keys():
                write_buffer += '\\item {} Ports: {}\n'.format(
                    addr, locations[addr])
            write_buffer += '\\\\ \\\\ \n \\end{itemize}\n'
        write_buffer += '\\end{enumerate}\n'

    non_vuln_services = list(set(results.keys()) - set(vulnerable_services))
    write_buffer += '\\section*{Services With No Known Vulnerabilities}\n'

    if non_vuln_services:
        write_buffer += (
            '\\begin{enumerate}[wide, labelwidth=!, labelindent=0pt,'
            'label=\\textbf{\\large \\arabic{enumi} \\large}]\n')
        for n_service in non_vuln_services:
            write_buffer += '\\item \\textbf{\\large ' + n_service \
                            + ' \\large}\n\\begin{itemize}\n'
            locations = results[n_service]['locations']
            for addr in locations.keys():
                write_buffer += '\\item {} Ports: {}\n'.format(
                    addr, locations[addr])
            write_buffer += '\\end{itemize}\n'
        write_buffer += '\\end{enumerate}\n'

    write_buffer += '\\section*{List of IPs Scanned}'
    write_buffer += '\\begin{itemize}\n'
    with open(ip_file) as ip_f:
        for line in ip_f:
            write_buffer += '\\item ' + line + '\n'
    write_buffer += '\\end{itemize}\n'

    write_buffer += '\\end{document}'
    with open(output_file, "w+") as latex_file:
        latex_file.write(write_buffer)


def parse_nmap_command(raw_command):
    nmap_split = raw_command.split()[:-1]  # remove last element, ip address
    nmap_split[3] = "<output-file>"
    return " ".join(nmap_split)


def main():
    dirname = sys.argv[1]
    nmap_command = ""
    start_date = ""

    for loop_id, filename in enumerate(os.listdir(dirname)):
        with open(dirname + "/" + filename) as xml_f:
            xml_content = xml_f.read()
        data = xmltodict.parse(xml_content)
        parse_results(data)
        if loop_id == 0:
            nmap_command = parse_nmap_command(data['nmaprun']['@args'])
            start_date = data['nmaprun']['@startstr']

    create_latex(nmap_command, start_date)


if __name__ == "__main__":
    main()
