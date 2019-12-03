import sys
import json
import urllib.request as urllib
import os
import xmltodict

results = {}
vulnerable_services = []
colors = {'High': 'FD6864', 'Medium': 'F8A102', 'Low': '34CDF9'}


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


def convert_severity(sev):
    if sev < 4:
        return 'Low'
    elif sev < 7:
        return 'Medium'
    else:
        return 'High'


def get_description(vuln, type):
    if type == 'cve':
        year = vuln[4:8]
        section = vuln[9:-3] + 'xxx'
        url = """https://raw.githubusercontent.com/CVEProject/cvelist/master/{}/{}/{}.json""".format(year, section, vuln)
        cve_json = json.loads(urllib.urlopen(url).read().decode("utf-8"))
        return cve_json["description"]["description_data"][0]["value"]
    else:
        return ''


def create_latex(nmap_command, start_date):
    f = open('./latex_header.tex')
    write_buffer = f.read()
    f.close()

    output_file = sys.argv[2]
    ip_file = sys.argv[3]

    write_buffer += "Flan Scan ran a network vulnerability scan with the following Nmap command on " \
                 + start_date \
                 + "UTC.\n\\begin{lstlisting}\n" \
                 + nmap_command \
                 + "\n\end{lstlisting}\nTo find out what IPs were scanned see the end of this report.\n"
    write_buffer += "\section*{Services with Vulnerabilities}"
    if vulnerable_services:
        write_buffer += """\\begin{enumerate}[wide, labelwidth=!, labelindent=0pt,
                        label=\\textbf{\large \\arabic{enumi} \large}]\n"""
        for s in vulnerable_services:
            write_buffer += '\item \\textbf{\large ' + s + ' \large}'
            vulns = results[s]['vulns']
            locations = results[s]['locations']
            num_vulns = len(vulns)

            for i, v in enumerate(vulns):
                write_buffer += '\\begin{figure}[h!]\n'
                severity_name = convert_severity(v['severity'])
                write_buffer += '\\begin{tabular}{|p{16cm}|}\\rowcolor[HTML]{' \
                         + colors[severity_name] \
                         + """} \\begin{tabular}{@{}p{15cm}>{\\raggedleft\\arraybackslash}
                           p{0.5cm}@{}}\\textbf{""" \
                         + v['name'] + ' ' + severity_name + ' (' \
                         + str(v['severity']) \
                         + ')} & \href{https://nvd.nist.gov/vuln/detail/' \
                         + v['name'] + '}{\large \\faicon{link}}' \
                         + '\end{tabular}\\\\\n Summary:' \
                         + get_description(v['name'], v['type']) \
                         + '\\\\ \hline \end{tabular}  '
                write_buffer += '\end{figure}\n'

            write_buffer += '\FloatBarrier\n\\textbf{The above ' \
                         + str(num_vulns) \
                         + """ vulnerabilities apply to these network locations:}\n
                         \\begin{itemize}\n"""
            for addr in locations.keys():
                write_buffer += '\item ' + addr + ' Ports: ' + str(locations[addr])+ '\n'
            write_buffer += '\\\\ \\\\ \n \end{itemize}\n'
        write_buffer += '\end{enumerate}\n'

    non_vuln_services = list(set(results.keys()) - set(vulnerable_services))
    write_buffer += '\section*{Services With No Known Vulnerabilities}'

    if non_vuln_services:
        write_buffer += """\\begin{enumerate}[wide, labelwidth=!, labelindent=0pt,
        label=\\textbf{\large \\arabic{enumi} \large}]\n"""
        for ns in non_vuln_services:
            write_buffer += '\item \\textbf{\large ' + ns \
                            + ' \large}\n\\begin{itemize}\n'
            locations = results[ns]['locations']
            for addr in locations.keys():
                write_buffer += '\item ' + addr + ' Ports: ' + str(locations[addr])+ '\n'
            write_buffer += '\end{itemize}\n'
        write_buffer += '\end{enumerate}\n'

    write_buffer += '\section*{List of IPs Scanned}'
    write_buffer += '\\begin{itemize}\n'
    f = open(ip_file)
    for line in f:
        write_buffer += '\item ' + line + '\n'
    f.close()
    write_buffer += '\end{itemize}\n'

    write_buffer += '\end{document}'
    latex_file = open(output_file, "w+")
    latex_file.write(write_buffer)
    latex_file.close()

def parse_nmap_command(raw_command):
    nmap_split = raw_command.split()[:-1] #remove last element, ip address
    nmap_split[3] = "<output-file>"
    return " ".join(nmap_split)

def main():
    dirname = sys.argv[1]
    nmap_command = ""
    start_date = ""

    for i, filename in enumerate(os.listdir(dirname)):
        f = open(dirname + "/" + filename)
        xml_content = f.read()
        f.close()
        data = xmltodict.parse(xml_content)
        parse_results(data)
        if i == 0:
            nmap_command = parse_nmap_command(data['nmaprun']['@args'])
            start_date = data['nmaprun']['@startstr']

    create_latex(nmap_command, start_date)


if __name__ == "__main__":
    main()
