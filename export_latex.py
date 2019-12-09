import os
import sys
import json
import xmltodict
import urllib.request as urllib

from os import path

def read_file(filename):
    f = open(filename)
    content = f.read()
    f.close()

    return content

def parse_nmap_command(raw_command):
    nmap_split = raw_command.split()[:-1] #remove last element, ip address
    nmap_split[3] = "<output-file>"
    return " ".join(nmap_split)

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

def create_latex(results, vulnerable_services, colors, nmap_command, start_date):
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

def main():
    dirname = sys.argv[1]
    nmap_command = ""
    start_date = ""
    results = {}
    vulnerable_services = []
    colors = {'High': 'FD6864', 'Medium': 'F8A102', 'Low': '34CDF9'}

    for i, filename in enumerate(os.listdir(dirname)):
        if path.splitext(filename)[1] == ".xml":
            xml_content = read_file(dirname + "/" + filename)

            report_filename = dirname.split("/")[-1]

            report_content = read_file(dirname + report_filename  + ".json")

            vuln_svc_content = read_file(dirname + report_filename + ".services" + ".json")

            results = json.loads(report_content)

            vulnerable_services = json.loads(vuln_svc_content)

            data = xmltodict.parse(xml_content)

            if i == 0:
                nmap_command = parse_nmap_command(data['nmaprun']['@args'])
                start_date = data['nmaprun']['@startstr']

        create_latex(results, vulnerable_services, colors, nmap_command, start_date)


if __name__ == "__main__":
    main()