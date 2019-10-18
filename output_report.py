import json
import xmltodict
import sys
import os
from datetime import datetime
from ares import CVESearch

colors = {'high': 'FD6864', 'medium': 'F8A102', 'low': '34CDF9'}

def get_summary(cve):
    cveDB = CVESearch()
    json = cveDB.id(cve)
    return json['summary']

def table(cve_elem):
    type = ''
    cvss = ''
    id = ''
    severity = ''
    for e in cve_elem:
        if e['@key'] == 'cvss':
            cvss = float(e['#text'])
        elif e['@key'] == 'id':
            id = e['#text']
        elif e['@key'] == 'type':
            type = e['#text']
    if type != 'cve': 
        return {"write_buffer": ''}

    write_buffer = '\\begin{figure}[h!]\n\\begin{tabular}{|p{15cm}|}\\rowcolor[HTML]{'
    if cvss < 4:
        severity = 'low'
        write_buffer += colors['low']
    elif cvss < 7:
        severity = 'medium'
        write_buffer += colors['medium']
    else:
        severity = 'high'
        write_buffer += colors['high']
    write_buffer += '}\n\\begin{tabular}[c]{@{}l@{}}\n'
    if cvss < 4:
        write_buffer += 'Low (CVSS: '
    elif cvss < 7:
        write_buffer += 'Medium (CVSS: '
    else:
        write_buffer += 'High (CVSS: '
    write_buffer += str(cvss) + ') \\\\ ' + id  + '\end{tabular} \\\\ \hline\nSummary: '
    write_buffer += get_summary(id) + '\\\\ \hline\n'
    write_buffer += 'Reference: https://vulners.com/cve/' + id 
    write_buffer += ' \\\\ \hline\n\end{tabular}\n\end{figure}\n'
    return {"write_buffer": write_buffer, "severity": severity} 

def create_table(s):
    write_buffer = ''
    low = 0
    medium = 0
    high = 0
    script_table = s['table']['table']
    if isinstance(script_table, list):
	for t in script_table:
	     table_obj = table(t['elem'])
             if table_obj['write_buffer'] != '':
		     write_buffer += table_obj['write_buffer']
		     if table_obj['severity'] == 'low':
			 low += 1
		     elif table_obj['severity'] == 'medium':
			 medium += 1
		     elif table_obj['severity'] == 'high':
			 high += 1
    else:
     table_obj = table(script_table['elem'])
     if table_obj['write_buffer'] != '':
	     write_buffer += table_obj['write_buffer']
	     if table_obj['severity'] == 'low':
		 low += 1
	     elif table_obj['severity'] == 'medium':
		 medium += 1
	     elif table_obj['severity'] == 'high':
		 high += 1
    return {"write_buffer": write_buffer, "low": low, "high": high, "medium": medium}

def port_and_service(p):
        result = {"low": 0, "medium": 0, "high": 0}
        write_buffer = ''
        if p['state']['@state'] == 'closed':
            result["str"] = write_buffer
            return result
        write_buffer += subsection('Port', p['@portid'])
        write_buffer += bold_text('State', p['state']['@state'])
	if('cpe' in p['service'].keys()):
            if isinstance(p['service']['cpe'], list):
                for cpe in p['service']['cpe']:
                    write_buffer += bold_text('CPE', '\\texttt{' + cpe + '}')
            else:
                write_buffer += bold_text('CPE', '\\texttt{' + p['service']['cpe'] + '}')
	if '@product' in p['service'].keys():
            write_buffer += bold_text('Product', p['service']['@product'])
	    if '@version' in p['service'].keys():
                write_buffer += bold_text('Version', p['service']['@version'])
	elif '@name' in p['service'].keys():
            write_buffer += bold_text('Service', p['service']['@name'])

        if 'script' in p.keys():
            if isinstance(p['script'], list):
                for s in p['script']:
                    if s['@id'] == 'vulners':
                        table_obj = create_table(s)
                        result["low"] += table_obj["low"]  
                        result["medium"] += table_obj["medium"]  
                        result["high"] += table_obj["high"]  
                        write_buffer += table_obj["write_buffer"]
            else:
                s = p['script']
                if s['@id'] == 'vulners':
                        table_obj = create_table(s)
                        result["low"] += table_obj["low"]  
                        result["medium"] += table_obj["medium"]  
                        result["high"] += table_obj["high"]  
                        write_buffer += table_obj["write_buffer"]
        result["str"] =  write_buffer
	return result

def bold_text(title, value):
    return '\\textbf{' + title + ': }' + value + '\\\\\n'

def subsection(title, value):
    return '\subsection{' + title + ' ' + value + '}\n'


def parse_host(h):
        result = {"write_buffer": '', "high": 0, "medium": 0, "low":0}
        str_buffer = ''
        if h['status']['@state'] == 'up' and 'port' in h['ports'].keys():
            if isinstance(h['ports']['port'], list):
	        for p in h['ports']['port']:
                    port_obj= port_and_service(p)    
                    str_buffer += port_obj['str']
                    result["low"] += port_obj["low"]
                    result["medium"] += port_obj["medium"]
                    result["high"] += port_obj["high"]
            else:
                    p = h['ports']['port']
                    port_obj= port_and_service(p)    
                    str_buffer += port_obj['str']
                    result["low"] += port_obj["low"]
                    result["medium"] += port_obj["medium"]
                    result["high"] += port_obj["high"]
            if str_buffer != '':
               str_buffer = '\section{' + h['address']['@addr'] + '}\n' + bold_text('Start Time', str(datetime.fromtimestamp(int(h['@starttime']))) + ' UTC') + bold_text('End Time', str(datetime.fromtimestamp(int(h['@endtime']))) + ' UTC') + str_buffer
        result['write_buffer'] = str_buffer
        return result

def write_ip_list(ip_file):
    write_buffer = "\\begin{enumerate}\n"
    f = open(ip_file)
    for line in f:
        write_buffer += "\item " + line + "\n"
    f.close()
    write_buffer += "\end{enumerate}"
    return write_buffer

def add_to_summary_table(h, port_obj, total_vulns):
   total_vulns['high'] += port_obj['high']
   total_vulns['medium'] += port_obj['medium']
   total_vulns['low'] += port_obj['low']
   return  h['address']['@addr'] + " & " + str(port_obj['high']) + " & " + str(port_obj['medium']) + " & " + str(port_obj['low']) + '\\\\ \hline\n'  

def main():
    dirname = sys.argv[1]
    output_file = sys.argv[2]
    ip_file = sys.argv[3]

    f = open('./latex_header.tex')
    write_buffer = f.read()
    f.close()

    write_buffer += write_ip_list(ip_file)
    total_vulns = {"high": 0, "medium": 0, "low": 0}

    summary_table = "\section{Results Summary}\n\\begin{longtable}{|l|l|l|l|}\n\hline \nHost & High & Medium & Low \\\\ \hline\n"
    doc_buffer = ''
    for filename in os.listdir(dirname):
        f= open(dirname + "/" + filename)
        xml_content = f.read()
        f.close()
        dicti = xmltodict.parse(xml_content)

        port_obj = {}
        if isinstance(dicti['nmaprun']['host'], list):
            for h in dicti['nmaprun']['host']:
                port_obj = parse_host(h)
                if port_obj['write_buffer'] != '':
                     summary_table += add_to_summary_table(h, port_obj, total_vulns)
                     doc_buffer += port_obj['write_buffer']
        else:
            h = dicti['nmaprun']['host']
            port_obj = parse_host(h)
            if port_obj['write_buffer'] != '':
                summary_table += add_to_summary_table(h, port_obj, total_vulns)
                doc_buffer += port_obj['write_buffer']

    write_buffer += summary_table + '\end{longtable}\n\n' 
    write_buffer += doc_buffer
    write_buffer += '\end{document}'
    print("WRITING to vuln_metrics" + str(total_vulns))
    metrics_file = open("/vuln_metrics.txt", "w+")
    metrics_file.write(str(total_vulns))
    latex_file = open(output_file, "w+")
    latex_file.write(write_buffer)
    latex_file.close()


if __name__ == "__main__":
    main()
