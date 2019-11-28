import googleapiclient.discovery
import os


project_id = os.getenv("PROJECT_ID")

client = googleapiclient.discovery.build('compute', 'v1')

compute = client.instances()
zones = client.zones().list(project_id).execute()

ips = []

for zone in zones['items']:
    result = compute.list(
            project=project_id,
            zone=zone['name'],
            filter="status=RUNNING").execute()

    if 'items' not in result:
        continue

    for vm in result['items']:
        if 'networkInterfaces' in vm:
            for network_interface in vm['networkInterfaces']:
                if 'accessConfigs' in network_interface:
                    ips.extend(
                        [x['natIP'] for x in network_interface['accessConfigs']
                        if x['type'] == 'ONE_TO_ONE_NAT']
                    )
                else:
                    ips.append(network_interface['networkIP'])

with open('shared/ips.txt', 'a') as f:
    f.writelines("%s\n" % ip for ip in ips)
