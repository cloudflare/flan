import boto3
import googleapiclient.discovery
import os

def aws_list_ip():
    region_name = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    session = boto3.Session(region_name=region_name)
    client = session.client('ec2')
    regions = client.describe_regions()

    ips = []

    for region in regions['Regions']:
        session = boto3.Session(region_name=region['RegionName'])
        ec2 = session.resource('ec2')
        running_instances = ec2.instances.filter(Filters=[{
                'Name': 'instance-state-name',
                'Values': ['running']}])

        for instance in running_instances:
            if instance.public_ip_address:
                ips.append(instance.public_ip_address)
            else:
                ips.append(instance.private_ip_address)
    return ips

def gcp_list_ip():
    project_id = os.getenv("PROJECT_ID")

    client = googleapiclient.discovery.build('compute', 'v1')

    compute = client.instances()
    zones = client.zones().list(project=project_id).execute()

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
    return ips

def write_file(ip_list):
    with open('shared/ips.txt', 'a') as f:
        f.writelines("%s\n" % ip for ip in ip_list)


if __name__ == "__main__":
    request = os.getenv("generate_ips")
    if "aws" in request:
        write_file(aws_list_ip())

    if "gcp" in request:
        write_file(gcp_list_ip())
