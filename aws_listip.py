import boto3


session = boto3.Session(region_name="us-east-1")
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

with open('shared/ips.txt', 'a') as f:
    f.writelines("%s\n" % ip for ip in ips)
