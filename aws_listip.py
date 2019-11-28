import boto3


ec2 = boto3.resource('ec2')

running_instances = ec2.instances.filter(Filters=[{
    'Name': 'instance-state-name',
    'Values': ['running']}])

ips = []
for instance in running_instances:
    if instance.public_ip_address:
        ips.append(instance.public_ip_address)
    else:
        ips.append(instance.private_ip_address)

with open('shared/ips.txt', 'a') as f:
    f.writelines("%s\n" % ip for ip in ips)
