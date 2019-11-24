import boto3, sys, os
from botocore.exceptions import ClientError
from bcolors import bcolors
import time

#KEY PAIR
def keyPair(ec2Client, keyName):
    ec2 = ec2Client
    response = ec2.describe_key_pairs()

    for i in response["KeyPairs"]:
        if i["KeyName"] == keyName:
            print('\nDeletando Key Pair %s' % (keyName))
            ec2.delete_key_pair(KeyName=keyName)

    print('\nCriando Key Pair nova %s\n' % keyName)
    keypair = ec2.create_key_pair(KeyName=keyName)

    print('\nCriada com ' + bcolors.OKGREEN + 'sucesso' + bcolors.ENDC)

    keyName = "%s.pem" % keyName
    try:
        os.chmod(keyName, 0o777)
    except:
        pass


    with open(keyName, "w") as text_file:
        text_file.write(keypair['KeyMaterial'])

    os.chmod(keyName, 0o400)

#SECURITY GROUPS
def securityGroups(ec2Client, securityGroupName, keyName):
    ec2 = ec2Client

    print('\nProcurando VPC...')
    responseVPC = ec2.describe_vpcs()
    VPC_id = responseVPC['Vpcs'][0]['VpcId']

    if securityGroupName == 'vitorsv1-Projeto-secgroup-mongo':
        security_group_id = securityGroups_create_mongo(ec2,securityGroupName, VPC_id)
    else:
        security_group_id = securityGroups_create_webserver(ec2,securityGroupName, VPC_id)   
    return security_group_id

def securityGroups_create_mongo(ec2Client, securityGroupName, VPC_id):
    ec2 = ec2Client

    try:
        response = ec2.create_security_group(GroupName=securityGroupName,
                                             Description="vitorsv1 Projeto",
                                             VpcId = VPC_id)
        security_group_id = response['GroupId']
        print('\nSecurity Group' + bcolors.OKGREEN + ' criado' + bcolors.ENDC +  ' %s' % (security_group_id))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol' : 'tcp',
                    'FromPort' : 22,
                    'ToPort' : 22,
                    'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                },
                {
                    'IpProtocol' : 'tcp',
                    'FromPort' : 27017,
                    'ToPort' : 27017,
                    'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}] #ESPECIFICAR O IP ELASTICO DO WEBSERVER
                }
            ]
        )

        return security_group_id

    except ClientError as e:
        print(e)

def securityGroups_create_webserver(ec2Client, securityGroupName, VPC_id):
    ec2 = ec2Client

    try:
        response = ec2.create_security_group(GroupName=securityGroupName,
                                             Description="vitorsv1 Projeto",
                                             VpcId = VPC_id)
        security_group_id = response['GroupId']
        print('\nSecurity Group' + bcolors.OKGREEN + ' criado' + bcolors.ENDC +  ' %s' % (security_group_id))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol' : 'tcp',
                    'FromPort' : 22,
                    'ToPort' : 22,
                    'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                },
                {
                    'IpProtocol' : 'tcp',
                    'FromPort' : 8000,
                    'ToPort' : 8000,
                    'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                }
            ]
        )

        return security_group_id

    except ClientError as e:
        print(e)

def securityGroup_delete(ec2, securityGroupName, keyName):
    securityGroupId = ''
    try:
        s = ec2.describe_security_groups(GroupNames=[securityGroupName])
        for i in s['SecurityGroups']:
            securityGroupId = i['GroupId']
    except ClientError as e:
        print(e)
    
    try:
        instances_kill(ec2,keyName)    
        try:
            responseD = ec2.delete_security_group(GroupId=securityGroupId)
            print('\nSecurity group %s deletado' % (securityGroupId))
        except ClientError as e:
            print(e)
    except ClientError as e:
        print(e)

# INSTANCES
def instances(ec2Resource, ec2Client, keyName, securityGroupId, securityGroupName, ubuntu18):
    ec2 = ec2Resource
    ec2Cliente = ec2Client
    
    ip = 0
    ip_webserver = 0

    instances_kill(ec2Cliente["North-Virginia"],keyName["North-Virginia"])
    instances_kill(ec2Cliente["Ohio"],keyName["Ohio"])

    userdata_mongo = """
    #cloud-config
        runcmd:
        - sudo apt update -y
        - sudo apt-get install gnupg
        - wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
        - echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
        - sudo apt-get update -y
        - sudo apt-get install -y mongodb-org
        - echo "mongodb-org hold" | sudo dpkg --set-selections
        - echo "mongodb-org-server hold" | sudo dpkg --set-selections
        - echo "mongodb-org-shell hold" | sudo dpkg --set-selections
        - echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
        - echo "mongodb-org-tools hold" | sudo dpkg --set-selections
        - sudo service mongod start,
        - sudo sed -i "s/127.0.0.1/0.0.0.0/g" /etc/mongod.conf
        - sudo service mongod restart
    """    
    
    # Mongo Instance
    i1 = instance_create(ec2["Ohio"], ec2Cliente["Ohio"], ubuntu18["Ohio"], securityGroupId["Mongo"], securityGroupName["Mongo"], keyName["Ohio"], userdata_mongo)    
    
    print('\nEsperando para instancia ficar ok...')

    waiter = ec2Cliente["Ohio"].get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[i1.id])

    i1.load()

    print('\nInstancia esta '+ bcolors.OKGREEN +'OK!' + bcolors.ENDC)

    r = ec2Cliente["Ohio"].describe_instances()
    
    for i in r['Reservations']:
        for j in i['Instances']:
            for k in j['SecurityGroups']:
                if k['GroupName'] == securityGroupName['Mongo']:
                    ip = j['PrivateIpAddress']


    userdata_webserver = """
    #cloud-config
    runcmd:
     - sudo apt-get update -y
     - sudo apt install python3-pip --yes
     - sudo pip3 install fastapi
     - sudo pip3 install pymongo
     - sudo pip3 install uvicorn 
     - export mongoIP=%s
     - git clone https://github.com/vitorsv1/Hybrid-Cloud.git
     - cd Hybrid-Cloud
     - uvicorn webserver-ohio:app --reload --host 0.0.0.0
    """ % (ip)

    # WebServer de Ohio
    i2 = instance_create(ec2["Ohio"], ec2Cliente["Ohio"], ubuntu18["Ohio"], securityGroupId["WebServer-OH"], securityGroupName["WebServer"], keyName["Ohio"], userdata_webserver)

    print('\nEsperando para instancia ficar ok...')

    waiter = ec2Cliente["Ohio"].get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[i2.id])

    i2.load()

    print('\nInstancia esta '+ bcolors.OKGREEN +'OK!' + bcolors.ENDC)

    r = ec2Cliente["Ohio"].describe_instances()
    
    for i in r['Reservations']:
        for j in i['Instances']:
            for k in j['SecurityGroups']:
                if k['GroupName'] == securityGroupName['WebServer']:
                    ip_webserver = j['PublicIpAddress']

    # WebServer de North-Virginia
    userdata_webserver_nv = """
    #cloud-config
    runcmd:
     - sudo apt-get update -y
     - sudo apt install python3-pip --yes
     - sudo pip3 install fastapi
     - sudo pip3 install pymongo
     - sudo pip3 install email-validator
     - sudo pip3 install uvicorn 
     - export webserverIP=%s
     - git clone https://github.com/vitorsv1/Hybrid-Cloud.git
     - cd Hybrid-Cloud
     - uvicorn webserver:app --reload --host 0.0.0.0 & curl 127.0.0.1:8000
    """ % (ip_webserver)
                
    i3 = instance_create(ec2["North-Virginia"], ec2Cliente["North-Virginia"],ubuntu18["North-Virginia"] ,securityGroupId["WebServer-NV"], securityGroupName["WebServer"], keyName["North-Virginia"], userdata_webserver_nv)

    print('\nEsperando para instancias ficarem ok...')

    waiter = ec2Cliente["North-Virginia"].get_waiter('instance_status_ok')
    waiter.wait(InstanceIds=[i3.id])

    i3.load()

    print('\nInstancia esta '+ bcolors.OKGREEN +'OK!' + bcolors.ENDC)

    r = ec2Cliente["North-Virginia"].describe_instances()
    
    for i in r['Reservations']:
        for j in i['Instances']:
            for k in j['SecurityGroups']:
                if k['GroupName'] == securityGroupName['WebServer']:
                    ip_webserver_nv = j['PublicIpAddress']


    print("\nPublic dns da instancia Mongo %s é %s\nIp privado %s " %(i1.id, i1.public_dns_name, ip))
    print("\nPublic dns da instancia WebServer-OH %s é %s\nIp publico %s " %(i2.id, i2.public_dns_name, ip_webserver))
    print("\nPublic dns da instancia WebServer-NV %s é %s\nIp publico %s" %(i3.id, i3.public_dns_name, ip_webserver_nv))

    return ip_webserver_nv

def instance_create(ec2, ec2Cliente, ubuntu18, securityGroupId, securityGroupName, keyName, userdata):
    print('\nCriando instancias')
    
    if userdata is None:
        response = ec2.create_instances(ImageId=ubuntu18,
                                    MinCount=1,
                                    MaxCount=1,
                                    InstanceType='t2.micro',
                                    SecurityGroupIds=[securityGroupId],
                                    SecurityGroups=[securityGroupName],
                                    KeyName=keyName,
                                    TagSpecifications=[{
                                            'ResourceType' : 'instance',
                                            'Tags' : [
                                                {
                                                    'Key' : 'Name',
                                                    'Value' : keyName,
                                                },
                                                {
                                                    'Key' : 'Owner',
                                                    'Value' : 'vitorsv1'
                                                }
                                            ]
                                    }]
                                    )
    else:
        response = ec2.create_instances(ImageId=ubuntu18,
                                        MinCount=1,
                                        MaxCount=1,
                                        InstanceType='t2.micro',
                                        SecurityGroupIds=[securityGroupId],
                                        SecurityGroups=[securityGroupName],
                                        KeyName=keyName,
                                        TagSpecifications=[{
                                                'ResourceType' : 'instance',
                                                'Tags' : [
                                                    {
                                                        'Key' : 'Name',
                                                        'Value' : keyName,
                                                    },
                                                    {
                                                        'Key' : 'Owner',
                                                        'Value' : 'vitorsv1'
                                                    }
                                                ]
                                        }],
                                        UserData=userdata
                                        )

    print('\nInstancia criada com id %s' % response[0].id)

    return response[0]

def instances_kill(ec2Client, key):
    ec2 = ec2Client

    numberInstances = 0
    r = ec2.describe_tags()
    for i in r['Tags']:
        if i['Key'] == 'Name' and i['Value'] == key:
            numberInstances += 1

    response = ec2.describe_instances(Filters=[
        {
            'Name': 'tag:Name',
            'Values': [
                key,
            ]
        },
    ])
    instanceId = []
    for i in response['Reservations']:
        for j in i['Instances']:
            instanceId.append(j['InstanceId'])
            

    print('\nMatando instancias %s' % instanceId)
    if instanceId:
        ec2.terminate_instances(InstanceIds=instanceId)
        print('\nEsperando instancias terminar')

        waiter = ec2.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=instanceId)

# TARGET GROUPS
def target_group_create(elbv2Cliente, ec2Cliente, targetGroupName):
    print('\nCriando Target Group...')
    responseVPC = ec2Cliente.describe_vpcs()
    VPC_id = responseVPC['Vpcs'][0]['VpcId']
    
    r = elbv2Cliente.create_target_group(
        Name = targetGroupName,
        Protocol = 'HTTP',
        Port = 8000,
        VpcId = VPC_id,
        HealthCheckProtocol = 'HTTP',
        HealthCheckPath = '/healthcheck',
        TargetType='instance'
    )

    response = elbv2Cliente.describe_target_groups(
        Names=[
            targetGroupName,
        ]
    )

    responseARN = response["TargetGroups"][0]["TargetGroupArn"]

    return responseARN

def target_group_delete(elbv2Cliente, ec2Cliente, targetGroupName):
    print('\nDeletando Target Group...')
    try:
        response = elbv2Cliente.describe_target_groups(
            Names=[
                targetGroupName,
            ]
        )

        responseARN = response["TargetGroups"][0]["TargetGroupArn"]

        try:
            res = elbv2Cliente.delete_target_group(TargetGroupArn = responseARN)
            print('\nTarget Group deletado\n')
        except ClientError as e:
            print(e)        
    except ClientError as e:
        print(e)

def load_balancer_create(elbv2Client_nv, loadbalancerName, securityGroupId):
    print('\nCriando Load Balancer...')

    r = elbv2Client_nv.create_load_balancer(
        Name = loadbalancerName,
        Subnets=['subnet-1c813340',
        'subnet-4999d803',
        'subnet-540e795b',
        'subnet-5ddb6b3a',
        'subnet-91a463af',
        'subnet-d164d8ff'
        ],
        SecurityGroups=[
            securityGroupId,
        ],
        Scheme='internet-facing',
        Tags=[
            {
                'Key': 'Owner',
                'Value': 'vitorsv1'
            },
        ],
        Type='application',
        IpAddressType='ipv4'
    )

    lbArn = r['LoadBalancers'][0]['LoadBalancerArn']

    waiter = elbv2Client_nv.get_waiter('load_balancer_exists')
    waiter.wait(LoadBalancerArns=[lbArn])
    time.sleep(15)

    r = elbv2Client_nv.describe_load_balancers()

    for i in r['LoadBalancers']:
        if i['LoadBalancerName'] == 'LoadBalancer-vitorsv1':
            print('\nLoadBalancer esta no endereço %s:8000/docs' % (i['DNSName']))

    return lbArn

def load_balancer_delete(elbv2Cliente, ec2Cliente, loadBalancerName):
    print('\nDeletando Load Balancer...')
    try:
        response = elbv2Cliente.describe_load_balancers(
            Names=[loadBalancerName]
        )

        responseARN = response["LoadBalancers"][0]['LoadBalancerArn']
        try:
            print('\nLoad Balancer Deletando..')
            res = elbv2Cliente.delete_load_balancer(LoadBalancerArn = responseARN)
        
            waiterLoadBalancer=elbv2Cliente.get_waiter('load_balancers_deleted')
            waiterLoadBalancer.wait(LoadBalancerArns=[responseARN])

            time.sleep(20)

            print('\nLoad Balancer Deletado')
        except ClientError as e:
            print(e)        
    except ClientError as e:
        print(e)

# AUTO SCALING GROUP
def auto_scaling_group_create(autoScalingCliente, autoScalingName,launchName,targetGroupARN):
    print('\nCriando AutoScaling Group..')
    response = autoScalingCliente.create_auto_scaling_group(
    AutoScalingGroupName=autoScalingName,
    LaunchConfigurationName=launchName,
    MinSize=1,
    MaxSize=3,
    DesiredCapacity=1,
    DefaultCooldown=100,
    TargetGroupARNs=[
        targetGroupARN,
    ],
    AvailabilityZones=["us-east-1a",
    "us-east-1b",
    "us-east-1c",
    "us-east-1d",
    "us-east-1e",
    "us-east-1f"],
    HealthCheckGracePeriod=123)

def auto_scaling_group_delete(autoScalingCliente, autoScalingName, forceDelete = False):
    print('\nDeletando Auto Scaling Group...')
    
    wait = True
    try:
        response = autoScalingCliente.delete_auto_scaling_group(
            AutoScalingGroupName=autoScalingName,
            ForceDelete = forceDelete
        )

        print('\nEsperando deletar...')
        while wait:
            r = autoScalingCliente.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoScalingName]
            )

            a = len(r['AutoScalingGroups'])
            
            if a == 0:
                wait = False

            time.sleep(2)
        
        print('\nDeletado Auto Scaling Group')

    except ClientError as e:
        print(e)

# LAUNCH CONFIGURATION
def launch_configuration_create(autoscale,launchName,amiId,keyName,securityGroupID, ip):
    print('\nCriando Launch Configuration...')
    userdata_webserver = """
    #cloud-config
    runcmd:
     - sudo apt-get update -y
     - sudo apt install python3-pip --yes
     - sudo pip3 install fastapi
     - sudo pip3 install pymongo
     - sudo pip3 install email-validator
     - sudo pip3 install uvicorn 
     - export webserverIP=%s
     - git clone https://github.com/vitorsv1/Hybrid-Cloud.git
     - cd Hybrid-Cloud
     - uvicorn webserver:app --reload --host 0.0.0.0 & curl 127.0.0.1:8000
    """ % (ip)

    response = autoscale.create_launch_configuration(
    LaunchConfigurationName=launchName,
    ImageId=amiId,
    KeyName=keyName,
    SecurityGroups=[
        securityGroupID,
    ],
    InstanceType='t2.micro',
    InstanceMonitoring={
        'Enabled': True
    },
    UserData = userdata_webserver)

def launch_configuration_delete(autoscale,launchName):
    print('\nDeletando Launch Configuration...')
    try:
        response = autoscale.delete_launch_configuration(
            LaunchConfigurationName=launchName
        )
        print('\nDeletado Launch Configuration')
    except ClientError as e:
        print(e)

# LISTENER
def listener_create(elbv2Client, loadBalancerArn, targetGroupArn):
    print('\nCriando listener para LoadBalancer e TargetGroup')
    response = elbv2Client.create_listener(
            LoadBalancerArn = loadBalancerArn,
            Protocol='HTTP',
            Port=8000,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': targetGroupArn
                }
            ])

if __name__ == "__main__":

    key_nv = 'vitorsv1-Projeto-nv'
    key_o = 'vitorsv1-Projeto-o'
    secGroup = 'vitorsv1-Projeto-secgroup'
    secGroup_mongo = 'vitorsv1-Projeto-secgroup-mongo'
    loadBalancer = 'vitorsv1-Projeto-loadbalancer'
    targetGroup = 'vitorsv1-Projeto-targetgroup'
    launchName = 'vitorsv1-Projeto-launchconfiguration'
    autoScalingName = 'vitorsv1-Projeto-autoscaling'
    
    ec2Client_nv = boto3.client('ec2', region_name='us-east-1')
    ec2Client_o = boto3.client('ec2', region_name='us-east-2')

    elbv2Client_nv = boto3.client('elbv2')
    autoscaleClient = boto3.client('autoscaling')
    
    ec2Resource_nv = boto3.resource('ec2', region_name='us-east-1')
    ec2Resource_o = boto3.resource('ec2', region_name='us-east-2')
    
    ubuntu18_nv = 'ami-04b9e92b5572fa0d1'
    ubuntu18_ohio = 'ami-0d5d9d301c853a04a'

    keyPair(ec2Client_nv,key_nv)
    keyPair(ec2Client_o,key_o)

    auto_scaling_group_delete(autoscaleClient, autoScalingName, True)
    load_balancer_delete(elbv2Client_nv,ec2Client_nv, loadBalancer)
    target_group_delete(elbv2Client_nv, ec2Client_nv, targetGroup)
    launch_configuration_delete(autoscaleClient, launchName)
    securityGroup_delete(ec2Client_nv, secGroup, key_nv)
    securityGroup_delete(ec2Client_o, secGroup_mongo, key_o)
    securityGroup_delete(ec2Client_o, secGroup, key_o)

    security_group_id = securityGroups(ec2Client_nv,secGroup, key_nv)
    security_group_id_webserver = securityGroups(ec2Client_o,secGroup, key_o)
    security_group_id_mongo = securityGroups(ec2Client_o,secGroup_mongo, key_o)
    redirect_ip = instances(ec2Resource = {"North-Virginia":ec2Resource_nv, "Ohio": ec2Resource_o},
            ec2Client = {"North-Virginia":ec2Client_nv, "Ohio": ec2Client_o}, 
            keyName = {"North-Virginia": key_nv, "Ohio": key_o}, 
            securityGroupId = {"WebServer-NV": security_group_id, "WebServer-OH" : security_group_id_webserver, "Mongo": security_group_id_mongo}, 
            securityGroupName = {"WebServer" : secGroup, "Mongo": secGroup_mongo}, 
            ubuntu18 = {"North-Virginia" : ubuntu18_nv, "Ohio": ubuntu18_ohio})    
    target_group_arn = target_group_create(elbv2Client_nv, ec2Client_nv, targetGroup)
    load_balancer_arn = load_balancer_create(elbv2Client_nv,loadBalancer,security_group_id)
    launch_configuration_create(autoscaleClient, launchName, ubuntu18_nv, key_nv, security_group_id, redirect_ip)
    auto_scaling_group_create(autoscaleClient, autoScalingName,launchName,target_group_arn)  
    listener_create(elbv2Client_nv, load_balancer_arn, target_group_arn)


