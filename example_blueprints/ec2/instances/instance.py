"""AWS EC2 instance resource."""
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair
from stackzilla.provider.aws.ec2.instance import AWSInstance
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup, AWSSecurityGroupRule, IPAddressRange
from stackzilla.host_services.users import HostUser

class MyKey(AWSKeyPair):
    """Definition of an AWS Key Pair."""

    def __init__(self):
        """Define attributes of the Key Pair"""
        super().__init__()
        self.name = 'my-ssh-key'
        self.region = 'us-east-1'

class AllowSSH(AWSSecurityGroup):
    """A security group that allows incoming SSH connections."""

    def __init__(self):
        """Define all of the security group attributes here."""
        super().__init__()

        self.ingress = [
            AWSSecurityGroupRule(cidr_blocks=[IPAddressRange('0.0.0.0/0', 'the whole wide world')],
                                 protocol='tcp', from_port=22, to_port=22)
        ]
        self.name = 'InboundSSH'
        self.description = 'Allows incoming TCP connections to port 22'
        self.region = 'us-east-1'

class MyServer(AWSInstance):
    """EC2 Instance."""

    def __init__(self):
        """Define the server attributes."""
        super().__init__()

        self.name = 'my-demo-server'
        self.region = 'us-east-1'
        self.type = 't2.micro'
        self.security_groups = [AllowSSH]
        self.ssh_key = MyKey
        #self.ami = 'ami-0c4e4b4eb2e11d1d4'  # Amazon Linux 2 AMI
        #self.ssh_username = 'ec2-user'
        #self.ami = 'ami-0df157613dfbb5b36' # Centos 7
        #self.ssh_username = 'centos'

        #self.ami = 'ami-08c40ec9ead489470' # Ubuntu 22.04
        #self.ssh_username = 'ubuntu'

        #self.ami = 'ami-0c347b91d57528501' # Centos 8


        self.users = [HostUser(name='zim', password='zim'), HostUser(name='rob', password='rob')]
