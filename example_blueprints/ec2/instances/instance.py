"""AWS EC2 instance resource."""
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair
from stackzilla.provider.aws.ec2.instance import AWSInstance
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup, AWSSecurityGroupRule, IPAddressRange

class MyKey(AWSKeyPair):
    """Definition of an AWS Key Pair."""

    def __init__(self):
        """Define attributes of the Key Pair"""
        super().__init__()
        self.name = 'zim-key'
        self.tags = {'project': 'stackzilla-provider-aws'}
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

class AllowHTTPS(AWSSecurityGroup):
    """A security group that allows incoming HTTP connections."""

    def __init__(self):
        """Define all of the security group attributes here."""
        super().__init__()

        self.ingress = [
            AWSSecurityGroupRule(cidr_blocks=[IPAddressRange('0.0.0.0/0', 'the whole wide world')],
                                 protocol='tcp', from_port=80, to_port=80)
        ]
        self.name = 'InboundHTTPS'
        self.description = 'Allows incoming HTTP connections to port 80'
        self.region = 'us-east-1'

class MyServer(AWSInstance):
    """EC2 Instance."""

    def __init__(self):
        """Define the server attributes."""
        super().__init__()

        self.name = 'zim-server'
        self.region = 'us-east-1'
        self.type = 't2.micro'
        self.security_groups = [AllowSSH, AllowHTTPS]
        self.ssh_key = MyKey
        self.ami = 'ami-0c4e4b4eb2e11d1d4'  # Amazon Linux 2 AMI
        self.ssh_username = 'ec2-user'
