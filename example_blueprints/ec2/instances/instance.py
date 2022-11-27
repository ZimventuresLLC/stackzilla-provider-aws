"""AWS EC2 instance resource."""
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair
from stackzilla.provider.aws.ec2.instance import AWSInstance
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup, AWSSecurityGroupRule, IPAddressRange
from stackzilla.resource import StackzillaResource
from stackzilla.host_services.users import HostUser
from stackzilla.host_services.groups import HostGroup

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

        self.on_create_done.attach(handler=self.restart_apache)

        self.name = 'my-demo-server'
        self.region = 'us-east-1'
        self.type = 't2.micro'
        self.security_groups = [AllowSSH]
        self.ssh_key = MyKey

        self.groups = [HostGroup(name='netadmins'), HostGroup(name='coolkids')]
        self.users = [HostUser(name='zim', password='zim', extra_groups='netadmins')]

        # Amazon Linux 2 AMI
        # self.ami = 'ami-0c4e4b4eb2e11d1d4'
        # self.ssh_username = 'ec2-user'
        # self.packages = ['httpd']

        # Centos 7
        #self.ami = 'ami-0df157613dfbb5b36'
        #self.ssh_username = 'centos'
        #self.packages = ['httpd']

        # Centos 8: NOT SUPPORTED
        # Need to enable Stream support
        # self.ami = 'ami-0c347b91d57528501'
        # self.ssh_username = 'centos'
        # self.packages = ['httpd']

        # Ubuntu 22.04
        #self.ami = 'ami-08c40ec9ead489470'
        #self.ssh_username = 'ubuntu'

        # RHEL 9
        # https://access.redhat.com/solutions/15356#us_east_1_rhel9
        #self.ami = 'ami-0c41531b8d18cc72b'
        #self.ssh_username = 'ec2-user'
        #self.packages = ['httpd']

        # Debian 11 (Bullseye)
        # https://wiki.debian.org/Cloud/AmazonEC2Image/Bullseye
        #self.ami = 'ami-0be49b0e69a32b6bb'
        #self.ssh_username = 'admin'
        #self.packages = ['apache2']

        # Fedora 37
        # https://alt.fedoraproject.org/en/cloud/
        # self.ami = 'ami-023fb534213ca41da'
        # self.ssh_username = 'fedora'
        # self.packages = ['httpd']

    def restart_apache(self, sender: StackzillaResource):

        print('restarting Apache')
        self.restart_service('httpd')
