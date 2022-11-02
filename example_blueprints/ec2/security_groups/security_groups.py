"""Example Security Group defintion."""
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup, AWSSecurityGroupRule, IPAddressRange

class AllowAll(AWSSecurityGroup):
    """A security group that allows incoming SSH connections."""

    def __init__(self):
        """Define all of the security group attributes here."""
        super().__init__()

        self.ingress = [
            AWSSecurityGroupRule(cidr_blocks=[IPAddressRange('0.0.0.0/0', 'the whole wide world')],
                                 protocol='tcp', from_port=22, to_port=22),
        ]
        self.name = 'InboundSSH'
        self.description = 'Allows incoming TCP connections to port 22'
        self.region = 'us-east-1'
        #self.tags = {'test-tag': 'zim'}
