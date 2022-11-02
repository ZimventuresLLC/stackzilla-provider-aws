"""AWS Key Pair resource."""
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair

class MyKey(AWSKeyPair):
    """Definition of an AWS Key Pair."""

    def __init__(self):
        """Define attributes of the Key Pair"""
        super().__init__()
        self.name = 'zim-key'
        self.tags = {'project': 'stackzilla-provider-aws'}
        self.region = 'us-east-1'
