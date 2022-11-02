"""Helper functions for dealing with AWS ARNs."""
import re
from typing import Optional
from dataclasses import dataclass

# This regular expression will decompose an ARN into its component parts
# pylint: disable=line-too-long
ARN_REGEX = r'^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountID>[^:\n]*):(?P<Ignore>(?P<ResourceType>[^:\/\n]*)[:\/])?(?P<Resource>.*)$'

@dataclass
class ARN:
    """Models all of the components found within an ARN."""

    partition: str
    service: str
    region: str
    account_id: str
    resource: str
    resource_type: Optional[str] = ''

    @staticmethod
    def from_str(value: str) -> 'ARN':
        """Convert an ARN string into an ARN dataclass."""
        match = re.match(ARN_REGEX, value)

        return ARN(partition=match['Partition'],
                   service=match['Service'],
                   region=match['Region'],
                   account_id=match['AccountID'],
                   resource_type=match['ResourceType'],
                   resource=match['Resource'])

    def to_str(self) -> str:
        """Export the ARN as a string."""
        return f'arn:{self.partition}:{self.service}:{self.region}:{self.account_id}:{self.resource_type}/{self.resource}'
