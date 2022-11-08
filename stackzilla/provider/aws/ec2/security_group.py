"""AWS Security Group resource definition for Stackzilla."""
from dataclasses import dataclass
from typing import Dict, List, Optional, Type, Union

import boto3
from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.provider.aws.utils.arn import ARN
from stackzilla.provider.aws.utils.regions import REGION_NAMES
from stackzilla.provider.aws.utils.tags import dict_to_boto_tags, update_tags
from stackzilla.resource.base import ResourceVersion, StackzillaResource

@dataclass
class IPAddressRange:
    """Simple model which defines a CIDR range."""

    cidr_block: str
    description: str

    def to_boto(self):
        """Convert to the dictionary format boto3 expects."""
        return {"CidrIp": self.cidr_block, "Description": self.description}

@dataclass
class AWSSecurityGroupRule:
    """A single security group rule."""

    # List of (optional) IPAddressRange blocks that the rule applies to
    cidr_blocks: Optional[List[IPAddressRange]] = None

    # The start of the protocol port range the rule applies to
    from_port: Optional[int] = None

    # protocol is either the protocol name (ex: tcp, udp, icmp) or the protocol number. -1 means "everything"
    protocol: str = "-1"

    # source_group can be either a string (a souce group name) or an AWSSecurityGroup resource
    souce_group: Optional[Union[Type['AWSSecurityGroup'], str]] = None

    # The end of the protocol port range the rule applies to
    to_port: Optional[int] = None

    def to_boto(self) -> dict:
        """Convert the dataclass into a boto3 formatted dictionary."""
        rule = {
            'IpProtocol': self.protocol
        }

        # Sanity check that either source_group or cidr_blocks is specified

        if self.cidr_blocks and self.souce_group:
            raise ValueError('"cidr_blocks" and "source_group" fields are mutually exclusive')

        if self.cidr_blocks is None and self.souce_group is None:
            raise ValueError('One of "cidr_blocks" or "source_group" fields must be specified')

        if self.souce_group is not None:

            # The sounce_group parameter is a string
            if isinstance(self.souce_group, str):
                rule['UserIdGroupPairs'] = [{'GroupName': self.souce_group}]

            # The source_group parameter is an AWSSecurityGroup resource - use the ID
            elif issubclass(self.souce_group, AWSSecurityGroup):
                source_obj = self.souce_group()
                source_obj.load_from_db()
                rule['UserIdGroupPairs'] = [{'GroupId': str(source_obj.group_id)}]

        elif self.cidr_blocks:
            # Dump all of the IPAddressRange objects into a list
            rule['IpRanges'] = [range.to_boto() for range in self.cidr_blocks]

        # Port range specifier
        if self.from_port:
            rule['FromPort'] = self.from_port
            rule['ToPort'] = self.to_port

        return rule

class AWSSecurityGroup(StackzillaResource):
    """Resource definition for a Security Group."""

    # Dynamic parameters (determined at create)
    arn = StackzillaAttribute(dynamic=True)
    group_id = StackzillaAttribute(dynamic=True)

    # User-defined parameters
    egress: List[AWSSecurityGroupRule] = StackzillaAttribute(required=False)
    ingress: List[AWSSecurityGroupRule] = StackzillaAttribute(required=False)
    name = StackzillaAttribute(required=True, modify_rebuild=True)
    description = StackzillaAttribute(required=True)
    region = StackzillaAttribute(required=True, choices=REGION_NAMES, modify_rebuild=True)
    tags = StackzillaAttribute(required=False, modify_rebuild=False)
    vpc_id = StackzillaAttribute(required=False, modify_rebuild=True)


    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='aws.ec2.ssh_key',
                                      resource_name=self.path(remove_prefix=True))

    def create(self) -> None:
        """Called when the resource is created."""
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        self._logger.debug(message=f'Creating {self.name}')

        create_data = {
            'GroupName': self.name,
            'Description': self.description,
        }

        if self.vpc_id:
            create_data['VpcId'] = self.vpc_id

        if self.tags:
            create_data['TagSpecifications'] = [{
                'ResourceType': 'key-pair',
                'Tags': dict_to_boto_tags(tags=self.tags)
            }]


        results = client.create_security_group(**create_data)
        self.group_id = results['GroupId']

        # Forumulate the arn
        boto_session = boto3.session.Session()
        sts_client = boto_session.client('sts', region_name=self.region)
        account_id = sts_client.get_caller_identity()['Account']
        self.arn = f'arn:aws:ec2:{self.region}:{account_id}:security-group/{self.group_id}'

        self._logger.log(message=f'Create complete for security group {self.group_id}')

        # Apply egress rules
        if self.egress:
            for rule in self.egress:
                self._logger.debug(f'Applying egress rule: {rule}')
                client.authorize_security_group_egress(
                    GroupId=self.group_id, IpPermissions=[rule.to_boto()]
                )

        # Apply ingress rules
        if self.ingress:
            for rule in self.ingress:
                self._logger.debug(f'Applying ingress rule: {rule}')
                client.authorize_security_group_ingress(
                    GroupId=self.group_id, IpPermissions=[rule.to_boto()]
                )

        # Persist this resource to the database
        return super().create()

    def delete(self) -> None:
        """Delete a previously created key pair."""
        self._logger.debug(message=f'Deleting {self.group_id}')

        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        client.delete_security_group(GroupId=self.group_id)
        super().delete()

        self._logger.debug(message='Deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Required to be overridden."""
        result = []
        return result

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')

    ######################################################################
    #################### Modifier Methods ################################
    ######################################################################
    def ingress_modified(self, previous_value: Optional[List[AWSSecurityGroupRule]],
                               new_value: Optional[List[AWSSecurityGroupRule]]) -> None:
        """Called when the ingress argument is modified

        Args:
            previous_value (Optional[List[AWSSecurityGroupRule]]): The previous list of ingress rules
            new_value (Optional[List[AWSSecurityGroupRule]]): The new list of ingress rules
        """

        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        # For the first pass, add any new rules
        if new_value is not None:
            for rule in new_value:

                # Add this rule if there was no previous rule list or if the rule wasn't in that list.
                if previous_value is None or rule not in previous_value:
                    client.authorize_security_group_ingress(GroupId=self.group_id, IpPermissions=[rule.to_boto()])

        # For the second pass, delete any rules which are no longer present
        if previous_value is not None:
            for rule in previous_value:

                # Only delete the rule if there are no new rules, or the rule doesn't exist in the new rule list.
                if new_value is None or rule not in new_value:
                    client.revoke_security_group_ingress(GroupId=self.group_id, IpPermissions=[rule.to_boto()])

    def egress_modified(self, previous_value: Optional[List[AWSSecurityGroupRule]],
                              new_value: Optional[List[AWSSecurityGroupRule]]) -> None:
        """Called when the egress argument is modified

        Args:
            previous_value (Optional[List[AWSSecurityGroupRule]]): The previous list of egress rules
            new_value (Optional[List[AWSSecurityGroupRule]]): The new list of egress rules
        """

        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        # For the first pass, add any new rules
        if new_value is not None:
            for rule in new_value:

                # Add this rule if there was no previous rule list or if the rule wasn't in that list.
                if previous_value is None or rule not in previous_value:
                    client.authorize_security_group_egress(GroupId=self.group_id, IpPermissions=[rule.to_boto()])

        # For the second pass, delete any rules which are no longer present
        if previous_value is not None:
            for rule in previous_value:

                # Only delete the rule if there are no new rules, or the rule doesn't exist in the new rule list.
                if new_value is None or rule not in new_value:
                    client.revoke_security_group_egress(GroupId=self.group_id, IpPermissions=[rule.to_boto()])

    def tags_modified(self, previous_value: Optional[Dict[str, str]], new_value: Optional[Dict[str, str]]) -> None:
        """Handler for when the tags attribute is modified

        Args:
            previous_value (Optional[Dict[str, str]]): The previous tag value
            new_value (Optional[Dict[str, str]]): The new tag value
        """
        self._logger.debug(f"Updating tags from {previous_value} to {new_value}")

        update_tags(arn=ARN.from_str(self.arn), previous_value=previous_value, new_value=new_value)

        self._logger.debug('Update complete')

def sg_list_to_boto_id_list(security_groups: List[Union[AWSSecurityGroup, str]]) -> List[str]:
    """Convert a list of AWSSecurityGroup resources into a list of AWS security group IDs.

        NOTE: The list may contain "raw" strings, which are considered to simply be security group IDs.

    Args:
        security_groups (List[AWSSecurityGroup]): A list of AWSSecurityGroup resources

    Returns:
        List[str]: List of AWS security group IDs
    """

    result = []
    for group in security_groups:
        if issubclass(group, str):
            result.append(group)
        elif issubclass(group, AWSSecurityGroup):
            sg_obj: AWSSecurityGroup = group()
            sg_obj.load_from_db()
            result.append(sg_obj.group_id)
        else:
            raise ValueError('Unsupported type passed in')

    return result
