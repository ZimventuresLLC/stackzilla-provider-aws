"""Module that defines an AWS EKS Node Group provider for stackzilla."""
from dataclasses import dataclass
from enum import Enum
from typing import List

import boto3
import botocore

from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.provider.aws.eks.cluster import AWSEKSCluster
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup
from stackzilla.provider.aws.utils.instances import INSTANCE_TYPES
from stackzilla.provider.aws.utils.tags import dict_to_boto_tags
from stackzilla.resource import StackzillaResource, ResourceVersion
from stackzilla.resource.exceptions import ResourceCreateFailure, AttributeModifyFailure

class TaintEffect(Enum):
    NO_SCHEDULE = 'NO_SCHEDULE'
    NO_EXECUTE = 'NO_EXECUTE'
    PREFER_NO_SCHEDULE = 'PREFER_NO_SCHEDULE'

@dataclass
class Taint:
    """Model a k8s taint."""

    key: str
    value: str
    effect: TaintEffect

    def to_boto(self) -> dict:
        """Export the values to a boto supported format."""
        return {'key': self.key, 'value': self.value, 'effect': self.effect.value}

class AWSEKSNodeGroup(StackzillaResource):
    """AWS EKS Node Group provider."""

    # Required attributes
    cluster = StackzillaAttribute(required=True, types=[AWSEKSCluster])
    name = StackzillaAttribute(required=True, modify_rebuild=True)
    region = StackzillaAttribute(required=True, modify_rebuild=True)
    # Details on setting up a node group IAM rule can be found here:
    # https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html
    iam_role = StackzillaAttribute(required=True)
    subnets = StackzillaAttribute(required=True, modify_rebuild=True)

    # Optional attributes
    ami_type = StackzillaAttribute(required=False, choices=['AL2_x86_64_GPU', 'AL2_x86_64', 'AL2_ARM_64'])
    capacity_type = StackzillaAttribute(required=False, choices=['ON_DEMAND', 'SPOT'])
    desired_node_count = StackzillaAttribute(required=False)
    disk_size = StackzillaAttribute(required=False)
    instance_types = StackzillaAttribute(required=False, choices=INSTANCE_TYPES)
    labels = StackzillaAttribute(required=False)
    # TODO: Support launch templates
    min_node_count = StackzillaAttribute(required=False)
    max_node_count = StackzillaAttribute(required=False)
    ssh_key = StackzillaAttribute(required=False, types=[str, AWSKeyPair])
    ssh_security_groups = StackzillaAttribute(required=False, types=[str, AWSSecurityGroup])
    taints = StackzillaAttribute(required=False, types=[Taint])
    tags = StackzillaAttribute(required=False)

    # Dynamic attributes
    arn = StackzillaAttribute(dynamic=True)

    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='aws.eks.cluster',
                                      resource_name=self.path(remove_prefix=True))

    def create(self) -> None:
        """Create the node group"""
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)

        cluster_obj = self.cluster()
        cluster_obj.load_from_db()
        cluster_name = cluster_obj.name

        create_args = {
            'clusterName': cluster_name,
            'nodegroupName': self.name,
        }

        if self.min_node_count or self.max_node_count or self.desired_node_count:
            create_args['scalingConfig'] = {}

            if self.min_node_count:
                create_args['scalingConfig']['minSize'] = self.min_node_count

            if self.max_node_count:
                create_args['scalingConfig']['maxSize'] = self.max_node_count

            if self.desired_node_count:
                create_args['scalingConfig']['desiredSize'] = self.desired_node_count

        if self.disk_size:
            create_args['diskSize'] = self.disk_size

        if self.subnets:
            create_args['subnets'] = self.subnets

        if self.instance_types:
            create_args['instanceTypes'] = self.instance_types

        if self.ami_type:
            create_args['amiType'] = self.ami_type

        # TODO: Implement this...
        """
        if self.ssh_key:
            if issubclass(AWSKeyPair, self.ssh_key):
                key = self.ssh_key().load_from_db().

            create_args['remoteAccess']['ec2SshKey']
        """

        if self.iam_role:
            create_args['nodeRole'] = self.iam_role

        if self.taints:
            create_args['taints'] = [taint.to_boto() for taint in self.taints]

        if self.tags:
            create_args['tags'] = dict_to_boto_tags(self.tags)

        if self.capacity_type:
            create_args['capacityType'] = self.capacity_type

        try:
            self._logger.debug('Creating node group')
            response = client.create_nodegroup(**create_args)
        except botocore.exceptions.ClientError as exc:
            raise ResourceCreateFailure(resource_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        # Save off any dynamic attributes
        self.arn = response['nodegroup']['nodegroupArn']
        super().create()

        # Wait for the nodegroup to become active
        self._logger.debug('Waiting for node group to become active (this could take a while)')
        waiter = client.get_waiter('nodegroup_active')
        waiter.wait(clusterName=cluster_name, nodegroupName=self.name)

        self._logger.debug(f'Creation complete: {self.arn}')
    def delete(self) -> None:
        """Delete the node group"""
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)

        cluster_obj = self.cluster()
        cluster_obj.load_from_db()
        cluster_name = cluster_obj.name

        self._logger.debug(f'Deleting {self.arn}')
        client.delete_nodegroup(clusterName=cluster_name, nodegroupName=self.name)

        self._logger.debug('Waiting for nodegroup to delete (this could take a while)')
        waiter = client.get_waiter('nodegroup_deleted')
        waiter.wait(clusterName=cluster_name, nodegroupName=self.name)
        super().delete()

        self._logger.debug('Deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Fetch blueprint dependencies of the EKS cluster."""
        return [self.cluster]

    def verify(self) -> None:

        # TODO: Do not set desired_node_count if cluster autoscaling is on
        # TODO: disk size and launch template can not both be defined
        pass

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')
