"""EKS cluster provier module."""
from dataclasses import dataclass
from textwrap import dedent
from typing import Dict, List, Union

import boto3
import botocore

from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.resource import StackzillaResource, ResourceVersion
from stackzilla.resource.kubernetes import StackzillaKubernetes
from stackzilla.resource.exceptions import ResourceCreateFailure, AttributeModifyFailure
from stackzilla.provider.aws.utils.regions import REGION_NAMES
from stackzilla.provider.aws.utils.tags import dict_to_boto_tags


@dataclass
class ClusterLogging:
    """Flags for controlling cluster loging"""
    api: bool = False
    audit: bool = False
    authenticator: bool = False
    controller_manager: bool = False
    scheduler: bool = False

    def to_boto(self) -> List[Dict[str, Union[str, bool]]]:
        """Convert into the expected boto format."""
        return [
            {'types': 'api', 'enabled': self.api},
            {'types': 'audit', 'enabled': self.audit},
            {'types': 'authenticator', 'enabled': self.authenticator},
            {'types': 'controllerManager', 'enabled': self.controller_manager},
            {'types': 'scheduler', 'enabled': self.scheduler}
        ]

class AWSEKSCluster(StackzillaKubernetes):
    """AWS EKS cluster provider."""

    # User configured attriburtes (required)
    name = StackzillaAttribute(required=True)
    region = StackzillaAttribute(required=True, choices=REGION_NAMES, modify_rebuild=True)

    # See https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html#create-service-role for creating a role
    role_arn = StackzillaAttribute(required=True, modify_rebuild=True)

    # TODO: Write a verifier to make sure all of the subnet IDs exist, and are in at least 2 different AZs
    subnets = StackzillaAttribute(required=False)

    # User configured attributes (optional)
    api_private = StackzillaAttribute(required=False, choices=[True, False], default=False)
    api_public = StackzillaAttribute(required=False, choices=[True, False], default=True)
    k8s_version = StackzillaAttribute(required=False, modify_rebuild=False,
                                      choices=['1.20', '1.21', '1.22', '1.23'], default='1.23')
    logging = StackzillaAttribute(required=False, types=[ClusterLogging])
    public_access_cidrs = StackzillaAttribute(required=False, modify_rebuild=True, default=['0.0.0.0/0'])
    security_groups = StackzillaAttribute(required=False)
    tags = StackzillaAttribute(required=False)

    # Dynamic attributes
    arn = StackzillaAttribute(dynamic=True)
    ca_data = StackzillaAttribute(dynamic=True)
    endpoint = StackzillaAttribute(dynamic=True)
    kubeconfig = StackzillaAttribute(dynamic=True)

    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='aws.eks.cluster',
                                      resource_name=self.path(remove_prefix=True))

    def create(self) -> None:
        """Create the EKS cluster."""
        self._logger.debug('Starting cluster creation')
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)

        resources_vpc_config = {
            'endpointPrivateAccess': self.api_private,
            'endpointPublicAccess': self.api_public,
            'publicAccessCidrs': self.public_access_cidrs,
        }

        # TODO: Support AWSSecurityGroup objects in addition to raw Security Group ID strings
        if self.security_groups:
            resources_vpc_config['securityGroupIds'] = self.security_groups

        if self.subnets:
            resources_vpc_config['subnetIds'] = self.subnets

        create_args = {
            'name': self.name,
            'version': self.k8s_version,
            'roleArn': self.role_arn,
            'resourcesVpcConfig': resources_vpc_config,
        }

        if self.logging:
            create_args['logging']['clusterLogging'] = self.logging.to_boto()

        if self.tags:
            create_args['tags'] = dict_to_boto_tags(self.tags)

        # Creation parameter refrence
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.create_cluster
        try:
            response = client.create_cluster(**create_args)
            print(response)
            self._logger.debug(response)
        except botocore.exceptions.ClientError as exc:
            raise ResourceCreateFailure(resource_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        # Save off the dynamic values that are availble before the cluster is active
        self.arn = response['cluster']['arn']

        super().create()

        self._logger.debug('Waiting for cluster to become active...')
        waiter = client.get_waiter('cluster_active')
        waiter.wait(name=self.name)

        try:
            response = client.describe_cluster(name=self.name)
        except botocore.exceptions.ClientError as exc:
            raise ResourceCreateFailure(resource_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        # Set up additional dynamic parameters (like certificate data)
        self.ca_data = response['cluster']['certificateAuthority']['data']
        self.endpoint = response['cluster']['endpoint']

        # Re-save
        super().update()

        self._logger.debug('Cluster creation complete')

    def delete(self) -> None:
        """Delete the EKS cluster."""
        self._logger.debug('Starting cluster deletion')
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)
        client.delete_cluster(name=self.name)

        # Wait for the cluster to finish deletion
        self._logger.debug('Waiting for cluster deletion to complete - this could take a while!')
        waiter = client.get_waiter('cluster_deleted')
        waiter.wait(name=self.name)

        super().delete()
        self._logger.debug('Cluster deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Fetch blueprint dependencies of the EKS cluster."""
        return []

    def get_certificate_data(self) -> str:
        """Fetch certificate data for the cluster.

        Returns:
            str: The certificate data.
        """
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)
        response = client.describe_cluster(name=self.name)
        return response['cluster']['certificateAuthority']['data']

    def get_endpoint(self) -> str:
        """Fetch the endpoint used to connect to this cluster."""
        return self.endpoint

    def get_nodes(self) -> List[List[str]]:
        """Get a list of the worker nodes."""

        session = boto3.session.Session()
        eks_client = session.client('eks', region_name=self.region)
        ec2_client = session.client('ec2', region_name=self.region)
        asg_client = session.client('autoscaling', region_name=self.region)

        # Fetch a list of all the nodegroups for this cluster
        node_groups = eks_client.list_nodegroups(clusterName=self.name)["nodegroups"]

        # Get all of the autoscaling groups for the node groups
        autoscaling_groups = []
        for node_group in node_groups:

            node_group_autoscaling_groups = eks_client.describe_nodegroup(
                clusterName=self.name, nodegroupName=node_group
            )["nodegroup"]["resources"]["autoScalingGroups"]

            for node_group_autoscaling_group in node_group_autoscaling_groups:
                autoscaling_groups.append(node_group_autoscaling_group["name"])

        # Build a list of all the instance IDs
        instances_ids = []
        for asg_info in asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=autoscaling_groups)["AutoScalingGroups"]:
            for instance in asg_info["Instances"]:
                instances_ids.append(instance['InstanceId'])

        reservations = ec2_client.describe_instances(InstanceIds=instances_ids)['Reservations']
        nodes = []
        nodes.append(
            ["InstanceId", "InstanceType", "AvailabilityZone", "PrivateIpAddress"]
        )

        for reservation in reservations:
            for instance in reservation['Instances']:
                nodes.append(
                    [
                        f"{instance['InstanceId']}",
                        f"{instance['InstanceType']}",
                        f"{instance['Placement']['AvailabilityZone']}",
                        f"{instance['NetworkInterfaces'][0]['PrivateIpAddress']}"
                    ]
                )

        return nodes

    def get_kubeconfig(self) -> str:
        """Generate a kubeconfig that can be used for accessing the cluster."""
        kubeconf_data = f"""
        apiVersion: v1
        clusters:
        - cluster:
            server: {self.endpoint}
            certificate-authority-data: {self.ca_data}
          name: {self.arn}
        contexts:
        - context:
            cluster: {self.arn}
            user: {self.arn}
          name: {self.arn}
        current-context: {self.arn}
        kind: Config
        preferences: {{}}
        users:
        - name: {self.arn}
          user:
            exec:
              apiVersion: client.authentication.k8s.io/v1beta1
              command: aws
              args:
                - --region
                - {self.region}
                - eks
                - get-token
                - --cluster-name
                - {self.name}"""

        return dedent(kubeconf_data)


    def k8s_version_modified(self, previous_value: str, new_value: str) -> None:
        """Handler for when the k8s_version attribute is modified.

        Args:
            previous_value (str): The previous kubernetes version
            new_value (str): The new kubernetes version
        """
        boto_session = boto3.session.Session()
        client = boto_session.client('eks', region_name=self.region)
        self._logger.debug(f'Changing kubernetes version from {previous_value} to {new_value}')

        try:
            response = client.update_cluster_version(name=self.name, version=new_value)
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        # Make sure hte update progress isn't in a fail state
        if 'errors' in response['update'] and len(response['update']['errors']):
            for error in response['update']['errors']:
                self._logger.critical(error['errorMessage'])

            raise AttributeModifyFailure(attribute_name='k8s_version', reason='Update failure. See logs for more details.')

        self._logger.debug('Waiting for cluster update to complete. This will take a while.')
        waiter = client.get_waiter('cluster_active')
        waiter.wait(name=self.name)
        self._logger.debug('Update complete')

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')
