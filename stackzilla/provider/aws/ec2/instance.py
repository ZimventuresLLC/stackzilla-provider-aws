"""Resource definition for AWS EC2 instances."""
from typing import List, Optional

import botocore
import boto3
from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.resource.exceptions import ResourceCreateFailure
from stackzilla.provider.aws.ec2.key_pair import AWSKeyPair
from stackzilla.provider.aws.ec2.security_group import AWSSecurityGroup, sg_list_to_boto_id_list
from stackzilla.provider.aws.utils.regions import REGION_NAMES
from stackzilla.provider.aws.utils.instances import INSTANCE_TYPES

from stackzilla.resource.base import AttributeModifyFailure, ResourceVersion
from stackzilla.resource.compute import StackzillaCompute, SSHCredentials, SSHAddress

class AWSInstance(StackzillaCompute):
    """Resource definition for an AWS EC2 Instance."""
    # Dynamic parameters (determined at create)
    instance_id = StackzillaAttribute(dynamic=True)
    private_ip = StackzillaAttribute(dynamic=True)
    public_ip = StackzillaAttribute(dynamic=True)

    # User-defined parameters
    ami = StackzillaAttribute(required=True, modify_rebuild=True)
    disable_api_termination = StackzillaAttribute(required=False, default=False, choices=[True, False])
    ebs_optimized = StackzillaAttribute(required=False, default=False, choices=[True, False])
    name = StackzillaAttribute(required=True, modify_rebuild=False)
    region = StackzillaAttribute(required=True, choices=REGION_NAMES)

    # This is a list of either security group names, or AWSSecurityGroup objects
    security_groups = StackzillaAttribute(required=False)
    ssh_key = StackzillaAttribute(required=True, types=[AWSKeyPair])
    ssh_username = StackzillaAttribute(required=True, types=[str])
    tags = StackzillaAttribute(required=False, modify_rebuild=False)
    type = StackzillaAttribute(required=True, choices=INSTANCE_TYPES)
    user_data = StackzillaAttribute(required=False)

    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='aws.ec2.instance',
                                      resource_name=self.path(remove_prefix=True))

    def ssh_credentials(self) -> SSHCredentials:
        """Provide the credentials needed to SSH into a host."""
        # Get the SSH key data
        ssh_key_obj = self.ssh_key()
        ssh_key_obj.load_from_db()

        # The key data must be binary encoded, otherwise ssh2-lib thinks it's a file path!
        return SSHCredentials(username=self.ssh_username, password=None, key=ssh_key_obj.key_material.encode())

    def ssh_address(self) -> SSHAddress:
        """Provide the hostname/ip and port number for connecting to a host."""
        addr = None
        if self.public_ip:
            addr = self.public_ip
        elif self.private_ip:
            addr = self.private_ip
        else:
            raise RuntimeError('No valid SSH addresses')

        return SSHAddress(host=addr, port=22)

    def create(self) -> None:
        """Called when the resource is created."""
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        self._logger.debug(message='Starting instance creation')

        # Get the SSH key name
        ssh_key_obj = self.ssh_key()
        ssh_key_obj.load_from_db()
        ssh_key_name = ssh_key_obj.name

        create_args = {
            'DisableApiTermination': self.disable_api_termination,
            'EbsOptimized': self.ebs_optimized,
            'ImageId': self.ami,
            'InstanceType': self.type,
            'KeyName': ssh_key_name,
            'MaxCount': 1,
            'MinCount': 1,
        }

        if self.user_data:
            create_args['UserData'] = self.user_data

        if self.security_groups:
            security_groups: List[str] = sg_list_to_boto_id_list(self.security_groups)
            create_args['SecurityGroupIds'] = security_groups

        try:
            result = client.run_instances(**create_args)
        except botocore.exceptions.ClientError as exc:
            raise ResourceCreateFailure(resource_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        # Wait for the instance to reach its running state
        waiter = client.get_waiter('instance_running')

        self.instance_id = result['Instances'][0]['InstanceId']

        if 'PrivateIpAddress' in result['Instances'][0]:
            self.private_ip = result['Instances'][0]['PrivateIpAddress']

        if 'PublicIpAddress' in result['Instances'][0]:
            self.public_ip = result['Instances'][0]['PublicIpAddress']

        self._logger.log(message=f'Create complete | {self.public_ip =} | {self.private_ip =}')

        # Persist the initial changes to the database
        super().create()

        # Wait for the instance to reach its running state
        waiter.wait(InstanceIds=[self.instance_id])

        # Get details about the newly running instance (notably, it's public IP address)
        result = client.describe_instances(InstanceIds=[self.instance_id])
        instance = result['Reservations'][0]['Instances'][0]

        if 'PublicIpAddress' in instance:
            self.public_ip = instance['PublicIpAddress']

        # Save with the updated information
        super().update()

    def delete(self) -> None:
        """Delete a previously created instance."""
        self._logger.debug(message='Deleting')

        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        client.terminate_instances(InstanceIds=[self.instance_id])

        # Wait for the instance to terminate
        self._logger.debug(message='Waiting for instnace to terminate')
        waiter = client.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=[self.instance_id])
        self._logger.debug(message='Instance terminated')

        super().delete()
        self._logger.debug(message='Deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Required to be overridden."""
        result = []

        if self.security_groups:
            # This list can be pre-defined security groups (strings) or AWSSecurityGroup resources
            # Only add the AWSSecurityGroup resources as dependencies
            for group in self.security_groups:
                if issubclass(group, AWSSecurityGroup):
                    result.append(group)

        if self.ssh_key:
            result.append(self.ssh_key)

        return result

    def start(self, wait_for_online: bool) -> None:
        """Power up the instance.

        Args:
            wait_for_online (bool): If True, the method will wait to be powered up before returning.

        Raises:
            ComputeStartError: Raised on an error
        """
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        self._logger.debug('Starting instance')

        client.start_instances(InstanceIds=[self.instance_id])

        if wait_for_online:
            self._logger.debug('Waiting for the instance to start')
            waiter = client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[self.instance_id])
            self._logger.debug('Instance has started')

        # TODO: The public IP addresses may have changed - save them here

    def stop(self, wait_for_offline: bool) -> None:
        """Stops the running instance.

        Args:
            wait_for_offline (bool): If True, wait for the instance to power down before returning.

        Raises:
            ComputeStopError: Raised when an error occurs
        """
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        self._logger.debug('Stopping instance')
        client.stop_instances(InstanceIds=[self.instance_id])

        if wait_for_offline:
            self._logger.debug('Waiting for the instance to stop')
            waiter = client.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[self.instance_id])
            self._logger.debug('Instance stopped')

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')

    #####################################################
    # Attribute modification handlers
    #####################################################
    def disable_api_termination_modified(self, previous_value: bool, new_value: bool) -> None:
        """Called when the disable_api_termination attribute is modified.

        Args:
            previous_value (bool): The previous API termination setting
            new_value (bool): The new API termination setting
        """
        self._logger.debug(f'Updating disable_api_termination from {previous_value} to {new_value}')
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        try:
            client.modify_instance_attribute(InstanceId=self.instance_id,
                                             DisableApiTermination={'Value': new_value})
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name='type', reason=str(exc)) from exc

        self._logger.debug('disable_api_termination update complete')

    def ebs_optimized_modified(self, previous_value: bool, new_value: bool) -> None:
        """Called when the ebs_optimized attribute is modified.

        Args:
            previous_value (bool): The previous EBS Optimization setting
            new_value (bool): The new EBS Optimization setting
        """
        self._logger.debug(f'Updating ebs_optimized from {previous_value} to {new_value}')
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        try:
            client.modify_instance_attribute(InstanceId=self.instance_id,
                                             EbsOptimized={'Value': new_value})
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name='type', reason=str(exc)) from exc

        self._logger.debug('ebs_optimized update complete')

    def security_groups_modified(self, previous_value: Optional[List[AWSSecurityGroup]],
                                       new_value: Optional[List[AWSSecurityGroup]]) -> None:
        """Called when the security_groups attribute is modified.

        Args:
            previous_value (Optional[List[AWSSecurityGroup]]): The previous list of security groups
            new_value (Optional[List[AWSSecurityGroup]]): The new list of security groups
        """
        self._logger.debug(f'Updating security_groups from {previous_value} to {new_value}')
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        try:
            security_groups: List[str] = []

            if new_value:
                security_groups = sg_list_to_boto_id_list(new_value)

            client.modify_instance_attribute(InstanceId=self.instance_id,
                                             Groups=security_groups)
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name='type', reason=str(exc)) from exc

        self._logger.debug('security_groups update complete')

    def type_modified(self, previous_value: str, new_value: str) -> None:
        """Called when the type parameter is modified.

        Args:
            previous_value (str): The previous instance type
            new_value (str): The new instance type
        """
        self._logger.debug(f'Updating instance type from {previous_value} to {new_value}')
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        instance_was_running = True
        if self._get_instance_state() in ['shutting-down', 'terminated', 'stopping', 'stopped']:
            instance_was_running = False

        # Wait for the instance to stop before changing the type
        if instance_was_running:
            self.stop(wait_for_offline=True)

        try:
            client.modify_instance_attribute(InstanceId=self.instance_id,
                                             InstanceType={'Value': new_value})
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name='type', reason=str(exc)) from exc

        # Power the instance back up if it was originally running
        if instance_was_running:
            self.start(wait_for_online=True)

        self._logger.debug('Instance type update complete')

    def user_data_modified(self, previous_value: str, new_value: str) -> None:
        """Called when the user_data attribute is modified.

        Args:
            previous_value (str): The previous user_data value
            new_value (str): The new user_data value
        """
        self._logger.debug('Updating user_data')
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        try:
            client.modify_instance_attribute(InstanceId=self.instance_id,
                                             UserData ={'Value': new_value.encode()})
        except botocore.exceptions.ClientError as exc:
            raise AttributeModifyFailure(attribute_name='type', reason=str(exc)) from exc

        self._logger.debug('user_data update complete')
    def _get_instance_state(self) -> str:
        """Fetch the current state of the instance.

        Returns:
            str: 'pending'|'running'|'shutting-down'|'terminated'|'stopping'|'stopped'
        """
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        response = client.describe_instance_status(InstanceIds=[self.instance_id])

        if len(response['InstanceStatuses']) == 0:
            return 'stopped'

        return response['InstanceStatuses'][0]['InstanceState']['Name']
