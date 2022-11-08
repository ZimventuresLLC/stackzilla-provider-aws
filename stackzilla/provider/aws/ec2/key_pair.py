"""AWS Key Pair resource definition for Stackzilla."""
from typing import Dict, List, Optional

import botocore
import boto3
from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.resource.exceptions import ResourceCreateFailure
from stackzilla.provider.aws.utils.arn import ARN
from stackzilla.provider.aws.utils.regions import REGION_NAMES
from stackzilla.provider.aws.utils.tags import dict_to_boto_tags, update_tags
from stackzilla.resource.base import ResourceVersion, StackzillaResource

class AWSKeyPair(StackzillaResource):
    """Resource definition for a <provider_name> volume."""

    # Dynamic parameters (determined at create)
    arn = StackzillaAttribute(dynamic=True)
    key_fingerprint = StackzillaAttribute(dynamic=True)
    key_material = StackzillaAttribute(dynamic=True, secret=True)
    key_pair_id = StackzillaAttribute(dynamic=True)

    # User-defined parameters
    name = StackzillaAttribute(required=True, modify_rebuild=True)
    tags = StackzillaAttribute(required=False, modify_rebuild=False)
    type = StackzillaAttribute(choices=['ed25519', 'rsa'], default='rsa', modify_rebuild=True)
    format = StackzillaAttribute(choices=['pem', 'ppk'], default='pem', modify_rebuild=True)
    region = StackzillaAttribute(required=True, choices=REGION_NAMES, modify_rebuild=True)

    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='aws.ec2.ssh_key',
                                      resource_name=self.path(remove_prefix=True))

    def create(self) -> None:
        """Called when the resource is created."""
        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)

        self._logger.debug(message='Starting KeyPair creation')

        create_data = {
            'KeyName': self.name,
            'KeyType': self.type,
            'KeyFormat': self.format
        }

        if self.tags:
            create_data['TagSpecifications'] = [{
                'ResourceType': 'key-pair',
                'Tags': dict_to_boto_tags(tags=self.tags)
            }]

        try:
            results = client.create_key_pair(**create_data)
        except botocore.exceptions.ClientError as exc:
            raise ResourceCreateFailure(resource_name=self.path(remove_prefix=True), reason=str(exc)) from exc

        self.key_fingerprint = results['KeyFingerprint']
        self.key_material = results['KeyMaterial']
        self.key_pair_id = results['KeyPairId']

        # Build the ARN and save it
        boto_session = boto3.session.Session()
        sts_client = boto_session.client('sts', region_name=self.region)
        account_id = sts_client.get_caller_identity().get('Account')
        self.arn = f'arn:aws:ec2:{self.region}:{account_id}:key-pair/{self.key_pair_id}'

        self._logger.log(message=f'Create complete for key {self.key_pair_id}')

        # Persist this resource to the database
        return super().create()

    def delete(self) -> None:
        """Delete a previously created key pair."""
        self._logger.debug(message=f'Deleting {self.key_pair_id}')

        boto_session = boto3.session.Session()
        client = boto_session.client('ec2', region_name=self.region)
        client.delete_key_pair(KeyName=self.name)
        super().delete()

        self._logger.debug(message='Deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Required to be overridden."""
        result = []
        return result

    def tags_modified(self, previous_value: Optional[Dict[str, str]], new_value: Optional[Dict[str, str]]) -> None:
        """Handler for when the tags attribute is modified

        Args:
            previous_value (Optional[Dict[str, str]]): The previous tag value
            new_value (Optional[Dict[str, str]]): The new tag value
        """
        self._logger.debug(f"Updating tags from {previous_value} to {new_value}")

        update_tags(arn=ARN.from_str(self.arn), previous_value=previous_value, new_value=new_value)

        self._logger.debug('Update complete')

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')
