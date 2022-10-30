"""<provider_name> <your resource name> resource definition for Stackzilla."""
from typing import Any, List

from stackzilla.attribute import StackzillaAttribute
from stackzilla.logger.provider import ProviderLogger
from stackzilla.resource.base import ResourceVersion, StackzillaResource

class LinodeVolume(StackzillaResource):
    """Resource definition for a <provider_name> volume."""

    # Dynamic parameters (determined at create)
    some_parameter = StackzillaAttribute(dynamic=True)

    # User-defined parameters
    label = StackzillaAttribute(required=False, modify_rebuild=False)
    tags = StackzillaAttribute(required=False, modify_rebuild=False)


    def __init__(self):
        """Set up logging for the provider."""
        super().__init__()
        self._logger = ProviderLogger(provider_name='<provider_name>.resource_type', resource_name=self.path(remove_prefix=True))

    def create(self) -> None:
        """Called when the resource is created."""

        self._logger.debug(message=f'Starting creation of {self.label}')

        # Perform actual resource creation here
        # ...

        self._logger.log(message='Creation complete')

        # Persist this resource to the database
        return super().create()

    def delete(self) -> None:
        """Delete a previously created volume."""
        self._logger.debug(message=f'Deleting {self.label}')

        # Perform resource deletino here
        # ...
        super().delete()

        self._logger.debug(message='Deletion complete')

    def depends_on(self) -> List['StackzillaResource']:
        """Required to be overridden."""
        result = []

        # If there are any dependencies to other resources in the blueprint, add them here.
        # results.append(...)

        return result

    def label_modified(self, previous_value: Any, new_value: Any) -> None:
        """Called when the label value needs modification

        Args:
            previous_value (Any): Previous label
            new_value (Any): New label
        """
        self._logger.log(f'Updating volume label from {previous_value} to {new_value}')

        # TODO: Actually do whatever is needed to persist the label to the resource.

    @classmethod
    def version(cls) -> ResourceVersion:
        """Fetch the version of the resource provider."""
        return ResourceVersion(major=0, minor=1, build=0, name='alpha')
