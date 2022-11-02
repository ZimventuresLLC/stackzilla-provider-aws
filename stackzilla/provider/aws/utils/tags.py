"""Utility functions for dealing with tags."""
from typing import Any, Dict, List

import boto3
from stackzilla.provider.aws.utils.arn import ARN

def dict_to_boto_tags(tags: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert a standard Python dictionary to the expected format for boto.

    Args:
        tags (Dict[str, Any]): Dictionary of key/value pairs.

    Returns:
        List[Dict[str, Any]]: A list of tags
    """
    tag_list = []

    for key, value in tags.items():
        tag_list.append({'Key': key, 'Value': value})

    return tag_list

def update_tags(arn: ARN, previous_value: Dict[str, str], new_value: Dict[str, str]) -> None:
    """Given an ARN, update the tags for the resource.

    Args:
        arn (ARN): The ARN resource to update the tags on
        previous_value (Dict[str, str]): The previous dictionary of tags
        new_value (Dict[str, str]): The new dictionary of tags
    """

    # Decompose the ARN into its component parts
    boto_session = boto3.session.Session()
    client = boto_session.client('resourcegroupstaggingapi', region_name=arn.region)

    # First Pass: Remove tags that are not present anymore
    tags_to_delete = []

    # Either previous_value or new_value may be none, convert that to an empty dictionary
    if previous_value is None:
        previous_value = {}

    if new_value is None:
        new_value = {}

    # Build up a list of the keys to delete
    for tag_key in previous_value.keys():
        if tag_key not in new_value:
            tags_to_delete.append(tag_key)

    if tags_to_delete:
        client.untag_resources(ResourceARNList=[arn.to_str()], TagKeys=tags_to_delete)

    # Second Pass: Add/update tags
    if new_value:
        client.tag_resources(ResourceARNList=[arn.to_str()], Tags=new_value)
