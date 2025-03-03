import json
import logging
from typing import Dict, List, Optional, Any, Union

from botocore.exceptions import ClientError

from aws_lib_3.utils.aws_session import AWSSession

logger = logging.getLogger(__name__)

class PolicyManager:
    """
    Manager class for IAM policies.
    """

    def __init__(self, aws_session: Optional[AWSSession] = None) -> None:
        """
        Initialize the PolicyManager.

        Args:
            aws_session: AWSSession instance for AWS API calls
        """
        self.aws_session = aws_session or AWSSession()
        self.iam_client = self.aws_session.get_client("iam")

    def create_policy(
        self,
        policy_name: str,
        policy_document: Union[Dict[str, Any], str],
        description: Optional[str] = None,
        path: str = "/",
        tags: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Create an IAM policy.

        Args:
            policy_name: Name of the policy
            policy_document: Policy document as a dictionary or JSON string
            description: Description of the policy
            path: Path for the policy
            tags: List of tags to attach to the policy

        Returns:
            Dict containing the created policy information

        Raises:
            ClientError: If the policy creation fails
        """
        if isinstance(policy_document, dict):
            policy_document = json.dumps(policy_document)

        try:
            kwargs = {
                "PolicyName": policy_name,
                "PolicyDocument": policy_document,
                "Path": path,
            }

            if description:
                kwargs["Description"] = description

            if tags:
                kwargs["Tags"] = tags

            response = self.iam_client.create_policy(**kwargs)
            logger.info(f"Created IAM policy: {policy_name}")
            return response["Policy"]
        except ClientError as e:
            logger.error(f"Failed to create IAM policy {policy_name}: {e}")
            raise

    def get_policy(self, policy_arn: str) -> Dict[str, Any]:
        """
        Get an IAM policy by ARN.

        Args:
            policy_arn: ARN of the policy to get

        Returns:
            Dict containing the policy information

        Raises:
            ClientError: If the policy retrieval fails
        """
        try:
            response = self.iam_client.get_policy(PolicyArn=policy_arn)
            return response["Policy"]
        except ClientError as e:
            logger.error(f"Failed to get IAM policy {policy_arn}: {e}")
            raise

    def get_policy_version(self, policy_arn: str, version_id: str) -> Dict[str, Any]:
        """
        Get a specific version of an IAM policy.

        Args:
            policy_arn: ARN of the policy
            version_id: Version ID of the policy

        Returns:
            Dict containing the policy version information

        Raises:
            ClientError: If the policy version retrieval fails
        """
        try:
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            return response["PolicyVersion"]
        except ClientError as e:
            logger.error(
                f"Failed to get IAM policy version {version_id} for {policy_arn}: {e}"
            )
            raise

    def list_policies(
        self,
        scope: str = "Local",
        only_attached: bool = False,
        path_prefix: Optional[str] = None,
        max_items: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List IAM policies.

        Args:
            scope: Scope of the policies to list (All, AWS, Local)
            only_attached: Only list attached policies
            path_prefix: Path prefix for filtering policies
            max_items: Maximum number of items to return

        Returns:
            List of policy information dictionaries

        Raises:
            ClientError: If the policy listing fails
        """
        try:
            kwargs = {
                "Scope": scope,
                "OnlyAttached": only_attached,
                "MaxItems": max_items,
            }

            if path_prefix:
                kwargs["PathPrefix"] = path_prefix

            response = self.iam_client.list_policies(**kwargs)
            return response["Policies"]
        except ClientError as e:
            logger.error(f"Failed to list IAM policies: {e}")
            raise

    def update_policy(
        self,
        policy_arn: str,
        policy_document: Union[Dict[str, Any], str],
        set_as_default: bool = True,
    ) -> Dict[str, Any]:
        """
        Update an IAM policy by creating a new version.

        Args:
            policy_arn: ARN of the policy to update
            policy_document: New policy document as a dictionary or JSON string
            set_as_default: Set the new version as the default version

        Returns:
            Dict containing the updated policy version information

        Raises:
            ClientError: If the policy update fails
        """
        if isinstance(policy_document, dict):
            policy_document = json.dumps(policy_document)

        try:
            # Check if we need to delete an old version (maximum of 5 versions allowed)
            versions = self.list_policy_versions(policy_arn)
            if len(versions) >= 5:
                # Find a non-default version to delete
                for version in versions:
                    if not version["IsDefaultVersion"]:
                        self.delete_policy_version(policy_arn, version["VersionId"])
                        break

            response = self.iam_client.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=policy_document,
                SetAsDefault=set_as_default,
            )
            logger.info(f"Updated IAM policy: {policy_arn}")
            return response["PolicyVersion"]
        except ClientError as e:
            logger.error(f"Failed to update IAM policy {policy_arn}: {e}")
            raise

    def list_policy_versions(self, policy_arn: str) -> List[Dict[str, Any]]:
        """
        List all versions of an IAM policy.

        Args:
            policy_arn: ARN of the policy

        Returns:
            List of policy version information dictionaries

        Raises:
            ClientError: If the policy version listing fails
        """
        try:
            response = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
            return response["Versions"]
        except ClientError as e:
            logger.error(f"Failed to list versions for IAM policy {policy_arn}: {e}")
            raise

    def delete_policy_version(self, policy_arn: str, version_id: str) -> None:
        """
        Delete a version of an IAM policy.

        Args:
            policy_arn: ARN of the policy
            version_id: Version ID to delete

        Raises:
            ClientError: If the policy version deletion fails
        """
        try:
            self.iam_client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            logger.info(f"Deleted version {version_id} of IAM policy: {policy_arn}")
        except ClientError as e:
            logger.error(
                f"Failed to delete version {version_id} of IAM policy {policy_arn}: {e}"
            )
            raise

    def delete_policy(self, policy_arn: str) -> None:
        """
        Delete an IAM policy.

        Args:
            policy_arn: ARN of the policy to delete

        Raises:
            ClientError: If the policy deletion fails
        """
        try:
            self.iam_client.delete_policy(PolicyArn=policy_arn)
            logger.info(f"Deleted IAM policy: {policy_arn}")
        except ClientError as e:
            logger.error(f"Failed to delete IAM policy {policy_arn}: {e}")
            raise

    def attach_policy_to_role(self, policy_arn: str, role_name: str) -> None:
        """
        Attach an IAM policy to a role.

        Args:
            policy_arn: ARN of the policy to attach
            role_name: Name of the role to attach the policy to

        Raises:
            ClientError: If the policy attachment fails
        """
        try:
            self.iam_client.attach_role_policy(
                RoleName=role_name, PolicyArn=policy_arn
            )
            logger.info(f"Attached IAM policy {policy_arn} to role {role_name}")
        except ClientError as e:
            logger.error(
                f"Failed to attach IAM policy {policy_arn} to role {role_name}: {e}"
            )
            raise

    def detach_policy_from_role(self, policy_arn: str, role_name: str) -> None:
        """
        Detach an IAM policy from a role.

        Args:
            policy_arn: ARN of the policy to detach
            role_name: Name of the role to detach the policy from

        Raises:
            ClientError: If the policy detachment fails
        """
        try:
            self.iam_client.detach_role_policy(
                RoleName=role_name, PolicyArn=policy_arn
            )
            logger.info(f"Detached IAM policy {policy_arn} from role {role_name}")
        except ClientError as e:
            logger.error(
                f"Failed to detach IAM policy {policy_arn} from role {role_name}: {e}"
            )
            raise

    def list_attached_role_policies(
        self, role_name: str, path_prefix: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List policies attached to a role.

        Args:
            role_name: Name of the role
            path_prefix: Path prefix for filtering policies

        Returns:
            List of attached policy information dictionaries

        Raises:
            ClientError: If the policy listing fails
        """
        try:
            kwargs = {"RoleName": role_name}
            if path_prefix:
                kwargs["PathPrefix"] = path_prefix

            response = self.iam_client.list_attached_role_policies(**kwargs)
            return response["AttachedPolicies"]
        except ClientError as e:
            logger.error(
                f"Failed to list attached policies for role {role_name}: {e}"
            )
            raise
