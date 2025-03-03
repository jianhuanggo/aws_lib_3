import json
import logging
from typing import Dict, List, Optional, Any, Union

from botocore.exceptions import ClientError

from aws_lib_3.utils.aws_session import AWSSession

logger = logging.getLogger(__name__)

class RoleManager:
    """
    Manager class for IAM roles.
    """

    def __init__(self, aws_session: Optional[AWSSession] = None) -> None:
        """
        Initialize the RoleManager.

        Args:
            aws_session: AWSSession instance for AWS API calls
        """
        self.aws_session = aws_session or AWSSession()
        self.iam_client = self.aws_session.get_client("iam")

    def create_role(
        self,
        role_name: str,
        assume_role_policy_document: Union[Dict[str, Any], str],
        description: Optional[str] = None,
        path: str = "/",
        max_session_duration: int = 3600,
        permissions_boundary: Optional[str] = None,
        tags: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Create an IAM role.

        Args:
            role_name: Name of the role
            assume_role_policy_document: Trust policy document as a dictionary or JSON string
            description: Description of the role
            path: Path for the role
            max_session_duration: Maximum session duration in seconds
            permissions_boundary: ARN of the policy to set as the permissions boundary
            tags: List of tags to attach to the role

        Returns:
            Dict containing the created role information

        Raises:
            ClientError: If the role creation fails
        """
        if isinstance(assume_role_policy_document, dict):
            assume_role_policy_document = json.dumps(assume_role_policy_document)

        try:
            kwargs = {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": assume_role_policy_document,
                "Path": path,
                "MaxSessionDuration": max_session_duration,
            }

            if description:
                kwargs["Description"] = description

            if permissions_boundary:
                kwargs["PermissionsBoundary"] = permissions_boundary

            if tags:
                kwargs["Tags"] = tags

            response = self.iam_client.create_role(**kwargs)
            logger.info(f"Created IAM role: {role_name}")
            return response["Role"]
        except ClientError as e:
            logger.error(f"Failed to create IAM role {role_name}: {e}")
            raise

    def get_role(self, role_name: str) -> Dict[str, Any]:
        """
        Get an IAM role by name.

        Args:
            role_name: Name of the role to get

        Returns:
            Dict containing the role information

        Raises:
            ClientError: If the role retrieval fails
        """
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response["Role"]
        except ClientError as e:
            logger.error(f"Failed to get IAM role {role_name}: {e}")
            raise

    def list_roles(
        self, path_prefix: Optional[str] = None, max_items: int = 100
    ) -> List[Dict[str, Any]]:
        """
        List IAM roles.

        Args:
            path_prefix: Path prefix for filtering roles
            max_items: Maximum number of items to return

        Returns:
            List of role information dictionaries

        Raises:
            ClientError: If the role listing fails
        """
        try:
            kwargs = {"MaxItems": max_items}
            if path_prefix:
                kwargs["PathPrefix"] = path_prefix

            response = self.iam_client.list_roles(**kwargs)
            return response["Roles"]
        except ClientError as e:
            logger.error(f"Failed to list IAM roles: {e}")
            raise

    def update_role(
        self,
        role_name: str,
        description: Optional[str] = None,
        max_session_duration: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Update an IAM role's description and/or max session duration.

        Args:
            role_name: Name of the role to update
            description: New description for the role
            max_session_duration: New maximum session duration in seconds

        Returns:
            Dict containing the updated role information

        Raises:
            ClientError: If the role update fails
        """
        try:
            kwargs = {"RoleName": role_name}

            if description is not None:
                kwargs["Description"] = description

            if max_session_duration is not None:
                kwargs["MaxSessionDuration"] = max_session_duration

            if len(kwargs) > 1:  # More than just RoleName
                self.iam_client.update_role(**kwargs)
                logger.info(f"Updated IAM role: {role_name}")

            return self.get_role(role_name)
        except ClientError as e:
            logger.error(f"Failed to update IAM role {role_name}: {e}")
            raise

    def update_assume_role_policy(
        self, role_name: str, assume_role_policy_document: Union[Dict[str, Any], str]
    ) -> None:
        """
        Update the trust policy of an IAM role.

        Args:
            role_name: Name of the role to update
            assume_role_policy_document: New trust policy document as a dictionary or JSON string

        Raises:
            ClientError: If the trust policy update fails
        """
        if isinstance(assume_role_policy_document, dict):
            assume_role_policy_document = json.dumps(assume_role_policy_document)

        try:
            self.iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=assume_role_policy_document,
            )
            logger.info(f"Updated trust policy for IAM role: {role_name}")
        except ClientError as e:
            logger.error(f"Failed to update trust policy for IAM role {role_name}: {e}")
            raise

    def delete_role(self, role_name: str) -> None:
        """
        Delete an IAM role.

        Args:
            role_name: Name of the role to delete

        Raises:
            ClientError: If the role deletion fails
        """
        try:
            # First, detach all policies
            attached_policies = self.list_attached_role_policies(role_name)
            for policy in attached_policies:
                self.detach_role_policy(role_name, policy["PolicyArn"])

            # Then, delete all inline policies
            inline_policies = self.list_role_policies(role_name)
            for policy_name in inline_policies:
                self.delete_role_policy(role_name, policy_name)

            # Finally, delete the role
            self.iam_client.delete_role(RoleName=role_name)
            logger.info(f"Deleted IAM role: {role_name}")
        except ClientError as e:
            logger.error(f"Failed to delete IAM role {role_name}: {e}")
            raise

    def attach_role_policy(self, role_name: str, policy_arn: str) -> None:
        """
        Attach an IAM policy to a role.

        Args:
            role_name: Name of the role
            policy_arn: ARN of the policy to attach

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

    def detach_role_policy(self, role_name: str, policy_arn: str) -> None:
        """
        Detach an IAM policy from a role.

        Args:
            role_name: Name of the role
            policy_arn: ARN of the policy to detach

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

    def list_role_policies(self, role_name: str) -> List[str]:
        """
        List inline policies for a role.

        Args:
            role_name: Name of the role

        Returns:
            List of inline policy names

        Raises:
            ClientError: If the policy listing fails
        """
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            return response["PolicyNames"]
        except ClientError as e:
            logger.error(f"Failed to list inline policies for role {role_name}: {e}")
            raise

    def put_role_policy(
        self,
        role_name: str,
        policy_name: str,
        policy_document: Union[Dict[str, Any], str],
    ) -> None:
        """
        Add or update an inline policy for a role.

        Args:
            role_name: Name of the role
            policy_name: Name of the inline policy
            policy_document: Policy document as a dictionary or JSON string

        Raises:
            ClientError: If the inline policy creation fails
        """
        if isinstance(policy_document, dict):
            policy_document = json.dumps(policy_document)

        try:
            self.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=policy_document,
            )
            logger.info(
                f"Added/updated inline policy {policy_name} for role {role_name}"
            )
        except ClientError as e:
            logger.error(
                f"Failed to add/update inline policy {policy_name} for role {role_name}: {e}"
            )
            raise

    def get_role_policy(self, role_name: str, policy_name: str) -> Dict[str, Any]:
        """
        Get an inline policy for a role.

        Args:
            role_name: Name of the role
            policy_name: Name of the inline policy

        Returns:
            Dict containing the inline policy information

        Raises:
            ClientError: If the inline policy retrieval fails
        """
        try:
            response = self.iam_client.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
            return response
        except ClientError as e:
            logger.error(
                f"Failed to get inline policy {policy_name} for role {role_name}: {e}"
            )
            raise

    def delete_role_policy(self, role_name: str, policy_name: str) -> None:
        """
        Delete an inline policy from a role.

        Args:
            role_name: Name of the role
            policy_name: Name of the inline policy

        Raises:
            ClientError: If the inline policy deletion fails
        """
        try:
            self.iam_client.delete_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
            logger.info(f"Deleted inline policy {policy_name} from role {role_name}")
        except ClientError as e:
            logger.error(
                f"Failed to delete inline policy {policy_name} from role {role_name}: {e}"
            )
            raise
