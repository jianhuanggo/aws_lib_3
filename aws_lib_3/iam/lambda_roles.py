import logging
from typing import Dict, List, Optional, Any

from aws_lib_3.iam.policy_manager import PolicyManager
from aws_lib_3.iam.role_manager import RoleManager
from aws_lib_3.utils.aws_session import AWSSession

logger = logging.getLogger(__name__)

class LambdaRoles:
    """
    Utility class for creating and managing IAM roles for Lambda functions.
    """

    def __init__(self, aws_session: Optional[AWSSession] = None) -> None:
        """
        Initialize the LambdaRoles utility.

        Args:
            aws_session: AWSSession instance for AWS API calls
        """
        self.aws_session = aws_session or AWSSession()
        self.role_manager = RoleManager(aws_session)
        self.policy_manager = PolicyManager(aws_session)

    def create_lambda_execution_role(
        self,
        role_name: str,
        description: Optional[str] = None,
        path: str = "/",
        tags: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Create an IAM role for Lambda execution.

        Args:
            role_name: Name of the role
            description: Description of the role
            path: Path for the role
            tags: List of tags to attach to the role

        Returns:
            Dict containing the created role information

        Raises:
            ClientError: If the role creation fails
        """
        # Define the trust policy for Lambda
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        # Create the role
        role = self.role_manager.create_role(
            role_name=role_name,
            assume_role_policy_document=trust_policy,
            description=description or "Lambda execution role",
            path=path,
            tags=tags,
        )

        # Attach the AWS managed policy for Lambda basic execution
        self.role_manager.attach_role_policy(
            role_name=role_name,
            policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        logger.info(f"Created Lambda execution role: {role_name}")
        return role

    def create_lambda_s3_access_role(
        self,
        role_name: str,
        s3_bucket_arns: List[str],
        description: Optional[str] = None,
        path: str = "/",
        tags: Optional[List[Dict[str, str]]] = None,
        read_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Create an IAM role for Lambda functions to access S3 buckets.

        Args:
            role_name: Name of the role
            s3_bucket_arns: List of S3 bucket ARNs to grant access to
            description: Description of the role
            path: Path for the role
            tags: List of tags to attach to the role
            read_only: Whether to grant read-only access to the S3 buckets

        Returns:
            Dict containing the created role information

        Raises:
            ClientError: If the role creation fails
        """
        # Define the trust policy for Lambda
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        # Create the role
        role = self.role_manager.create_role(
            role_name=role_name,
            assume_role_policy_document=trust_policy,
            description=description or "Lambda S3 access role",
            path=path,
            tags=tags,
        )

        # Attach the AWS managed policy for Lambda basic execution
        self.role_manager.attach_role_policy(
            role_name=role_name,
            policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        # Create a custom policy for S3 access
        s3_policy_name = f"{role_name}-s3-access-policy"
        s3_policy_document = self._create_s3_access_policy_document(
            s3_bucket_arns, read_only
        )

        s3_policy = self.policy_manager.create_policy(
            policy_name=s3_policy_name,
            policy_document=s3_policy_document,
            description=f"S3 access policy for {role_name}",
            tags=[{"Key": "ManagedBy", "Value": "aws_lib_3"}] if tags else None,
        )

        # Attach the S3 access policy to the role
        self.role_manager.attach_role_policy(
            role_name=role_name, policy_arn=s3_policy["Arn"]
        )

        logger.info(f"Created Lambda S3 access role: {role_name}")
        return role

    def _create_s3_access_policy_document(
        self, s3_bucket_arns: List[str], read_only: bool = False
    ) -> Dict[str, Any]:
        """
        Create an S3 access policy document.

        Args:
            s3_bucket_arns: List of S3 bucket ARNs to grant access to
            read_only: Whether to grant read-only access to the S3 buckets

        Returns:
            Dict containing the S3 access policy document
        """
        # Create resource list for buckets and objects
        bucket_resources = s3_bucket_arns
        object_resources = [f"{arn}/*" for arn in s3_bucket_arns]
        all_resources = bucket_resources + object_resources

        if read_only:
            # Read-only access
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:GetBucketLocation",
                            "s3:GetObjectVersion",
                            "s3:GetLifecycleConfiguration",
                        ],
                        "Resource": all_resources,
                    }
                ],
            }
        else:
            # Read-write access
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:GetBucketLocation",
                            "s3:GetObjectVersion",
                            "s3:PutObject",
                            "s3:PutObjectAcl",
                            "s3:GetLifecycleConfiguration",
                            "s3:PutLifecycleConfiguration",
                            "s3:DeleteObject",
                        ],
                        "Resource": all_resources,
                    }
                ],
            }

        return policy_document

    def create_lambda_full_access_role(
        self,
        role_name: str,
        description: Optional[str] = None,
        path: str = "/",
        tags: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """
        Create an IAM role with full Lambda access permissions.

        Args:
            role_name: Name of the role
            description: Description of the role
            path: Path for the role
            tags: List of tags to attach to the role

        Returns:
            Dict containing the created role information

        Raises:
            ClientError: If the role creation fails
        """
        # Define the trust policy for Lambda
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        # Create the role
        role = self.role_manager.create_role(
            role_name=role_name,
            assume_role_policy_document=trust_policy,
            description=description or "Lambda full access role",
            path=path,
            tags=tags,
        )

        # Attach the AWS managed policies for Lambda
        managed_policies = [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AWSLambdaInvocation-DynamoDB",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
            "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
            "arn:aws:iam::aws:policy/AmazonSNSFullAccess",
            "arn:aws:iam::aws:policy/AmazonKinesisFullAccess",
        ]

        for policy_arn in managed_policies:
            self.role_manager.attach_role_policy(
                role_name=role_name, policy_arn=policy_arn
            )

        logger.info(f"Created Lambda full access role: {role_name}")
        return role

    def update_lambda_role_s3_access(
        self,
        role_name: str,
        s3_bucket_arns: List[str],
        policy_name: Optional[str] = None,
        read_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Update an existing Lambda role with S3 access permissions.

        Args:
            role_name: Name of the role to update
            s3_bucket_arns: List of S3 bucket ARNs to grant access to
            policy_name: Name of the policy to create or update
            read_only: Whether to grant read-only access to the S3 buckets

        Returns:
            Dict containing the updated role information

        Raises:
            ClientError: If the role update fails
        """
        # Get the role to ensure it exists
        role = self.role_manager.get_role(role_name)

        # Create a custom policy for S3 access
        policy_name = policy_name or f"{role_name}-s3-access-policy"
        s3_policy_document = self._create_s3_access_policy_document(
            s3_bucket_arns, read_only
        )

        # Check if the policy already exists
        account_id = self.aws_session.get_client("sts").get_caller_identity()["Account"]
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

        try:
            # Try to get the policy
            self.policy_manager.get_policy(policy_arn)
            # If it exists, update it
            self.policy_manager.update_policy(
                policy_arn=policy_arn, policy_document=s3_policy_document
            )
        except Exception:
            # If it doesn't exist, create it
            s3_policy = self.policy_manager.create_policy(
                policy_name=policy_name,
                policy_document=s3_policy_document,
                description=f"S3 access policy for {role_name}",
                tags=[{"Key": "ManagedBy", "Value": "aws_lib_3"}],
            )
            policy_arn = s3_policy["Arn"]

        # Attach the S3 access policy to the role if not already attached
        attached_policies = self.role_manager.list_attached_role_policies(role_name)
        if not any(p["PolicyArn"] == policy_arn for p in attached_policies):
            self.role_manager.attach_role_policy(
                role_name=role_name, policy_arn=policy_arn
            )

        logger.info(f"Updated Lambda role with S3 access: {role_name}")
        return self.role_manager.get_role(role_name)
