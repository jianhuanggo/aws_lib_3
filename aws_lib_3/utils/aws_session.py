import logging
from typing import Dict, Optional, Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class AWSSession:
    """
    Utility class for managing AWS sessions and clients.
    """

    def __init__(
        self,
        region_name: Optional[str] = None,
        profile_name: Optional[str] = None,
        assume_role_arn: Optional[str] = None,
        session_name: str = "aws-lib-3-session",
        **kwargs: Any,
    ) -> None:
        """
        Initialize an AWS session.

        Args:
            region_name: AWS region name
            profile_name: AWS profile name
            assume_role_arn: ARN of the role to assume
            session_name: Name of the session when assuming a role
            **kwargs: Additional arguments to pass to boto3.session.Session
        """
        self.region_name = region_name
        self.profile_name = profile_name
        self.assume_role_arn = assume_role_arn
        self.session_name = session_name
        self.kwargs = kwargs
        self._session = None
        self._clients: Dict[str, Any] = {}

    @property
    def session(self) -> boto3.Session:
        """
        Get or create a boto3 session.

        Returns:
            boto3.Session: The boto3 session
        """
        if self._session is None:
            if self.assume_role_arn:
                base_session = boto3.Session(
                    region_name=self.region_name,
                    profile_name=self.profile_name,
                    **self.kwargs,
                )
                sts_client = base_session.client("sts")
                try:
                    response = sts_client.assume_role(
                        RoleArn=self.assume_role_arn,
                        RoleSessionName=self.session_name,
                    )
                    credentials = response["Credentials"]
                    self._session = boto3.Session(
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                        region_name=self.region_name,
                        **self.kwargs,
                    )
                except ClientError as e:
                    logger.error(f"Failed to assume role {self.assume_role_arn}: {e}")
                    raise
            else:
                self._session = boto3.Session(
                    region_name=self.region_name,
                    profile_name=self.profile_name,
                    **self.kwargs,
                )
        return self._session

    def get_client(self, service_name: str) -> Any:
        """
        Get or create a boto3 client for the specified service.

        Args:
            service_name: Name of the AWS service

        Returns:
            The boto3 client for the specified service
        """
        if service_name not in self._clients:
            self._clients[service_name] = self.session.client(service_name)
        return self._clients[service_name]

    def get_resource(self, service_name: str) -> Any:
        """
        Get or create a boto3 resource for the specified service.

        Args:
            service_name: Name of the AWS service

        Returns:
            The boto3 resource for the specified service
        """
        return self.session.resource(service_name)
