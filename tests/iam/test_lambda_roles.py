import json
import unittest
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_iam

from aws_lib_3.iam.lambda_roles import LambdaRoles


@mock_iam
class TestLambdaRoles(unittest.TestCase):
    """
    Test cases for the LambdaRoles class.
    """

    def setUp(self):
        """
        Set up test fixtures.
        """
        self.lambda_roles = LambdaRoles()
        self.execution_role_name = "test-lambda-execution-role"
        self.s3_access_role_name = "test-lambda-s3-access-role"
        self.s3_bucket_arns = ["arn:aws:s3:::example-bucket"]

    def test_create_lambda_execution_role(self):
        """
        Test creating a Lambda execution role.
        This tests the creation of a role with relevant policy to serve as an execution role for a Lambda function.
        """
        # Create a Lambda execution role
        role = self.lambda_roles.create_lambda_execution_role(
            role_name=self.execution_role_name,
            description="Test Lambda execution role",
            tags=[{"Key": "Environment", "Value": "Test"}],
        )

        # Verify the role was created
        self.assertEqual(role["RoleName"], self.execution_role_name)
        self.assertIn("Arn", role)

        # Verify the trust policy allows Lambda to assume the role
        assume_role_policy_document = json.loads(role["AssumeRolePolicyDocument"])
        self.assertEqual(
            assume_role_policy_document["Statement"][0]["Principal"]["Service"],
            "lambda.amazonaws.com",
        )

        # Verify the AWSLambdaBasicExecutionRole policy is attached
        iam_client = boto3.client("iam", region_name="us-east-1")
        attached_policies = iam_client.list_attached_role_policies(
            RoleName=self.execution_role_name
        )["AttachedPolicies"]
        
        # Check if the policy is attached
        basic_execution_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        self.assertTrue(
            any(p["PolicyArn"] == basic_execution_policy_arn for p in attached_policies),
            f"Policy {basic_execution_policy_arn} not attached to role {self.execution_role_name}",
        )

    def test_create_lambda_s3_access_role(self):
        """
        Test creating a Lambda S3 access role.
        This tests the creation of a role with policy to access an S3 bucket.
        """
        # Create a Lambda S3 access role
        role = self.lambda_roles.create_lambda_s3_access_role(
            role_name=self.s3_access_role_name,
            s3_bucket_arns=self.s3_bucket_arns,
            description="Test Lambda S3 access role",
            tags=[{"Key": "Environment", "Value": "Test"}],
        )

        # Verify the role was created
        self.assertEqual(role["RoleName"], self.s3_access_role_name)
        self.assertIn("Arn", role)

        # Verify the trust policy allows Lambda to assume the role
        assume_role_policy_document = json.loads(role["AssumeRolePolicyDocument"])
        self.assertEqual(
            assume_role_policy_document["Statement"][0]["Principal"]["Service"],
            "lambda.amazonaws.com",
        )

        # Verify the AWSLambdaBasicExecutionRole policy is attached
        iam_client = boto3.client("iam", region_name="us-east-1")
        attached_policies = iam_client.list_attached_role_policies(
            RoleName=self.s3_access_role_name
        )["AttachedPolicies"]
        
        # Check if the basic execution policy is attached
        basic_execution_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        self.assertTrue(
            any(p["PolicyArn"] == basic_execution_policy_arn for p in attached_policies),
            f"Policy {basic_execution_policy_arn} not attached to role {self.s3_access_role_name}",
        )
        
        # Check if a custom S3 access policy is attached
        self.assertTrue(
            any("s3-access-policy" in p["PolicyArn"] for p in attached_policies),
            f"S3 access policy not attached to role {self.s3_access_role_name}",
        )
        
        # Get the custom S3 access policy
        s3_policy_arn = next(p["PolicyArn"] for p in attached_policies if "s3-access-policy" in p["PolicyArn"])
        s3_policy = iam_client.get_policy(PolicyArn=s3_policy_arn)["Policy"]
        
        # Get the policy document
        policy_version = iam_client.get_policy_version(
            PolicyArn=s3_policy_arn,
            VersionId=s3_policy["DefaultVersionId"],
        )["PolicyVersion"]
        
        # Verify the policy document contains S3 permissions
        policy_document = json.loads(policy_version["Document"])
        self.assertTrue(
            any(
                "s3:" in action
                for statement in policy_document["Statement"]
                for action in (
                    statement["Action"]
                    if isinstance(statement["Action"], list)
                    else [statement["Action"]]
                )
            ),
            "S3 permissions not found in policy document",
        )
        
        # Verify the policy document contains the S3 bucket ARNs
        self.assertTrue(
            any(
                any(
                    bucket_arn in resource
                    for resource in (
                        statement["Resource"]
                        if isinstance(statement["Resource"], list)
                        else [statement["Resource"]]
                    )
                )
                for statement in policy_document["Statement"]
                for bucket_arn in self.s3_bucket_arns
            ),
            f"S3 bucket ARNs {self.s3_bucket_arns} not found in policy document",
        )

    def test_create_lambda_full_access_role(self):
        """
        Test creating a Lambda full access role.
        """
        # Create a Lambda full access role
        role_name = "test-lambda-full-access-role"
        role = self.lambda_roles.create_lambda_full_access_role(
            role_name=role_name,
            description="Test Lambda full access role",
            tags=[{"Key": "Environment", "Value": "Test"}],
        )

        # Verify the role was created
        self.assertEqual(role["RoleName"], role_name)
        self.assertIn("Arn", role)

        # Verify the trust policy allows Lambda to assume the role
        assume_role_policy_document = json.loads(role["AssumeRolePolicyDocument"])
        self.assertEqual(
            assume_role_policy_document["Statement"][0]["Principal"]["Service"],
            "lambda.amazonaws.com",
        )

        # Verify the managed policies are attached
        iam_client = boto3.client("iam", region_name="us-east-1")
        attached_policies = iam_client.list_attached_role_policies(
            RoleName=role_name
        )["AttachedPolicies"]
        
        # Check if the basic execution policy is attached
        basic_execution_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        self.assertTrue(
            any(p["PolicyArn"] == basic_execution_policy_arn for p in attached_policies),
            f"Policy {basic_execution_policy_arn} not attached to role {role_name}",
        )
        
        # Check if other managed policies are attached
        managed_policies = [
            "arn:aws:iam::aws:policy/AWSLambdaInvocation-DynamoDB",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
            "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
            "arn:aws:iam::aws:policy/AmazonSNSFullAccess",
            "arn:aws:iam::aws:policy/AmazonKinesisFullAccess",
        ]
        
        for policy_arn in managed_policies:
            self.assertTrue(
                any(p["PolicyArn"] == policy_arn for p in attached_policies),
                f"Policy {policy_arn} not attached to role {role_name}",
            )

    def test_update_lambda_role_s3_access(self):
        """
        Test updating a Lambda role with S3 access.
        """
        # Create a Lambda execution role
        role = self.lambda_roles.create_lambda_execution_role(
            role_name=self.execution_role_name,
            description="Test Lambda execution role",
        )

        # Update the role with S3 access
        updated_role = self.lambda_roles.update_lambda_role_s3_access(
            role_name=self.execution_role_name,
            s3_bucket_arns=self.s3_bucket_arns,
            policy_name="test-s3-access-policy",
        )

        # Verify the role was updated
        self.assertEqual(updated_role["RoleName"], self.execution_role_name)

        # Verify the S3 access policy is attached
        iam_client = boto3.client("iam", region_name="us-east-1")
        attached_policies = iam_client.list_attached_role_policies(
            RoleName=self.execution_role_name
        )["AttachedPolicies"]
        
        # Check if a custom S3 access policy is attached
        self.assertTrue(
            any("test-s3-access-policy" in p["PolicyArn"] for p in attached_policies),
            f"S3 access policy not attached to role {self.execution_role_name}",
        )


if __name__ == "__main__":
    unittest.main()
