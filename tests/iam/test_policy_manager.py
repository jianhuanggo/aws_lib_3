import json
import unittest
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_iam

from aws_lib_3.iam.policy_manager import PolicyManager


@mock_iam
class TestPolicyManager(unittest.TestCase):
    """
    Test cases for the PolicyManager class.
    """

    def setUp(self):
        """
        Set up test fixtures.
        """
        self.policy_manager = PolicyManager()
        self.policy_name = "test-policy"
        self.policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }

    def test_create_policy(self):
        """
        Test creating a policy.
        """
        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
            description="Test policy",
        )

        # Verify the policy was created
        self.assertEqual(policy["PolicyName"], self.policy_name)
        self.assertIn("Arn", policy)

        # Verify the policy can be retrieved
        retrieved_policy = self.policy_manager.get_policy(policy["Arn"])
        self.assertEqual(retrieved_policy["PolicyName"], self.policy_name)

    def test_get_policy(self):
        """
        Test getting a policy.
        """
        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # Get the policy
        retrieved_policy = self.policy_manager.get_policy(policy["Arn"])

        # Verify the policy
        self.assertEqual(retrieved_policy["PolicyName"], self.policy_name)
        self.assertEqual(retrieved_policy["Arn"], policy["Arn"])

    def test_list_policies(self):
        """
        Test listing policies.
        """
        # Create a policy
        self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # List policies
        policies = self.policy_manager.list_policies()

        # Verify the policy is in the list
        self.assertTrue(any(p["PolicyName"] == self.policy_name for p in policies))

    def test_update_policy(self):
        """
        Test updating a policy.
        """
        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # Update the policy
        updated_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:GetObject"],
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        policy_version = self.policy_manager.update_policy(
            policy_arn=policy["Arn"],
            policy_document=updated_policy_document,
        )

        # Verify the policy version
        self.assertTrue(policy_version["IsDefaultVersion"])

    def test_delete_policy(self):
        """
        Test deleting a policy.
        """
        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # Delete the policy
        self.policy_manager.delete_policy(policy["Arn"])

        # Verify the policy is deleted
        with pytest.raises(Exception):
            self.policy_manager.get_policy(policy["Arn"])

    def test_attach_policy_to_role(self):
        """
        Test attaching a policy to a role.
        """
        # Create a role
        iam_client = boto3.client("iam", region_name="us-east-1")
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
        role_name = "test-role"
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )

        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # Attach the policy to the role
        self.policy_manager.attach_policy_to_role(
            policy_arn=policy["Arn"], role_name=role_name
        )

        # Verify the policy is attached to the role
        attached_policies = self.policy_manager.list_attached_role_policies(role_name)
        self.assertTrue(any(p["PolicyArn"] == policy["Arn"] for p in attached_policies))

    def test_detach_policy_from_role(self):
        """
        Test detaching a policy from a role.
        """
        # Create a role
        iam_client = boto3.client("iam", region_name="us-east-1")
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
        role_name = "test-role"
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )

        # Create a policy
        policy = self.policy_manager.create_policy(
            policy_name=self.policy_name,
            policy_document=self.policy_document,
        )

        # Attach the policy to the role
        self.policy_manager.attach_policy_to_role(
            policy_arn=policy["Arn"], role_name=role_name
        )

        # Detach the policy from the role
        self.policy_manager.detach_policy_from_role(
            policy_arn=policy["Arn"], role_name=role_name
        )

        # Verify the policy is detached from the role
        attached_policies = self.policy_manager.list_attached_role_policies(role_name)
        self.assertFalse(any(p["PolicyArn"] == policy["Arn"] for p in attached_policies))


if __name__ == "__main__":
    unittest.main()
