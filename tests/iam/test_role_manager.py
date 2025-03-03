import json
import unittest
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_iam

from aws_lib_3.iam.role_manager import RoleManager


@mock_iam
class TestRoleManager(unittest.TestCase):
    """
    Test cases for the RoleManager class.
    """

    def setUp(self):
        """
        Set up test fixtures.
        """
        self.role_manager = RoleManager()
        self.role_name = "test-role"
        self.trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

    def test_create_role(self):
        """
        Test creating a role.
        """
        # Create a role
        role = self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
            description="Test role",
        )

        # Verify the role was created
        self.assertEqual(role["RoleName"], self.role_name)
        self.assertIn("Arn", role)

        # Verify the role can be retrieved
        retrieved_role = self.role_manager.get_role(self.role_name)
        self.assertEqual(retrieved_role["RoleName"], self.role_name)

    def test_get_role(self):
        """
        Test getting a role.
        """
        # Create a role
        role = self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Get the role
        retrieved_role = self.role_manager.get_role(self.role_name)

        # Verify the role
        self.assertEqual(retrieved_role["RoleName"], self.role_name)
        self.assertEqual(retrieved_role["Arn"], role["Arn"])

    def test_list_roles(self):
        """
        Test listing roles.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # List roles
        roles = self.role_manager.list_roles()

        # Verify the role is in the list
        self.assertTrue(any(r["RoleName"] == self.role_name for r in roles))

    def test_update_role(self):
        """
        Test updating a role.
        """
        # Create a role
        role = self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Update the role
        new_description = "Updated test role"
        updated_role = self.role_manager.update_role(
            role_name=self.role_name,
            description=new_description,
        )

        # Verify the role was updated
        self.assertEqual(updated_role["RoleName"], self.role_name)
        self.assertEqual(updated_role["Description"], new_description)

    def test_update_assume_role_policy(self):
        """
        Test updating the trust policy of a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Update the trust policy
        updated_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["lambda.amazonaws.com", "s3.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        self.role_manager.update_assume_role_policy(
            role_name=self.role_name,
            assume_role_policy_document=updated_trust_policy,
        )

        # Verify the trust policy was updated
        role = self.role_manager.get_role(self.role_name)
        assume_role_policy_document = json.loads(role["AssumeRolePolicyDocument"])
        self.assertEqual(
            assume_role_policy_document["Statement"][0]["Principal"]["Service"],
            ["lambda.amazonaws.com", "s3.amazonaws.com"],
        )

    def test_delete_role(self):
        """
        Test deleting a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Delete the role
        self.role_manager.delete_role(self.role_name)

        # Verify the role is deleted
        with pytest.raises(Exception):
            self.role_manager.get_role(self.role_name)

    def test_attach_role_policy(self):
        """
        Test attaching a policy to a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Create a policy
        iam_client = boto3.client("iam", region_name="us-east-1")
        policy_name = "test-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        policy = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
        )
        policy_arn = policy["Policy"]["Arn"]

        # Attach the policy to the role
        self.role_manager.attach_role_policy(
            role_name=self.role_name, policy_arn=policy_arn
        )

        # Verify the policy is attached to the role
        attached_policies = self.role_manager.list_attached_role_policies(self.role_name)
        self.assertTrue(any(p["PolicyArn"] == policy_arn for p in attached_policies))

    def test_detach_role_policy(self):
        """
        Test detaching a policy from a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Create a policy
        iam_client = boto3.client("iam", region_name="us-east-1")
        policy_name = "test-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        policy = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
        )
        policy_arn = policy["Policy"]["Arn"]

        # Attach the policy to the role
        self.role_manager.attach_role_policy(
            role_name=self.role_name, policy_arn=policy_arn
        )

        # Detach the policy from the role
        self.role_manager.detach_role_policy(
            role_name=self.role_name, policy_arn=policy_arn
        )

        # Verify the policy is detached from the role
        attached_policies = self.role_manager.list_attached_role_policies(self.role_name)
        self.assertFalse(any(p["PolicyArn"] == policy_arn for p in attached_policies))

    def test_put_role_policy(self):
        """
        Test adding an inline policy to a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Add an inline policy to the role
        policy_name = "test-inline-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        self.role_manager.put_role_policy(
            role_name=self.role_name,
            policy_name=policy_name,
            policy_document=policy_document,
        )

        # Verify the inline policy is added to the role
        inline_policies = self.role_manager.list_role_policies(self.role_name)
        self.assertIn(policy_name, inline_policies)

    def test_get_role_policy(self):
        """
        Test getting an inline policy from a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Add an inline policy to the role
        policy_name = "test-inline-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        self.role_manager.put_role_policy(
            role_name=self.role_name,
            policy_name=policy_name,
            policy_document=policy_document,
        )

        # Get the inline policy
        inline_policy = self.role_manager.get_role_policy(
            role_name=self.role_name, policy_name=policy_name
        )

        # Verify the inline policy
        self.assertEqual(inline_policy["PolicyName"], policy_name)
        self.assertEqual(inline_policy["RoleName"], self.role_name)

    def test_delete_role_policy(self):
        """
        Test deleting an inline policy from a role.
        """
        # Create a role
        self.role_manager.create_role(
            role_name=self.role_name,
            assume_role_policy_document=self.trust_policy,
        )

        # Add an inline policy to the role
        policy_name = "test-inline-policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::example-bucket",
                }
            ],
        }
        self.role_manager.put_role_policy(
            role_name=self.role_name,
            policy_name=policy_name,
            policy_document=policy_document,
        )

        # Delete the inline policy
        self.role_manager.delete_role_policy(
            role_name=self.role_name, policy_name=policy_name
        )

        # Verify the inline policy is deleted
        inline_policies = self.role_manager.list_role_policies(self.role_name)
        self.assertNotIn(policy_name, inline_policies)


if __name__ == "__main__":
    unittest.main()
