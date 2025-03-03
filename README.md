# AWS Library 3 - IAM Role and Policy Management

A production-grade Python library for managing AWS IAM roles and policies, with a focus on Lambda function roles.

## Features

- Create, read, update, and delete IAM policies
- Create, read, update, and delete IAM roles
- Assign policies to roles
- Create specialized roles for Lambda functions:
  - Lambda execution roles
  - Lambda roles with S3 bucket access
  - Lambda roles with full access to AWS services

## Installation

```bash
# Clone the repository
git clone https://github.com/jianhuanggo/aws_lib_3.git
cd aws_lib_3

# Install the package
pip install -e .
```

## Requirements

- Python 3.8+
- boto3
- botocore

## Usage

### Initialize AWS Session

```python
from aws_lib_3.utils.aws_session import AWSSession

# Create a session with default credentials
session = AWSSession()

# Create a session with specific region
session = AWSSession(region_name="us-west-2")

# Create a session with a specific profile
session = AWSSession(profile_name="my-profile")

# Create a session with role assumption
session = AWSSession(
    assume_role_arn="arn:aws:iam::123456789012:role/my-role",
    session_name="my-session"
)
```

### IAM Policy Management

```python
from aws_lib_3.iam.policy_manager import PolicyManager

# Initialize the policy manager
policy_manager = PolicyManager()

# Create a policy
policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::example-bucket"
        }
    ]
}

policy = policy_manager.create_policy(
    policy_name="example-policy",
    policy_document=policy_document,
    description="Example policy for S3 access"
)

# Get a policy
policy = policy_manager.get_policy("arn:aws:iam::123456789012:policy/example-policy")

# Update a policy
updated_policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": "arn:aws:s3:::example-bucket"
        }
    ]
}

policy_manager.update_policy(
    policy_arn="arn:aws:iam::123456789012:policy/example-policy",
    policy_document=updated_policy_document
)

# Delete a policy
policy_manager.delete_policy("arn:aws:iam::123456789012:policy/example-policy")
```

### IAM Role Management

```python
from aws_lib_3.iam.role_manager import RoleManager

# Initialize the role manager
role_manager = RoleManager()

# Create a role
trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }
    ]
}

role = role_manager.create_role(
    role_name="example-role",
    assume_role_policy_document=trust_policy,
    description="Example role for Lambda"
)

# Get a role
role = role_manager.get_role("example-role")

# Update a role
role_manager.update_role(
    role_name="example-role",
    description="Updated example role for Lambda"
)

# Update a role's trust policy
updated_trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": ["lambda.amazonaws.com", "s3.amazonaws.com"]},
            "Action": "sts:AssumeRole"
        }
    ]
}

role_manager.update_assume_role_policy(
    role_name="example-role",
    assume_role_policy_document=updated_trust_policy
)

# Attach a policy to a role
role_manager.attach_role_policy(
    role_name="example-role",
    policy_arn="arn:aws:iam::123456789012:policy/example-policy"
)

# Detach a policy from a role
role_manager.detach_role_policy(
    role_name="example-role",
    policy_arn="arn:aws:iam::123456789012:policy/example-policy"
)

# Delete a role
role_manager.delete_role("example-role")
```

### Lambda Roles

```python
from aws_lib_3.iam.lambda_roles import LambdaRoles

# Initialize the Lambda roles utility
lambda_roles = LambdaRoles()

# Create a Lambda execution role
execution_role = lambda_roles.create_lambda_execution_role(
    role_name="lambda-execution-role",
    description="Role for Lambda function execution"
)

# Create a Lambda role with S3 access
s3_access_role = lambda_roles.create_lambda_s3_access_role(
    role_name="lambda-s3-access-role",
    s3_bucket_arns=["arn:aws:s3:::example-bucket"],
    description="Role for Lambda function with S3 access",
    read_only=True  # Set to False for read-write access
)

# Create a Lambda role with full access to AWS services
full_access_role = lambda_roles.create_lambda_full_access_role(
    role_name="lambda-full-access-role",
    description="Role for Lambda function with full access"
)

# Update an existing Lambda role with S3 access
lambda_roles.update_lambda_role_s3_access(
    role_name="lambda-execution-role",
    s3_bucket_arns=["arn:aws:s3:::example-bucket"],
    policy_name="s3-access-policy",
    read_only=False
)
```

## Testing

The library includes comprehensive unit tests using pytest and moto for mocking AWS services.

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/
```

## API Documentation

### AWSSession

- `__init__(region_name=None, profile_name=None, assume_role_arn=None, session_name="aws-lib-3-session", **kwargs)`: Initialize an AWS session.
- `session`: Property that returns a boto3 Session.
- `get_client(service_name)`: Get a boto3 client for the specified service.
- `get_resource(service_name)`: Get a boto3 resource for the specified service.

### PolicyManager

- `__init__(aws_session=None)`: Initialize the PolicyManager.
- `create_policy(policy_name, policy_document, description=None, path="/", tags=None)`: Create an IAM policy.
- `get_policy(policy_arn)`: Get an IAM policy by ARN.
- `get_policy_version(policy_arn, version_id)`: Get a specific version of an IAM policy.
- `list_policies(scope="Local", only_attached=False, path_prefix=None, max_items=100)`: List IAM policies.
- `update_policy(policy_arn, policy_document, set_as_default=True)`: Update an IAM policy.
- `list_policy_versions(policy_arn)`: List all versions of an IAM policy.
- `delete_policy_version(policy_arn, version_id)`: Delete a version of an IAM policy.
- `delete_policy(policy_arn)`: Delete an IAM policy.
- `attach_policy_to_role(policy_arn, role_name)`: Attach an IAM policy to a role.
- `detach_policy_from_role(policy_arn, role_name)`: Detach an IAM policy from a role.
- `list_attached_role_policies(role_name, path_prefix=None)`: List policies attached to a role.

### RoleManager

- `__init__(aws_session=None)`: Initialize the RoleManager.
- `create_role(role_name, assume_role_policy_document, description=None, path="/", max_session_duration=3600, permissions_boundary=None, tags=None)`: Create an IAM role.
- `get_role(role_name)`: Get an IAM role by name.
- `list_roles(path_prefix=None, max_items=100)`: List IAM roles.
- `update_role(role_name, description=None, max_session_duration=None)`: Update an IAM role.
- `update_assume_role_policy(role_name, assume_role_policy_document)`: Update the trust policy of an IAM role.
- `delete_role(role_name)`: Delete an IAM role.
- `attach_role_policy(role_name, policy_arn)`: Attach an IAM policy to a role.
- `detach_role_policy(role_name, policy_arn)`: Detach an IAM policy from a role.
- `list_attached_role_policies(role_name, path_prefix=None)`: List policies attached to a role.
- `list_role_policies(role_name)`: List inline policies for a role.
- `put_role_policy(role_name, policy_name, policy_document)`: Add or update an inline policy for a role.
- `get_role_policy(role_name, policy_name)`: Get an inline policy for a role.
- `delete_role_policy(role_name, policy_name)`: Delete an inline policy from a role.

### LambdaRoles

- `__init__(aws_session=None)`: Initialize the LambdaRoles utility.
- `create_lambda_execution_role(role_name, description=None, path="/", tags=None)`: Create an IAM role for Lambda execution.
- `create_lambda_s3_access_role(role_name, s3_bucket_arns, description=None, path="/", tags=None, read_only=False)`: Create an IAM role for Lambda functions to access S3 buckets.
- `create_lambda_full_access_role(role_name, description=None, path="/", tags=None)`: Create an IAM role with full Lambda access permissions.
- `update_lambda_role_s3_access(role_name, s3_bucket_arns, policy_name=None, read_only=False)`: Update an existing Lambda role with S3 access permissions.

## License

MIT
