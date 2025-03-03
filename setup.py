from setuptools import setup, find_packages

setup(
    name="aws_lib_3",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.28.0",
        "botocore>=1.31.0",
    ],
    python_requires=">=3.8",
    author="Jian Huang",
    author_email="your.email@example.com",
    description="AWS IAM role and policy management library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jianhuanggo/aws_lib_3",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
