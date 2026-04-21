# 🔒 CloudGuard

**AWS misconfiguration scanner – detect public S3 buckets, open security groups, IAM without MFA, and unencrypted RDS.**

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![AWS](https://img.shields.io/badge/AWS-boto3-orange)

## 🎯 Purpose

CloudGuard helps cloud security engineers and pentesters quickly identify:
- Publicly readable/writable S3 buckets
- Security groups allowing `0.0.0.0/0` on risky ports (SSH, RDP, DB ports)
- IAM users without MFA enabled
- Unencrypted RDS database instances

## 📦 Installation

```bash
git clone https://github.com/alitalhahere/CloudGuard.git
cd CloudGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
## 🔐 AWS Credentials Setup

You need AWS credentials with read-only permissions for the services you want to scan.

Option 1: AWS CLI configured (recommended)
```bash
aws configure   # set access key, secret key, region
```
Option 2: Named profile

Create ~/.aws/credentials:
```bash
[cloudguard]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```
Then use --profile cloudguard.

Option 3: Environment variables
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
```

## 🚀 Usage

Basic scan (uses default credentials):
```bash
python run.py
```

With a specific AWS profile:
```bash
python run.py --profile myprofile
```

JSON output (for SIEM or automation):
```bash
python run.py --ouput json
```

## 🧪 Testing with a Free Tier AWS Account

Create an AWS account (free tier includes S3, EC2, IAM, RDS).

Create a test S3 bucket and make it public.

Create a security group with 0.0.0.0/0 on SSH.

Run CloudGuard to see findings.

## 🛣️ Roadmap
S3 public access detection

Security group open to world

IAM MFA status

RDS encryption check

S3 bucket encryption check

Unused IAM roles/keys

CloudTrail logging status

Remediation suggestions (auto-fix flag)

## 🤝 Contributing
Pull requests welcome. Please ensure you add tests for new scanners.

## 👤 Author
Ali Talha – [LinkedIn](https://www.linkedin.com/in/imalitalha)
