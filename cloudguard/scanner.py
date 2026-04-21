#!/usr/bin/env python3
"""
AWS misconfiguration scanner.
Checks S3, EC2 security groups, IAM, RDS.
"""

import boto3
from tabulate import tabulate

class AWSMisconfigScanner:
    def __init__(self, profile_name=None):
        """Initialize AWS session using named profile or default credentials."""
        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        self.s3 = session.client('s3')
        self.ec2 = session.client('ec2')
        self.iam = session.client('iam')
        self.rds = session.client('rds')
        self.findings = []

    def scan_s3_buckets(self):
        """Find publicly accessible S3 buckets."""
        print("[*] Scanning S3 buckets...")
        try:
            buckets = self.s3.list_buckets()['Buckets']
            for bucket in buckets:
                name = bucket['Name']
                try:
                    acl = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acl['Grants']:
                        uri = grant.get('Grantee', {}).get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            permission = grant['Permission']
                            self.findings.append({
                                'service': 'S3',
                                'resource': name,
                                'issue': f"Public {permission} access",
                                'severity': 'HIGH'
                            })
                            break
                except Exception as e:
                    # Bucket may not exist or permissions issue
                    pass
        except Exception as e:
            print(f"[-] S3 scan failed: {e}")

    def scan_security_groups(self):
        """Find security groups with 0.0.0.0/0 on risky ports."""
        print("[*] Scanning EC2 security groups...")
        risky_ports = [22, 3389, 80, 443, 8080, 3306, 5432, 27017]
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                group_id = sg['GroupId']
                group_name = sg.get('GroupName', '')
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            if from_port in risky_ports or (from_port <= 22 <= to_port):
                                self.findings.append({
                                    'service': 'EC2',
                                    'resource': f"{group_name} ({group_id})",
                                    'issue': f"Open to world on port {from_port}-{to_port}",
                                    'severity': 'CRITICAL'
                                })
        except Exception as e:
            print(f"[-] EC2 scan failed: {e}")

    def scan_iam_mfa(self):
        """Find IAM users without MFA enabled."""
        print("[*] Scanning IAM users for MFA...")
        try:
            users = self.iam.list_users()['Users']
            for user in users:
                username = user['UserName']
                # Check MFA devices
                mfa = self.iam.list_mfa_devices(UserName=username)['MFADevices']
                if not mfa:
                    self.findings.append({
                        'service': 'IAM',
                        'resource': username,
                        'issue': "No MFA device assigned",
                        'severity': 'MEDIUM'
                    })
        except Exception as e:
            print(f"[-] IAM scan failed: {e}")

    def scan_rds_encryption(self):
        """Find unencrypted RDS instances."""
        print("[*] Scanning RDS instances...")
        try:
            instances = self.rds.describe_db_instances()['DBInstances']
            for db in instances:
                if not db.get('StorageEncrypted', False):
                    self.findings.append({
                        'service': 'RDS',
                        'resource': db['DBInstanceIdentifier'],
                        'issue': "Storage not encrypted",
                        'severity': 'MEDIUM'
                    })
        except Exception as e:
            print(f"[-] RDS scan failed (may not be enabled): {e}")

    def run_all_scans(self):
        """Execute all scan modules."""
        print("\n[+] Starting CloudGuard AWS misconfiguration scan...\n")
        self.scan_s3_buckets()
        self.scan_security_groups()
        self.scan_iam_mfa()
        self.scan_rds_encryption()
        return self.findings

    def generate_report(self, output_format='table'):
        """Return findings as formatted table or JSON."""
        if not self.findings:
            return "[+] No misconfigurations found. Your AWS account looks secure!\n"
        
        if output_format == 'json':
            import json
            return json.dumps(self.findings, indent=2)
        else:
            # Table format
            table_data = [[f['service'], f['resource'], f['issue'], f['severity']] for f in self.findings]
            headers = ['Service', 'Resource', 'Issue', 'Severity']
            return tabulate(table_data, headers=headers, tablefmt='grid')
