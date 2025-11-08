"""
Synthetic AWS Security Event Generator
Generates realistic CloudTrail events and GuardDuty findings with labels
for testing AWS Security Copilot multi-agent system
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict
import uuid

class SyntheticAWSSecurityGenerator:
    """Generate labeled synthetic AWS security events"""
    
    def __init__(self):
        self.attack_patterns = {
            "unauthorized_access": {
                "severity": "HIGH",
                "description": "Unauthorized IAM access attempt",
                "indicators": ["AssumeRole", "GetSessionToken", "unknown IP"]
            },
            "privilege_escalation": {
                "severity": "CRITICAL",
                "description": "IAM privilege escalation attempt",
                "indicators": ["AttachUserPolicy", "PutUserPolicy", "CreateAccessKey"]
            },
            "data_exfiltration": {
                "severity": "HIGH",
                "description": "Potential data exfiltration",
                "indicators": ["GetObject", "ListBucket", "large data transfer"]
            },
            "cryptomining": {
                "severity": "MEDIUM",
                "description": "EC2 instance cryptocurrency mining",
                "indicators": ["unusual CPU usage", "mining pool connection"]
            },
            "reconnaissance": {
                "severity": "LOW",
                "description": "Network reconnaissance activity",
                "indicators": ["DescribeInstances", "DescribeSecurityGroups", "scanning"]
            },
            "backdoor": {
                "severity": "CRITICAL",
                "description": "Backdoor establishment attempt",
                "indicators": ["AuthorizeSecurityGroupIngress", "port 22/3389 open", "unknown IP"]
            }
        }
        
        self.benign_patterns = {
            "normal_access": {
                "description": "Normal IAM user access",
                "actions": ["DescribeInstances", "GetObject", "PutObject"]
            },
            "automated_backup": {
                "description": "Automated backup process",
                "actions": ["CreateSnapshot", "CopySnapshot", "CreateBackup"]
            },
            "monitoring": {
                "description": "CloudWatch monitoring",
                "actions": ["PutMetricData", "GetMetricStatistics"]
            }
        }
    
    def generate_cloudtrail_event(self, attack_type: str = None, is_malicious: bool = False) -> Dict:
        """Generate a single CloudTrail event"""
        
        event_time = datetime.utcnow() - timedelta(
            hours=random.randint(0, 48),
            minutes=random.randint(0, 59)
        )
        
        if is_malicious and attack_type:
            pattern = self.attack_patterns[attack_type]
            event = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::123456789012:user/suspicious-user-{random.randint(1,100)}",
                    "accountId": "123456789012",
                    "userName": f"suspicious-user-{random.randint(1,100)}"
                },
                "eventTime": event_time.isoformat() + "Z",
                "eventSource": self._get_event_source(attack_type),
                "eventName": random.choice(pattern["indicators"]),
                "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
                "sourceIPAddress": self._generate_suspicious_ip(),
                "userAgent": "aws-cli/2.13.0",
                "errorCode": random.choice(["AccessDenied", None]),
                "requestParameters": self._generate_request_params(attack_type),
                "responseElements": None,
                "requestID": str(uuid.uuid4()),
                "eventID": str(uuid.uuid4()),
                "readOnly": False,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "123456789012",
                # LABEL
                "label": {
                    "is_malicious": True,
                    "attack_type": attack_type,
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "ground_truth": "THREAT"
                }
            }
        else:
            # Benign event
            pattern_key = random.choice(list(self.benign_patterns.keys()))
            pattern = self.benign_patterns[pattern_key]
            
            event = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(100000000000, 999999999999)}",
                    "arn": f"arn:aws:iam::123456789012:user/legitimate-user-{random.randint(1,50)}",
                    "accountId": "123456789012",
                    "userName": f"legitimate-user-{random.randint(1,50)}"
                },
                "eventTime": event_time.isoformat() + "Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": random.choice(pattern["actions"]),
                "awsRegion": random.choice(["us-east-1", "us-west-2"]),
                "sourceIPAddress": self._generate_legitimate_ip(),
                "userAgent": "aws-cli/2.13.0",
                "requestParameters": {},
                "responseElements": {"success": True},
                "requestID": str(uuid.uuid4()),
                "eventID": str(uuid.uuid4()),
                "readOnly": True,
                "eventType": "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": "123456789012",
                # LABEL
                "label": {
                    "is_malicious": False,
                    "attack_type": None,
                    "severity": "INFO",
                    "description": pattern["description"],
                    "ground_truth": "BENIGN"
                }
            }
        
        return event
    
    def generate_guardduty_finding(self, attack_type: str) -> Dict:
        """Generate a GuardDuty finding with label"""
        
        pattern = self.attack_patterns[attack_type]
        
        finding = {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "partition": "aws",
            "id": str(uuid.uuid4()),
            "arn": f"arn:aws:guardduty:us-east-1:123456789012:detector/12abc34d567e8fa901bc2d34e56789f0/finding/{uuid.uuid4()}",
            "type": self._get_guardduty_type(attack_type),
            "resource": {
                "resourceType": random.choice(["Instance", "AccessKey", "S3Bucket"]),
                "instanceDetails": {
                    "instanceId": f"i-{random.randint(100000000, 999999999):x}",
                    "instanceType": "t2.micro",
                    "launchTime": (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z"
                }
            },
            "service": {
                "serviceName": "guardduty",
                "detectorId": f"12abc34d567e8fa901bc2d34e56789f0",
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": random.choice(pattern["indicators"]),
                        "callerType": "Remote IP",
                        "remoteIpDetails": {
                            "ipAddressV4": self._generate_suspicious_ip(),
                            "organization": {"asn": "16509", "asnOrg": "AMAZON-02"},
                            "country": {"countryName": random.choice(["Russia", "China", "Unknown"])}
                        }
                    }
                },
                "eventFirstSeen": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
                "eventLastSeen": datetime.utcnow().isoformat() + "Z",
                "archived": False,
                "count": random.randint(5, 50)
            },
            "severity": self._severity_to_number(pattern["severity"]),
            "createdAt": datetime.utcnow().isoformat() + "Z",
            "updatedAt": datetime.utcnow().isoformat() + "Z",
            "title": pattern["description"],
            "description": f"Detected {pattern['description'].lower()} from suspicious IP address.",
            # LABEL
            "label": {
                "is_malicious": True,
                "attack_type": attack_type,
                "severity": pattern["severity"],
                "description": pattern["description"],
                "ground_truth": "THREAT",
                "recommended_action": self._get_remediation(attack_type)
            }
        }
        
        return finding
    
    def generate_dataset(self, 
                        num_cloudtrail: int = 100, 
                        num_guardduty: int = 50,
                        malicious_ratio: float = 0.3) -> Dict:
        """Generate a complete labeled dataset"""
        
        dataset = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "num_cloudtrail_events": num_cloudtrail,
                "num_guardduty_findings": num_guardduty,
                "malicious_ratio": malicious_ratio,
                "attack_types": list(self.attack_patterns.keys())
            },
            "cloudtrail_events": [],
            "guardduty_findings": []
        }
        
        # Generate CloudTrail events
        num_malicious_ct = int(num_cloudtrail * malicious_ratio)
        
        for i in range(num_malicious_ct):
            attack_type = random.choice(list(self.attack_patterns.keys()))
            event = self.generate_cloudtrail_event(attack_type=attack_type, is_malicious=True)
            dataset["cloudtrail_events"].append(event)
        
        for i in range(num_cloudtrail - num_malicious_ct):
            event = self.generate_cloudtrail_event(is_malicious=False)
            dataset["cloudtrail_events"].append(event)
        
        # Generate GuardDuty findings (all malicious by nature)
        for i in range(num_guardduty):
            attack_type = random.choice(list(self.attack_patterns.keys()))
            finding = self.generate_guardduty_finding(attack_type)
            dataset["guardduty_findings"].append(finding)
        
        # Shuffle to mix malicious and benign
        random.shuffle(dataset["cloudtrail_events"])
        
        return dataset
    
    # Helper methods
    def _get_event_source(self, attack_type: str) -> str:
        sources = {
            "unauthorized_access": "sts.amazonaws.com",
            "privilege_escalation": "iam.amazonaws.com",
            "data_exfiltration": "s3.amazonaws.com",
            "cryptomining": "ec2.amazonaws.com",
            "reconnaissance": "ec2.amazonaws.com",
            "backdoor": "ec2.amazonaws.com"
        }
        return sources.get(attack_type, "ec2.amazonaws.com")
    
    def _get_guardduty_type(self, attack_type: str) -> str:
        types = {
            "unauthorized_access": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "privilege_escalation": "PrivilegeEscalation:IAMUser/AnomalousPermissions",
            "data_exfiltration": "Exfiltration:S3/AnomalousBehavior",
            "cryptomining": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "reconnaissance": "Recon:EC2/PortProbeUnprotectedPort",
            "backdoor": "Backdoor:EC2/C&CActivity.B!DNS"
        }
        return types.get(attack_type, "UnauthorizedAccess:EC2/TorClient")
    
    def _generate_suspicious_ip(self) -> str:
        """Generate IP from suspicious ranges"""
        suspicious_ranges = [
            f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",  # Russia
            f"123.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",  # China
            f"82.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"    # Tor exit
        ]
        return random.choice(suspicious_ranges)
    
    def _generate_legitimate_ip(self) -> str:
        """Generate IP from AWS/corporate ranges"""
        return f"52.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def _generate_request_params(self, attack_type: str) -> Dict:
        params = {
            "privilege_escalation": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            "backdoor": {"groupId": "sg-12345", "ipPermissions": [{"fromPort": 22, "toPort": 22}]},
            "data_exfiltration": {"bucketName": "sensitive-data-bucket", "key": "confidential.zip"}
        }
        return params.get(attack_type, {})
    
    def _severity_to_number(self, severity: str) -> float:
        mapping = {"LOW": 2.0, "MEDIUM": 5.0, "HIGH": 7.5, "CRITICAL": 9.0}
        return mapping.get(severity, 5.0)
    
    def _get_remediation(self, attack_type: str) -> str:
        remediations = {
            "unauthorized_access": "Revoke IAM credentials and rotate access keys",
            "privilege_escalation": "Remove excessive IAM policies and review permissions",
            "data_exfiltration": "Enable S3 bucket versioning and restrict access",
            "cryptomining": "Terminate instance and review security groups",
            "reconnaissance": "Block source IP and enable VPC Flow Logs",
            "backdoor": "Remove security group rule and isolate instance"
        }
        return remediations.get(attack_type, "Investigate and remediate")


def main():
    """Generate and save synthetic dataset"""
    
    generator = SyntheticAWSSecurityGenerator()
    
    # Generate dataset
    print("Generating synthetic AWS security dataset...")
    dataset = generator.generate_dataset(
        num_cloudtrail=500,      # 500 CloudTrail events
        num_guardduty=200,       # 200 GuardDuty findings
        malicious_ratio=0.3      # 30% malicious CloudTrail events
    )
    
    # Save to files
    with open('synthetic_cloudtrail_events.json', 'w') as f:
        json.dump(dataset['cloudtrail_events'], f, indent=2)
    
    with open('synthetic_guardduty_findings.json', 'w') as f:
        json.dump(dataset['guardduty_findings'], f, indent=2)
    
    with open('synthetic_dataset_full.json', 'w') as f:
        json.dump(dataset, f, indent=2)
    
    # Generate summary statistics
    malicious_ct = sum(1 for e in dataset['cloudtrail_events'] if e['label']['is_malicious'])
    benign_ct = len(dataset['cloudtrail_events']) - malicious_ct
    
    print("\n" + "="*60)
    print("DATASET GENERATION COMPLETE")
    print("="*60)
    print(f"\nCloudTrail Events:")
    print(f"  - Total: {len(dataset['cloudtrail_events'])}")
    print(f"  - Malicious: {malicious_ct}")
    print(f"  - Benign: {benign_ct}")
    
    print(f"\nGuardDuty Findings:")
    print(f"  - Total: {len(dataset['guardduty_findings'])}")
    
    print(f"\nAttack Types:")
    attack_counts = {}
    for event in dataset['cloudtrail_events']:
        if event['label']['is_malicious']:
            attack_type = event['label']['attack_type']
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
    
    for attack_type, count in sorted(attack_counts.items()):
        print(f"  - {attack_type}: {count}")
    
    print(f"\nFiles saved:")
    print("  - synthetic_cloudtrail_events.json")
    print("  - synthetic_guardduty_findings.json")
    print("  - synthetic_dataset_full.json")
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
