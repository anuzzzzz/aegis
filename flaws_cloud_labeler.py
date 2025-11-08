"""
Flaws Cloud Dataset Auto-Labeler
Automatically labels unlabeled AWS security datasets using heuristics
"""

import json
import re
from typing import Dict, List
from datetime import datetime

class FlawsCloudLabeler:
    """Auto-label AWS security events from unlabeled datasets"""
    
    def __init__(self):
        # Malicious indicators
        self.malicious_patterns = {
            'unauthorized_access': {
                'actions': ['AssumeRole', 'GetSessionToken', 'GetCredentials'],
                'error_codes': ['AccessDenied', 'UnauthorizedAccess'],
                'ip_patterns': [r'^(?!52\.)', r'^185\.', r'^123\.'],  # Non-AWS IPs
                'unusual_times': ['00:', '01:', '02:', '03:', '04:', '05:'],  # Midnight-5am
                'severity': 'HIGH'
            },
            'privilege_escalation': {
                'actions': [
                    'AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey',
                    'CreateUser', 'AddUserToGroup', 'AttachRolePolicy',
                    'PutRolePolicy', 'UpdateAssumeRolePolicy'
                ],
                'policy_indicators': ['AdministratorAccess', 'FullAccess', '*'],
                'severity': 'CRITICAL'
            },
            'data_exfiltration': {
                'actions': ['GetObject', 'ListBucket', 'ListObjects', 'CopyObject'],
                'high_volume': 50,  # More than 50 GetObject calls
                'large_size': 1000000000,  # 1GB+
                'severity': 'HIGH'
            },
            'reconnaissance': {
                'actions': [
                    'DescribeInstances', 'DescribeSecurityGroups', 'DescribeSnapshots',
                    'DescribeVolumes', 'ListBuckets', 'GetBucketAcl', 'GetBucketPolicy'
                ],
                'rapid_succession': 5,  # 5+ describe actions in short time
                'severity': 'LOW'
            },
            'backdoor': {
                'actions': [
                    'AuthorizeSecurityGroupIngress', 'CreateSecurityGroup',
                    'ModifyInstanceAttribute', 'CreateUser', 'CreateAccessKey'
                ],
                'port_indicators': [22, 3389, 4444, 31337],  # SSH, RDP, backdoor ports
                'ip_indicators': ['0.0.0.0/0', '0.0.0.0'],
                'severity': 'CRITICAL'
            },
            'cryptomining': {
                'actions': ['RunInstances', 'ModifyInstanceAttribute'],
                'instance_types': ['p3', 'p4', 'g4', 'g5'],  # GPU instances
                'region_anomaly': ['us-east-1', 'us-west-2'],  # If unusual for user
                'severity': 'MEDIUM'
            },
            'resource_hijacking': {
                'actions': ['RunInstances', 'CreateVolume', 'CreateSnapshot'],
                'high_count': 10,  # Creating 10+ instances
                'severity': 'MEDIUM'
            }
        }
        
        # Known benign patterns
        self.benign_patterns = {
            'monitoring': ['GetMetricStatistics', 'PutMetricData', 'DescribeAlarms'],
            'backup': ['CreateSnapshot', 'CopySnapshot', 'CreateBackup'],
            'deployment': ['UpdateStack', 'CreateChangeSet', 'ExecuteChangeSet'],
            'read_only': ['Describe', 'List', 'Get'],
        }
    
    def label_cloudtrail_event(self, event: Dict) -> Dict:
        """Add label to a CloudTrail event"""
        
        # Initialize label
        label = {
            'is_malicious': False,
            'attack_type': None,
            'severity': 'INFO',
            'confidence': 'low',
            'indicators': [],
            'ground_truth': 'BENIGN',
            'labeling_method': 'heuristic'
        }
        
        event_name = event.get('eventName', '')
        source_ip = event.get('sourceIPAddress', '')
        error_code = event.get('errorCode')
        event_time = event.get('eventTime', '')
        user_agent = event.get('userAgent', '')
        request_params = event.get('requestParameters', {})
        
        # Check for malicious patterns
        for attack_type, pattern in self.malicious_patterns.items():
            indicators = []
            confidence_score = 0
            
            # Check action matches
            if event_name in pattern.get('actions', []):
                indicators.append(f"action:{event_name}")
                confidence_score += 30
            
            # Check error codes
            if error_code in pattern.get('error_codes', []):
                indicators.append(f"error:{error_code}")
                confidence_score += 20
            
            # Check IP patterns
            for ip_pattern in pattern.get('ip_patterns', []):
                if re.search(ip_pattern, source_ip):
                    indicators.append(f"suspicious_ip:{source_ip}")
                    confidence_score += 25
            
            # Check unusual times
            hour = event_time[11:13] if len(event_time) > 13 else ''
            if hour + ':' in pattern.get('unusual_times', []):
                indicators.append(f"unusual_time:{hour}:00")
                confidence_score += 15
            
            # Check policy indicators (privilege escalation)
            if attack_type == 'privilege_escalation':
                policy_arn = request_params.get('policyArn', '')
                for indicator in pattern.get('policy_indicators', []):
                    if indicator in policy_arn:
                        indicators.append(f"dangerous_policy:{indicator}")
                        confidence_score += 40
            
            # Check port indicators (backdoor)
            if attack_type == 'backdoor':
                ip_permissions = request_params.get('ipPermissions', [])
                for perm in ip_permissions:
                    from_port = perm.get('fromPort')
                    if from_port in pattern.get('port_indicators', []):
                        indicators.append(f"backdoor_port:{from_port}")
                        confidence_score += 35
                    
                    cidr = perm.get('ipRanges', [{}])[0].get('cidrIp', '')
                    if cidr in pattern.get('ip_indicators', []):
                        indicators.append(f"open_to_internet:{cidr}")
                        confidence_score += 30
            
            # If confidence is high enough, label as this attack type
            if confidence_score >= 40:
                label['is_malicious'] = True
                label['attack_type'] = attack_type
                label['severity'] = pattern['severity']
                label['indicators'] = indicators
                label['ground_truth'] = 'THREAT'
                
                if confidence_score >= 70:
                    label['confidence'] = 'high'
                elif confidence_score >= 50:
                    label['confidence'] = 'medium'
                else:
                    label['confidence'] = 'low'
                
                break
        
        # Check for benign patterns
        if not label['is_malicious']:
            for pattern_name, actions in self.benign_patterns.items():
                if any(action in event_name for action in actions):
                    label['description'] = f"Legitimate {pattern_name} activity"
                    label['confidence'] = 'high'
                    break
        
        # Add label to event
        event['label'] = label
        return event
    
    def label_guardduty_finding(self, finding: Dict) -> Dict:
        """Add enhanced label to a GuardDuty finding"""
        
        finding_type = finding.get('type', '')
        severity = finding.get('severity', 5.0)
        
        # Parse attack type from finding type
        attack_type = self._parse_attack_type(finding_type)
        severity_text = self._severity_number_to_text(severity)
        
        label = {
            'is_malicious': True,  # GuardDuty findings are always threats
            'attack_type': attack_type,
            'severity': severity_text,
            'confidence': 'high',  # GuardDuty is authoritative
            'indicators': [finding_type],
            'ground_truth': 'THREAT',
            'labeling_method': 'guardduty',
            'description': finding.get('description', ''),
            'recommended_action': self._get_remediation(attack_type)
        }
        
        finding['label'] = label
        return finding
    
    def label_dataset(self, input_file: str, output_file: str, data_type: str = 'cloudtrail'):
        """Label an entire dataset"""
        
        print(f"Loading dataset from {input_file}...")
        
        try:
            with open(input_file) as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error loading file: {e}")
            return
        
        # Ensure data is a list
        if isinstance(data, dict):
            if 'Records' in data:
                events = data['Records']
            else:
                print("Unknown data format")
                return
        else:
            events = data
        
        print(f"Found {len(events)} events to label...")
        
        # Label each event
        labeled_events = []
        stats = {'malicious': 0, 'benign': 0, 'attack_types': {}}
        
        for idx, event in enumerate(events):
            if data_type == 'cloudtrail':
                labeled_event = self.label_cloudtrail_event(event.copy())
            elif data_type == 'guardduty':
                labeled_event = self.label_guardduty_finding(event.copy())
            else:
                print(f"Unknown data type: {data_type}")
                return
            
            labeled_events.append(labeled_event)
            
            # Update stats
            if labeled_event['label']['is_malicious']:
                stats['malicious'] += 1
                attack_type = labeled_event['label']['attack_type']
                stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
            else:
                stats['benign'] += 1
            
            if (idx + 1) % 100 == 0:
                print(f"  Labeled {idx + 1}/{len(events)} events...")
        
        # Save labeled dataset
        output_data = {
            'metadata': {
                'labeled_at': datetime.utcnow().isoformat() + 'Z',
                'total_events': len(labeled_events),
                'malicious': stats['malicious'],
                'benign': stats['benign'],
                'labeling_method': 'heuristic',
                'confidence_note': 'Labels generated using heuristic patterns. Manual review recommended.'
            },
            'events': labeled_events
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        # Print summary
        print("\n" + "="*60)
        print("LABELING COMPLETE")
        print("="*60)
        print(f"\nTotal Events: {len(labeled_events)}")
        print(f"Malicious: {stats['malicious']} ({stats['malicious']/len(labeled_events)*100:.1f}%)")
        print(f"Benign: {stats['benign']} ({stats['benign']/len(labeled_events)*100:.1f}%)")
        
        if stats['attack_types']:
            print("\nAttack Types Detected:")
            for attack_type, count in sorted(stats['attack_types'].items()):
                print(f"  - {attack_type}: {count}")
        
        print(f"\nLabeled dataset saved to: {output_file}")
        print("="*60)
    
    def _parse_attack_type(self, finding_type: str) -> str:
        """Parse attack type from GuardDuty finding type"""
        
        if 'PrivilegeEscalation' in finding_type:
            return 'privilege_escalation'
        elif 'Exfiltration' in finding_type:
            return 'data_exfiltration'
        elif 'CryptoCurrency' in finding_type or 'Bitcoin' in finding_type:
            return 'cryptomining'
        elif 'Recon' in finding_type:
            return 'reconnaissance'
        elif 'Backdoor' in finding_type:
            return 'backdoor'
        elif 'UnauthorizedAccess' in finding_type:
            return 'unauthorized_access'
        else:
            return 'unknown'
    
    def _severity_number_to_text(self, severity: float) -> str:
        """Convert numeric severity to text"""
        
        if severity >= 8.0:
            return 'CRITICAL'
        elif severity >= 6.0:
            return 'HIGH'
        elif severity >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_remediation(self, attack_type: str) -> str:
        """Get remediation action for attack type"""
        
        remediations = {
            'unauthorized_access': 'Revoke IAM credentials and rotate access keys',
            'privilege_escalation': 'Remove excessive IAM policies and review permissions',
            'data_exfiltration': 'Enable S3 bucket versioning and restrict access',
            'cryptomining': 'Terminate instance and review security groups',
            'reconnaissance': 'Block source IP and enable VPC Flow Logs',
            'backdoor': 'Remove security group rule and isolate instance'
        }
        return remediations.get(attack_type, 'Investigate and remediate')


def main():
    """Label the Flaws Cloud dataset"""
    
    labeler = FlawsCloudLabeler()
    
    # Example usage
    print("Flaws Cloud Dataset Auto-Labeler")
    print("="*60)
    print("\nUsage:")
    print("1. Place your unlabeled dataset in 'flaws_cloud_raw.json'")
    print("2. Run this script")
    print("3. Get labeled dataset in 'flaws_cloud_labeled.json'\n")
    
    input_file = 'flaws_cloud_raw.json'
    output_file = 'flaws_cloud_labeled.json'
    
    import os
    if os.path.exists(input_file):
        labeler.label_dataset(
            input_file=input_file,
            output_file=output_file,
            data_type='cloudtrail'
        )
    else:
        print(f"❌ File not found: {input_file}")
        print("\nPlease download Flaws Cloud dataset and save as 'flaws_cloud_raw.json'")
        print("Then run this script again.")


if __name__ == "__main__":
    main()
