"""
Attack Scenario Generator
Creates realistic multi-step attack sequences for testing
the AWS Security Copilot's forensic analysis capabilities
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict
import random

class AttackScenarioGenerator:
    """Generate realistic attack scenarios with temporal sequences"""
    
    def __init__(self):
        self.scenarios = {
            "apt_exfiltration": {
                "name": "Advanced Persistent Threat - Data Exfiltration",
                "steps": [
                    {
                        "step": 1,
                        "description": "Initial reconnaissance",
                        "delay_minutes": 0,
                        "events": [
                            {"type": "cloudtrail", "action": "DescribeInstances"},
                            {"type": "cloudtrail", "action": "DescribeSecurityGroups"},
                            {"type": "cloudtrail", "action": "ListBuckets"}
                        ]
                    },
                    {
                        "step": 2,
                        "description": "Credential compromise",
                        "delay_minutes": 30,
                        "events": [
                            {"type": "guardduty", "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"},
                            {"type": "cloudtrail", "action": "GetSessionToken"}
                        ]
                    },
                    {
                        "step": 3,
                        "description": "Privilege escalation",
                        "delay_minutes": 15,
                        "events": [
                            {"type": "cloudtrail", "action": "AttachUserPolicy"},
                            {"type": "cloudtrail", "action": "CreateAccessKey"},
                            {"type": "guardduty", "finding_type": "PrivilegeEscalation:IAMUser/AnomalousPermissions"}
                        ]
                    },
                    {
                        "step": 4,
                        "description": "Establish backdoor",
                        "delay_minutes": 10,
                        "events": [
                            {"type": "cloudtrail", "action": "AuthorizeSecurityGroupIngress"},
                            {"type": "guardduty", "finding_type": "Backdoor:EC2/C&CActivity.B!DNS"}
                        ]
                    },
                    {
                        "step": 5,
                        "description": "Data exfiltration",
                        "delay_minutes": 60,
                        "events": [
                            {"type": "cloudtrail", "action": "GetObject", "count": 150},
                            {"type": "cloudtrail", "action": "ListObjectsV2", "count": 20},
                            {"type": "guardduty", "finding_type": "Exfiltration:S3/AnomalousBehavior"}
                        ]
                    }
                ],
                "severity": "CRITICAL",
                "expected_detection_time": "< 2 minutes",
                "expected_response": "Isolate instance, revoke credentials, block IP, enable S3 versioning"
            },
            
            "cryptominer_deployment": {
                "name": "Cryptocurrency Mining Deployment",
                "steps": [
                    {
                        "step": 1,
                        "description": "Compromised credentials used",
                        "delay_minutes": 0,
                        "events": [
                            {"type": "guardduty", "finding_type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"}
                        ]
                    },
                    {
                        "step": 2,
                        "description": "Launch high-CPU instances",
                        "delay_minutes": 5,
                        "events": [
                            {"type": "cloudtrail", "action": "RunInstances", "count": 10},
                            {"type": "cloudtrail", "action": "ModifyInstanceAttribute"}
                        ]
                    },
                    {
                        "step": 3,
                        "description": "Mining activity detected",
                        "delay_minutes": 30,
                        "events": [
                            {"type": "guardduty", "finding_type": "CryptoCurrency:EC2/BitcoinTool.B!DNS"}
                        ]
                    }
                ],
                "severity": "MEDIUM",
                "expected_detection_time": "< 5 minutes",
                "expected_response": "Terminate instances, revoke credentials, review CloudTrail for source"
            },
            
            "insider_threat": {
                "name": "Insider Threat - Data Theft",
                "steps": [
                    {
                        "step": 1,
                        "description": "Unusual time access",
                        "delay_minutes": 0,
                        "events": [
                            {"type": "cloudtrail", "action": "AssumeRole", "timestamp": "03:00 AM"}
                        ]
                    },
                    {
                        "step": 2,
                        "description": "Bulk data download",
                        "delay_minutes": 10,
                        "events": [
                            {"type": "cloudtrail", "action": "GetObject", "count": 500},
                            {"type": "guardduty", "finding_type": "Exfiltration:S3/AnomalousBehavior"}
                        ]
                    },
                    {
                        "step": 3,
                        "description": "Cover tracks",
                        "delay_minutes": 5,
                        "events": [
                            {"type": "cloudtrail", "action": "DeleteLogStream"},
                            {"type": "cloudtrail", "action": "StopLogging"}
                        ]
                    }
                ],
                "severity": "HIGH",
                "expected_detection_time": "< 3 minutes",
                "expected_response": "Suspend user, preserve logs, initiate forensic investigation"
            },
            
            "ransomware_preparation": {
                "name": "Ransomware Deployment Preparation",
                "steps": [
                    {
                        "step": 1,
                        "description": "Initial access",
                        "delay_minutes": 0,
                        "events": [
                            {"type": "guardduty", "finding_type": "UnauthorizedAccess:EC2/TorClient"}
                        ]
                    },
                    {
                        "step": 2,
                        "description": "Lateral movement",
                        "delay_minutes": 20,
                        "events": [
                            {"type": "cloudtrail", "action": "DescribeInstances"},
                            {"type": "guardduty", "finding_type": "Recon:EC2/PortProbeUnprotectedPort"}
                        ]
                    },
                    {
                        "step": 3,
                        "description": "Disable backups",
                        "delay_minutes": 15,
                        "events": [
                            {"type": "cloudtrail", "action": "DeleteSnapshot"},
                            {"type": "cloudtrail", "action": "DeleteBackupVault"},
                            {"type": "cloudtrail", "action": "DisableBackup"}
                        ]
                    },
                    {
                        "step": 4,
                        "description": "Establish persistence",
                        "delay_minutes": 10,
                        "events": [
                            {"type": "cloudtrail", "action": "CreateUser"},
                            {"type": "cloudtrail", "action": "AttachUserPolicy"},
                            {"type": "guardduty", "finding_type": "Backdoor:EC2/C&CActivity.B!DNS"}
                        ]
                    }
                ],
                "severity": "CRITICAL",
                "expected_detection_time": "< 1 minute",
                "expected_response": "Emergency isolation, snapshot all volumes, revoke all credentials"
            }
        }
    
    def generate_scenario(self, scenario_name: str, start_time: datetime = None) -> Dict:
        """Generate a complete attack scenario with timestamps"""
        
        if scenario_name not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        scenario = self.scenarios[scenario_name]
        start_time = start_time or datetime.utcnow()
        
        events = []
        current_time = start_time
        
        for step in scenario["steps"]:
            # Add delay between steps
            current_time += timedelta(minutes=step["delay_minutes"])
            
            for event in step["events"]:
                event_count = event.get("count", 1)
                
                for i in range(event_count):
                    event_data = {
                        "scenario_name": scenario_name,
                        "scenario_step": step["step"],
                        "step_description": step["description"],
                        "timestamp": (current_time + timedelta(seconds=i*2)).isoformat() + "Z",
                        "event_type": event["type"],
                        "severity": scenario["severity"],
                        "label": {
                            "is_attack": True,
                            "scenario": scenario_name,
                            "step": step["step"],
                            "expected_detection_time": scenario["expected_detection_time"],
                            "expected_response": scenario["expected_response"]
                        }
                    }
                    
                    # Add type-specific details
                    if event["type"] == "cloudtrail":
                        event_data["action"] = event["action"]
                        event_data["source_ip"] = self._generate_attacker_ip()
                    elif event["type"] == "guardduty":
                        event_data["finding_type"] = event["finding_type"]
                    
                    events.append(event_data)
        
        return {
            "scenario_metadata": {
                "name": scenario["name"],
                "scenario_id": scenario_name,
                "severity": scenario["severity"],
                "start_time": start_time.isoformat() + "Z",
                "num_steps": len(scenario["steps"]),
                "total_events": len(events),
                "expected_detection_time": scenario["expected_detection_time"],
                "expected_response": scenario["expected_response"]
            },
            "events": events
        }
    
    def generate_all_scenarios(self) -> Dict:
        """Generate all attack scenarios"""
        
        all_scenarios = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "num_scenarios": len(self.scenarios),
                "scenario_names": list(self.scenarios.keys())
            },
            "scenarios": []
        }
        
        start_time = datetime.utcnow() - timedelta(hours=24)
        
        for scenario_name in self.scenarios.keys():
            scenario_data = self.generate_scenario(scenario_name, start_time)
            all_scenarios["scenarios"].append(scenario_data)
            
            # Stagger scenarios
            start_time += timedelta(hours=6)
        
        return all_scenarios
    
    def generate_test_cases(self) -> List[Dict]:
        """Generate test cases for system evaluation"""
        
        test_cases = []
        
        for scenario_name, scenario in self.scenarios.items():
            test_case = {
                "test_id": f"TC_{scenario_name.upper()}",
                "scenario_name": scenario_name,
                "description": scenario["name"],
                "severity": scenario["severity"],
                "success_criteria": {
                    "detection_time": scenario["expected_detection_time"],
                    "must_detect_steps": [1, len(scenario["steps"])],  # Must detect first and last
                    "expected_actions": scenario["expected_response"]
                },
                "evaluation_metrics": {
                    "true_positive_required": True,
                    "false_positive_allowed": False,
                    "response_time_threshold": "30 seconds",
                    "remediation_accuracy": "100%"
                }
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_attacker_ip(self) -> str:
        """Generate attacker IP address"""
        suspicious_ranges = [
            f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            f"123.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        ]
        return random.choice(suspicious_ranges)


def main():
    """Generate attack scenarios for testing"""
    
    generator = AttackScenarioGenerator()
    
    print("Generating attack scenarios...")
    
    # Generate all scenarios
    all_scenarios = generator.generate_all_scenarios()
    
    with open('attack_scenarios.json', 'w') as f:
        json.dump(all_scenarios, f, indent=2)
    
    # Generate test cases
    test_cases = generator.generate_test_cases()
    
    with open('test_cases.json', 'w') as f:
        json.dump(test_cases, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("ATTACK SCENARIO GENERATION COMPLETE")
    print("="*60)
    
    print(f"\nTotal Scenarios: {len(all_scenarios['scenarios'])}")
    
    for scenario in all_scenarios['scenarios']:
        metadata = scenario['scenario_metadata']
        print(f"\n{metadata['name']}:")
        print(f"  - Severity: {metadata['severity']}")
        print(f"  - Steps: {metadata['num_steps']}")
        print(f"  - Events: {metadata['total_events']}")
        print(f"  - Expected Detection: {metadata['expected_detection_time']}")
    
    print(f"\nTest Cases: {len(test_cases)}")
    
    print(f"\nFiles saved:")
    print("  - attack_scenarios.json")
    print("  - test_cases.json")
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
