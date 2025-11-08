"""
Dataset Validator
Validates synthetic AWS security datasets for quality and consistency
"""

import json
from datetime import datetime
from collections import Counter
from typing import Dict, List

class DatasetValidator:
    """Validate synthetic security datasets"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.stats = {}
    
    def validate_cloudtrail_events(self, filepath: str) -> bool:
        """Validate CloudTrail events dataset"""
        
        print(f"\n{'='*60}")
        print(f"Validating CloudTrail Events: {filepath}")
        print(f"{'='*60}\n")
        
        try:
            with open(filepath) as f:
                events = json.load(f)
        except Exception as e:
            self.errors.append(f"Failed to load file: {e}")
            return False
        
        if not isinstance(events, list):
            self.errors.append("Data must be a list of events")
            return False
        
        # Validation checks
        self._check_required_fields(events, "CloudTrail")
        self._check_labels(events)
        self._check_timestamps(events)
        self._check_duplicates(events)
        self._check_severity_distribution(events)
        self._calculate_statistics(events, "CloudTrail")
        
        return len(self.errors) == 0
    
    def validate_guardduty_findings(self, filepath: str) -> bool:
        """Validate GuardDuty findings dataset"""
        
        print(f"\n{'='*60}")
        print(f"Validating GuardDuty Findings: {filepath}")
        print(f"{'='*60}\n")
        
        try:
            with open(filepath) as f:
                findings = json.load(f)
        except Exception as e:
            self.errors.append(f"Failed to load file: {e}")
            return False
        
        if not isinstance(findings, list):
            self.errors.append("Data must be a list of findings")
            return False
        
        # Validation checks
        self._check_required_fields(findings, "GuardDuty")
        self._check_labels(findings)
        self._check_guardduty_specific(findings)
        self._calculate_statistics(findings, "GuardDuty")
        
        return len(self.errors) == 0
    
    def validate_scenarios(self, filepath: str) -> bool:
        """Validate attack scenarios"""
        
        print(f"\n{'='*60}")
        print(f"Validating Attack Scenarios: {filepath}")
        print(f"{'='*60}\n")
        
        try:
            with open(filepath) as f:
                data = json.load(f)
        except Exception as e:
            self.errors.append(f"Failed to load file: {e}")
            return False
        
        scenarios = data.get('scenarios', [])
        
        for idx, scenario in enumerate(scenarios):
            self._validate_scenario(scenario, idx)
        
        return len(self.errors) == 0
    
    def _check_required_fields(self, events: List[Dict], event_type: str):
        """Check for required fields"""
        
        required_cloudtrail = ['eventTime', 'eventSource', 'eventName', 'sourceIPAddress', 'label']
        required_guardduty = ['id', 'type', 'severity', 'label']
        
        required = required_cloudtrail if event_type == "CloudTrail" else required_guardduty
        
        for idx, event in enumerate(events):
            missing = [field for field in required if field not in event]
            if missing:
                self.errors.append(f"Event {idx}: Missing fields: {missing}")
    
    def _check_labels(self, events: List[Dict]):
        """Check label validity"""
        
        required_label_fields = ['is_malicious', 'severity', 'ground_truth']
        
        for idx, event in enumerate(events):
            if 'label' not in event:
                continue
            
            label = event['label']
            
            # Check required label fields
            missing = [field for field in required_label_fields if field not in label]
            if missing:
                self.errors.append(f"Event {idx}: Label missing fields: {missing}")
            
            # Check severity values
            if 'severity' in label:
                valid_severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if label['severity'] not in valid_severities:
                    self.errors.append(f"Event {idx}: Invalid severity: {label['severity']}")
            
            # Check ground_truth values
            if 'ground_truth' in label:
                valid_gt = ['BENIGN', 'THREAT']
                if label['ground_truth'] not in valid_gt:
                    self.errors.append(f"Event {idx}: Invalid ground_truth: {label['ground_truth']}")
            
            # Check consistency
            if label.get('is_malicious') and label.get('ground_truth') == 'BENIGN':
                self.errors.append(f"Event {idx}: Inconsistent label (malicious but BENIGN)")
    
    def _check_timestamps(self, events: List[Dict]):
        """Check timestamp validity"""
        
        timestamps = []
        
        for idx, event in enumerate(events):
            if 'eventTime' in event:
                try:
                    dt = datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
                    timestamps.append(dt)
                except Exception as e:
                    self.errors.append(f"Event {idx}: Invalid timestamp: {e}")
        
        if timestamps:
            # Check if timestamps are reasonably recent (within last 90 days)
            oldest = min(timestamps)
            newest = max(timestamps)
            
            if (datetime.now().astimezone() - oldest).days > 90:
                self.warnings.append(f"Oldest event is {(datetime.now().astimezone() - oldest).days} days old")
            
            # Check temporal ordering
            sorted_timestamps = sorted(timestamps)
            if timestamps != sorted_timestamps:
                self.warnings.append("Events are not in chronological order")
    
    def _check_duplicates(self, events: List[Dict]):
        """Check for duplicate event IDs"""
        
        ids = []
        for event in events:
            if 'eventID' in event:
                ids.append(event['eventID'])
            elif 'id' in event:
                ids.append(event['id'])
        
        duplicates = [id for id, count in Counter(ids).items() if count > 1]
        
        if duplicates:
            self.errors.append(f"Found {len(duplicates)} duplicate event IDs")
    
    def _check_severity_distribution(self, events: List[Dict]):
        """Check severity distribution is realistic"""
        
        severities = [e['label']['severity'] for e in events if 'label' in e and 'severity' in e['label']]
        severity_counts = Counter(severities)
        
        total = len(severities)
        if total == 0:
            return
        
        # Check for unrealistic distributions
        critical_pct = severity_counts.get('CRITICAL', 0) / total * 100
        
        if critical_pct > 50:
            self.warnings.append(f"Unusually high CRITICAL events: {critical_pct:.1f}%")
    
    def _check_guardduty_specific(self, findings: List[Dict]):
        """Check GuardDuty-specific fields"""
        
        for idx, finding in enumerate(findings):
            # Check severity is numeric
            if 'severity' in finding:
                if not isinstance(finding['severity'], (int, float)):
                    self.errors.append(f"Finding {idx}: Severity must be numeric")
                elif not (0 <= finding['severity'] <= 10):
                    self.errors.append(f"Finding {idx}: Severity must be 0-10")
            
            # Check finding type format
            if 'type' in finding:
                if ':' not in finding['type']:
                    self.warnings.append(f"Finding {idx}: Type doesn't follow GuardDuty format")
    
    def _validate_scenario(self, scenario: Dict, idx: int):
        """Validate attack scenario"""
        
        required_metadata = ['name', 'scenario_id', 'severity']
        
        if 'scenario_metadata' not in scenario:
            self.errors.append(f"Scenario {idx}: Missing metadata")
            return
        
        metadata = scenario['scenario_metadata']
        missing = [field for field in required_metadata if field not in metadata]
        if missing:
            self.errors.append(f"Scenario {idx}: Missing metadata fields: {missing}")
        
        if 'events' not in scenario:
            self.errors.append(f"Scenario {idx}: Missing events")
            return
        
        events = scenario['events']
        
        # Check temporal ordering
        timestamps = []
        for event in events:
            if 'timestamp' in event:
                try:
                    dt = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    pass
        
        if timestamps != sorted(timestamps):
            self.errors.append(f"Scenario {idx}: Events not in chronological order")
    
    def _calculate_statistics(self, events: List[Dict], event_type: str):
        """Calculate dataset statistics"""
        
        stats = {
            'total_events': len(events),
            'malicious': 0,
            'benign': 0,
            'attack_types': Counter(),
            'severities': Counter()
        }
        
        for event in events:
            if 'label' not in event:
                continue
            
            label = event['label']
            
            if label.get('is_malicious'):
                stats['malicious'] += 1
                if 'attack_type' in label and label['attack_type']:
                    stats['attack_types'][label['attack_type']] += 1
            else:
                stats['benign'] += 1
            
            if 'severity' in label:
                stats['severities'][label['severity']] += 1
        
        self.stats[event_type] = stats
    
    def print_report(self):
        """Print validation report"""
        
        print("\n" + "="*60)
        print("VALIDATION REPORT")
        print("="*60)
        
        # Errors
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  - {error}")
        else:
            print("\n✅ No errors found!")
        
        # Warnings
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")
        else:
            print("\n✅ No warnings!")
        
        # Statistics
        if self.stats:
            print("\n📊 DATASET STATISTICS:")
            for event_type, stats in self.stats.items():
                print(f"\n{event_type}:")
                print(f"  Total: {stats['total_events']}")
                print(f"  Malicious: {stats['malicious']} ({stats['malicious']/stats['total_events']*100:.1f}%)")
                print(f"  Benign: {stats['benign']} ({stats['benign']/stats['total_events']*100:.1f}%)")
                
                if stats['attack_types']:
                    print(f"\n  Attack Types:")
                    for attack_type, count in stats['attack_types'].most_common():
                        print(f"    - {attack_type}: {count}")
                
                if stats['severities']:
                    print(f"\n  Severities:")
                    for severity, count in sorted(stats['severities'].items()):
                        print(f"    - {severity}: {count}")
        
        print("\n" + "="*60)
        
        # Overall result
        if not self.errors:
            print("\n✅ DATASET IS VALID - Ready for experiments!")
        else:
            print(f"\n❌ DATASET HAS {len(self.errors)} ERRORS - Please fix before use")
        
        print("="*60 + "\n")


def main():
    """Run validation on all generated datasets"""
    
    validator = DatasetValidator()
    
    # Validate CloudTrail events
    if os.path.exists('synthetic_cloudtrail_events.json'):
        validator.validate_cloudtrail_events('synthetic_cloudtrail_events.json')
    
    # Validate GuardDuty findings
    if os.path.exists('synthetic_guardduty_findings.json'):
        validator.validate_guardduty_findings('synthetic_guardduty_findings.json')
    
    # Validate attack scenarios
    if os.path.exists('attack_scenarios.json'):
        validator.validate_scenarios('attack_scenarios.json')
    
    # Print report
    validator.print_report()


if __name__ == "__main__":
    import os
    main()
