"""
MITRE ATT&CK Mapping Module

This module provides functionality to map detection results to MITRE ATT&CK
Tactics, Techniques, and Procedures (TTPs).
"""

import json
import os
import yaml
from typing import Dict, List, Any, Optional

# Define MITRE ATT&CK tactics
TACTICS = {
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0010': 'Exfiltration',
    'TA0011': 'Command and Control',
    'TA0040': 'Impact',
    'TA0042': 'Resource Development',
    'TA0043': 'Reconnaissance'
}

# Define common APT techniques with their MITRE ATT&CK IDs
TECHNIQUES = {
    'T1059': {'name': 'Command and Scripting Interpreter', 'tactic_ids': ['TA0002']},
    'T1078': {'name': 'Valid Accounts', 'tactic_ids': ['TA0001', 'TA0003', 'TA0004', 'TA0005']},
    'T1053': {'name': 'Scheduled Task/Job', 'tactic_ids': ['TA0002', 'TA0003', 'TA0004']},
    'T1082': {'name': 'System Information Discovery', 'tactic_ids': ['TA0007']},
    'T1083': {'name': 'File and Directory Discovery', 'tactic_ids': ['TA0007']},
    'T1046': {'name': 'Network Service Scanning', 'tactic_ids': ['TA0007']},
    'T1057': {'name': 'Process Discovery', 'tactic_ids': ['TA0007']},
    'T1021': {'name': 'Remote Services', 'tactic_ids': ['TA0008']},
    'T1560': {'name': 'Archive Collected Data', 'tactic_ids': ['TA0009']},
    'T1005': {'name': 'Data from Local System', 'tactic_ids': ['TA0009']},
    'T1071': {'name': 'Application Layer Protocol', 'tactic_ids': ['TA0011']},
    'T1105': {'name': 'Ingress Tool Transfer', 'tactic_ids': ['TA0011']},
    'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic_ids': ['TA0010']},
    'T1486': {'name': 'Data Encrypted for Impact', 'tactic_ids': ['TA0040']},
    'T1566': {'name': 'Phishing', 'tactic_ids': ['TA0001']},
    'T1190': {'name': 'Exploit Public-Facing Application', 'tactic_ids': ['TA0001']},
    'T1133': {'name': 'External Remote Services', 'tactic_ids': ['TA0001']},
    'T1110': {'name': 'Brute Force', 'tactic_ids': ['TA0006']},
    'T1496': {'name': 'Resource Hijacking', 'tactic_ids': ['TA0040']},
    'T1055': {'name': 'Process Injection', 'tactic_ids': ['TA0004', 'TA0005']},
    'T1559': {'name': 'Inter-Process Communication', 'tactic_ids': ['TA0002']},
    'T1095': {'name': 'Non-Application Layer Protocol', 'tactic_ids': ['TA0011']},
    'T1114': {'name': 'Email Collection', 'tactic_ids': ['TA0009']}
}

# Define feature-to-technique mappings
# This maps behavioral features to potential MITRE ATT&CK techniques
FEATURE_TECHNIQUE_MAPPING = {
    'network_traffic_volume_mean': ['T1071', 'T1105', 'T1041'],
    'number_of_logins_mean': ['T1078'],
    'number_of_failed_logins_mean': ['T1078', 'T1110'],
    'number_of_accessed_files_mean': ['T1005', 'T1083'],
    'number_of_email_sent_mean': ['T1566', 'T1114'],
    'cpu_usage_mean': ['T1486', 'T1496'],
    'memory_usage_mean': ['T1055', 'T1559'],
    'disk_io_mean': ['T1005', 'T1560', 'T1486'],
    'network_latency_mean': ['T1071', 'T1095'],
    'number_of_processes_mean': ['T1057', 'T1059']
}

# Define threshold values for anomaly detection
# These thresholds determine when a feature value is considered anomalous
ANOMALY_THRESHOLDS = {
    'network_traffic_volume_mean': 0.8,
    'number_of_logins_mean': 0.7,
    'number_of_failed_logins_mean': 0.6,
    'number_of_accessed_files_mean': 0.7,
    'number_of_email_sent_mean': 0.8,
    'cpu_usage_mean': 0.8,
    'memory_usage_mean': 0.7,
    'disk_io_mean': 0.7,
    'network_latency_mean': 0.6,
    'number_of_processes_mean': 0.7
}

def load_config():
    """Load configuration from config.yaml file."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

def get_technique_details(technique_id: str) -> Dict[str, Any]:
    """
    Get details for a specific MITRE ATT&CK technique.
    
    Args:
        technique_id: The MITRE ATT&CK technique ID (e.g., 'T1059')
        
    Returns:
        Dictionary containing technique details
    """
    if technique_id not in TECHNIQUES:
        return {
            'id': technique_id,
            'name': 'Unknown Technique',
            'tactics': []
        }
    
    technique = TECHNIQUES[technique_id]
    tactics = [{'id': tactic_id, 'name': TACTICS.get(tactic_id, 'Unknown')} 
               for tactic_id in technique['tactic_ids']]
    
    return {
        'id': technique_id,
        'name': technique['name'],
        'tactics': tactics
    }

def map_features_to_techniques(features: Dict[str, float], 
                               prediction_score: float) -> List[str]:
    """
    Map feature values to potential MITRE ATT&CK techniques based on anomaly detection.
    
    Args:
        features: Dictionary of feature names and their values
        prediction_score: The overall prediction score from the model
        
    Returns:
        List of technique IDs that match the anomalous features
    """
    if prediction_score < 0.5:  # If prediction score is low, no need to map techniques
        return []
    
    techniques = set()
    
    for feature_name, value in features.items():
        if feature_name in FEATURE_TECHNIQUE_MAPPING and value >= ANOMALY_THRESHOLDS.get(feature_name, 0.7):
            techniques.update(FEATURE_TECHNIQUE_MAPPING[feature_name])
    
    return list(techniques)

def enrich_alert_with_mitre_attack(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert with MITRE ATT&CK TTPs.
    
    Args:
        alert: The alert dictionary to enrich
        
    Returns:
        Enriched alert with MITRE ATT&CK information
    """
    features = alert.get('features', {})
    prediction_score = alert.get('prediction_score', 0)
    
    technique_ids = map_features_to_techniques(features, prediction_score)
    techniques = [get_technique_details(tid) for tid in technique_ids]
    
    # Group techniques by tactics
    tactics = {}
    for technique in techniques:
        for tactic in technique['tactics']:
            tactic_id = tactic['id']
            if tactic_id not in tactics:
                tactics[tactic_id] = {
                    'id': tactic_id,
                    'name': tactic['name'],
                    'techniques': []
                }
            tactics[tactic_id]['techniques'].append({
                'id': technique['id'],
                'name': technique['name']
            })
    
    # Add MITRE ATT&CK information to the alert
    enriched_alert = alert.copy()
    enriched_alert['mitre_attack'] = {
        'techniques': techniques,
        'tactics': list(tactics.values())
    }
    
    return enriched_alert

def generate_alert(prediction_results: Dict[str, Any], 
                   features: Dict[str, float],
                   threshold: float = 0.7) -> Optional[Dict[str, Any]]:
    """
    Generate an alert with MITRE ATT&CK TTPs based on prediction results.
    
    Args:
        prediction_results: Dictionary of model predictions
        features: Dictionary of feature values
        threshold: Threshold for generating an alert
        
    Returns:
        Alert dictionary with MITRE ATT&CK information, or None if no alert
    """
    # Calculate overall prediction score (average of all model predictions)
    scores = []
    for model_name, predictions in prediction_results.items():
        if isinstance(predictions, list) and len(predictions) > 0:
            scores.append(float(predictions[0]))
    
    if not scores:
        return None
    
    prediction_score = sum(scores) / len(scores)
    
    # If prediction score is below threshold, don't generate an alert
    if prediction_score < threshold:
        return None
    
    # Create base alert
    alert = {
        'prediction_score': prediction_score,
        'features': features,
        'severity': _calculate_severity(prediction_score),
        'models': {model: float(pred[0]) if isinstance(pred, list) and len(pred) > 0 else 0 
                  for model, pred in prediction_results.items()}
    }
    
    # Enrich alert with MITRE ATT&CK information
    return enrich_alert_with_mitre_attack(alert)

def _calculate_severity(score: float) -> str:
    """Calculate severity based on prediction score."""
    if score >= 0.9:
        return 'Critical'
    elif score >= 0.8:
        return 'High'
    elif score >= 0.7:
        return 'Medium'
    elif score >= 0.5:
        return 'Low'
    else:
        return 'Informational'

# Testing the MITRE ATT&CK mapping
if __name__ == "__main__":
    # Sample features
    sample_features = {
        'network_traffic_volume_mean': 0.9,
        'number_of_logins_mean': 0.3,
        'number_of_failed_logins_mean': 0.8,
        'number_of_accessed_files_mean': 0.2,
        'number_of_email_sent_mean': 0.1,
        'cpu_usage_mean': 0.9,
        'memory_usage_mean': 0.4,
        'disk_io_mean': 0.3,
        'network_latency_mean': 0.2,
        'number_of_processes_mean': 0.9
    }
    
    # Sample prediction results
    sample_predictions = {
        'lgbm_model': [0.85],
        'bilstm_model': [0.78]
    }
    
    # Generate alert
    alert = generate_alert(sample_predictions, sample_features)
    
    if alert:
        print(json.dumps(alert, indent=2))
    else:
        print("No alert generated")
