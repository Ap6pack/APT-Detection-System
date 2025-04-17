"""
MITRE ATT&CK Mapping Module

This module provides functionality to map detection results to MITRE ATT&CK
Tactics, Techniques, and Procedures (TTPs).
"""

import json
import os
import yaml
import logging
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
    'network_traffic_volume_mean': ['T1071', 'T1105', 'T1041', 'T1095', 'T1571'],
    'number_of_logins_mean': ['T1078', 'T1021', 'T1133'],
    'number_of_failed_logins_mean': ['T1078', 'T1110', 'T1187', 'T1212'],
    'number_of_accessed_files_mean': ['T1005', 'T1083', 'T1213', 'T1530', 'T1537'],
    'number_of_email_sent_mean': ['T1566', 'T1114', 'T1048', 'T1534'],
    'cpu_usage_mean': ['T1486', 'T1496', 'T1489', 'T1490', 'T1561'],
    'memory_usage_mean': ['T1055', 'T1559', 'T1562', 'T1497'],
    'disk_io_mean': ['T1005', 'T1560', 'T1486', 'T1074', 'T1115'],
    'network_latency_mean': ['T1071', 'T1095', 'T1571', 'T1572'],
    'number_of_processes_mean': ['T1057', 'T1059', 'T1106', 'T1204', 'T1569']
}

# Define threshold values for anomaly detection
# These thresholds determine when a feature value is considered anomalous
ANOMALY_THRESHOLDS = {
    'network_traffic_volume_mean': 0.7,
    'number_of_logins_mean': 0.6,
    'number_of_failed_logins_mean': 0.5,
    'number_of_accessed_files_mean': 0.6,
    'number_of_email_sent_mean': 0.7,
    'cpu_usage_mean': 0.7,
    'memory_usage_mean': 0.6,
    'disk_io_mean': 0.6,
    'network_latency_mean': 0.5,
    'number_of_processes_mean': 0.6
}

# Define event type to technique mappings for behavioral analytics
# This helps map specific event types to relevant techniques
EVENT_TYPE_TECHNIQUE_MAPPING = {
    'process': ['T1059', 'T1106', 'T1204', 'T1569'],
    'network_connection': ['T1071', 'T1095', 'T1571'],
    'authentication': ['T1078', 'T1110'],
    'file': ['T1005', 'T1083', 'T1074'],
    'dns_query': ['T1071', 'T1189', 'T1598'],
    'service': ['T1543', 'T1569'],
    'login': ['T1078', 'T1021']
}

# Define entity type to tactic mappings
# This helps prioritize tactics based on the entity type
ENTITY_TYPE_TACTIC_MAPPING = {
    'host': ['TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0007'],
    'user': ['TA0001', 'TA0003', 'TA0004', 'TA0006', 'TA0008'],
    'network': ['TA0001', 'TA0011', 'TA0010', 'TA0008']
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
                               prediction_score: float,
                               event_type: str = None,
                               entity_type: str = None) -> List[str]:
    """
    Map feature values to potential MITRE ATT&CK techniques based on anomaly detection.
    
    Args:
        features: Dictionary of feature names and their values
        prediction_score: The overall prediction score from the model
        event_type: Optional event type for more specific mapping
        entity_type: Optional entity type for more specific mapping
        
    Returns:
        List of technique IDs that match the anomalous features
    """
    if prediction_score < 0.5:  # If prediction score is low, no need to map techniques
        return []
    
    techniques = set()
    
    # Map based on anomalous features
    for feature_name, value in features.items():
        if feature_name in FEATURE_TECHNIQUE_MAPPING and value >= ANOMALY_THRESHOLDS.get(feature_name, 0.6):
            techniques.update(FEATURE_TECHNIQUE_MAPPING[feature_name])
    
    # Add techniques based on event type if available
    if event_type and event_type in EVENT_TYPE_TECHNIQUE_MAPPING:
        techniques.update(EVENT_TYPE_TECHNIQUE_MAPPING[event_type])
    
    # If we have an entity type, prioritize techniques based on relevant tactics
    if entity_type and entity_type in ENTITY_TYPE_TACTIC_MAPPING:
        relevant_tactics = ENTITY_TYPE_TACTIC_MAPPING[entity_type]
        prioritized_techniques = set()
        
        # Add techniques that are associated with relevant tactics
        for technique_id in techniques:
            if technique_id in TECHNIQUES:
                tactic_ids = TECHNIQUES[technique_id]['tactic_ids']
                if any(tactic_id in relevant_tactics for tactic_id in tactic_ids):
                    prioritized_techniques.add(technique_id)
        
        # If we found prioritized techniques, use those
        # Otherwise, fall back to all identified techniques
        if prioritized_techniques:
            return list(prioritized_techniques)
    
    return list(techniques)

def enrich_alert_with_mitre_attack(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert with MITRE ATT&CK TTPs.
    
    Args:
        alert: The alert dictionary to enrich
        
    Returns:
        Enriched alert with MITRE ATT&CK information
    """
    # Add debug logging
    logging.info(f"Enriching alert with MITRE ATT&CK: {alert.get('entity')}, detection_type: {alert.get('detection_type')}")
    
    features = alert.get('features', {})
    prediction_score = alert.get('prediction_score', 0)
    detection_type = alert.get('detection_type', '')
    entity = alert.get('entity', 'unknown')
    entity_type = alert.get('entity_type', 'host')
    
    # Extract event type if available (especially for behavioral analytics alerts)
    event_type = None
    if 'event_type' in alert:
        event_type = alert['event_type']
        logging.info(f"Found event_type in alert: {event_type}")
    
    # Map features to techniques with additional context
    technique_ids = map_features_to_techniques(
        features, 
        prediction_score,
        event_type=event_type,
        entity_type=entity_type
    )
    
    # Get detailed information for each technique
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
    
    # Add confidence level for behavioral analytics alerts
    if detection_type == 'behavioral_analytics':
        # Calculate confidence based on anomaly score and number of anomalous features
        anomalous_features_count = sum(1 for _, value in features.items() 
                                      if value >= ANOMALY_THRESHOLDS.get(_, 0.6))
        confidence = min(0.9, (prediction_score * 0.7) + (anomalous_features_count * 0.05))
        
        enriched_alert['mitre_attack']['confidence'] = round(confidence, 2)
    
    # Log the result
    if techniques:
        logging.info(f"Identified {len(techniques)} MITRE ATT&CK techniques for {entity}")
        for technique in techniques[:3]:  # Log first 3 techniques
            logging.info(f"- {technique['id']}: {technique['name']}")
    else:
        logging.info(f"No MITRE ATT&CK techniques identified for {entity}")
    
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
