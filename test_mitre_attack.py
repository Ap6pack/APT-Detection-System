#!/usr/bin/env python3
"""
Test script for MITRE ATT&CK integration in the APT Detection System.
This script simulates an APT detection and displays the MITRE ATT&CK TTPs.
"""

import json
import numpy as np
import logging
from real_time_detection.prediction_engine import run as run_prediction_engine

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def simulate_apt_detection():
    """Simulate an APT detection with MITRE ATT&CK TTPs."""
    logger.info("Simulating APT detection with MITRE ATT&CK TTPs...")
    
    # Sample feature names
    feature_names = [
        'network_traffic_volume_mean',
        'number_of_logins_mean',
        'number_of_failed_logins_mean',
        'number_of_accessed_files_mean',
        'number_of_email_sent_mean',
        'cpu_usage_mean',
        'memory_usage_mean',
        'disk_io_mean',
        'network_latency_mean',
        'number_of_processes_mean'
    ]
    
    # Create sample data with high values for specific features
    # This simulates an APT with high network traffic, failed logins, CPU usage, and process creation
    data = np.array([
        0.95,  # network_traffic_volume_mean (high)
        0.4,   # number_of_logins_mean
        0.85,  # number_of_failed_logins_mean (high)
        0.3,   # number_of_accessed_files_mean
        0.2,   # number_of_email_sent_mean
        0.9,   # cpu_usage_mean (high)
        0.5,   # memory_usage_mean
        0.4,   # disk_io_mean
        0.3,   # network_latency_mean
        0.8    # number_of_processes_mean (high)
    ]).reshape(1, -1)
    
    # Create a mock model for testing
    class MockModel:
        def predict(self, data):
            return [0.85]  # High prediction score
    
    # Initialize models
    models = {'lgbm_model': MockModel(), 'bilstm_model': MockModel()}
    
    # Run prediction with MITRE ATT&CK mapping
    predict_fn = run_prediction_engine(models, use_saved_models=False)
    result = predict_fn(data, feature_names)
    
    # Display results
    logger.info(f"Prediction scores: {result['predictions']}")
    
    if result['alert']:
        logger.info(f"Alert generated with severity: {result['alert']['severity']}")
        logger.info(f"Prediction score: {result['alert']['prediction_score']}")
        
        if 'mitre_attack' in result['alert']:
            techniques = result['alert']['mitre_attack']['techniques']
            logger.info(f"MITRE ATT&CK techniques identified: {len(techniques)}")
            
            # Display techniques and tactics
            for technique in techniques:
                logger.info(f"Technique: {technique['id']} - {technique['name']}")
                for tactic in technique['tactics']:
                    logger.info(f"  Tactic: {tactic['id']} - {tactic['name']}")
            
            # Display tactics with their techniques
            logger.info("\nTactics and their techniques:")
            for tactic in result['alert']['mitre_attack']['tactics']:
                logger.info(f"Tactic: {tactic['id']} - {tactic['name']}")
                for technique in tactic['techniques']:
                    logger.info(f"  Technique: {technique['id']} - {technique['name']}")
        
        # Save alert to JSON file for inspection
        with open('sample_alert.json', 'w') as f:
            json.dump(result['alert'], f, indent=2)
        logger.info("Alert saved to sample_alert.json")
    else:
        logger.info("No alert generated")

if __name__ == "__main__":
    simulate_apt_detection()
