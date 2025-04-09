#!/usr/bin/env python3
"""
Test script for Redis integration in the APT Detection System.

This script generates test alerts, stores them in Redis, and retrieves them
to verify that the Redis integration is working correctly.
"""

import logging
import random
import sys
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import Redis integration
from real_time_detection import redis_integration

def create_test_alerts(count=5):
    """Create test alerts for Redis storage."""
    alerts = []
    
    # Entity names for variation
    entities = ['host1', 'host2', 'host3', 'workstation4', 'server5']
    
    # Severity levels
    severities = ['Critical', 'High', 'Medium', 'Low']
    
    # Source types
    source_types = ['kafka', 'connector', 'behavioral_analytics', 'test']
    
    # Current time
    now = datetime.now()
    
    for i in range(count):
        # Create a test alert
        alert = {
            'entity': random.choice(entities),
            'timestamp': (now - timedelta(minutes=random.randint(0, 60))).isoformat(),
            'severity': random.choice(severities),
            'prediction_score': round(random.uniform(0.5, 0.99), 2),
            'features': {
                'network_traffic_volume_mean': round(random.uniform(0.1, 0.9), 2),
                'number_of_logins_mean': round(random.uniform(0.1, 0.9), 2),
                'number_of_failed_logins_mean': round(random.uniform(0.1, 0.9), 2),
                'cpu_usage_mean': round(random.uniform(0.1, 0.9), 2),
                'memory_usage_mean': round(random.uniform(0.1, 0.9), 2)
            },
            'source': {
                'type': random.choice(source_types),
                'timestamp': (now - timedelta(minutes=random.randint(0, 60))).isoformat()
            },
            'message': f'Test alert {i+1}'
        }
        
        alerts.append(alert)
    
    return alerts

def main():
    """Test Redis integration."""
    logger.info("Testing Redis integration")
    
    # Initialize Redis
    if not redis_integration.initialize():
        logger.error("Failed to initialize Redis. Make sure Redis is installed and running.")
        logger.error("You can install Redis with: sudo apt-get install redis-server")
        logger.error("You can start Redis with: sudo service redis-server start")
        sys.exit(1)
    
    # Clear existing alerts
    redis_integration.clear_alerts()
    logger.info("Cleared existing alerts from Redis")
    
    # Create test alerts
    test_alerts = create_test_alerts(10)
    logger.info(f"Created {len(test_alerts)} test alerts")
    
    # Store alerts in Redis
    for alert in test_alerts:
        success = redis_integration.store_alert(alert)
        if not success:
            logger.error(f"Failed to store alert for entity {alert['entity']}")
    
    # Get alert count
    count = redis_integration.get_alert_count()
    logger.info(f"Redis contains {count} alerts")
    
    # Get alerts from Redis
    alerts = redis_integration.get_alerts()
    logger.info(f"Retrieved {len(alerts)} alerts from Redis")
    
    # Print alerts
    for i, alert in enumerate(alerts):
        logger.info(f"Alert {i+1}:")
        logger.info(f"  Entity: {alert.get('entity', 'Unknown')}")
        logger.info(f"  Severity: {alert.get('severity', 'Unknown')}")
        logger.info(f"  Timestamp: {alert.get('timestamp', 'Unknown')}")
        logger.info(f"  Source: {alert.get('source', {}).get('type', 'Unknown')}")
        logger.info(f"  Message: {alert.get('message', 'No message')}")
    
    logger.info("Redis integration test completed successfully")

if __name__ == "__main__":
    main()
