#!/usr/bin/env python3
"""
Redis-based storage module for APT Detection System.

This module provides a robust storage mechanism for alerts using Redis,
which allows for sharing data between different processes and provides
persistence. This is a production-ready solution for handling live data.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable

try:
    import redis
except ImportError:
    print("Redis package not installed. Please install it with: pip install redis")
    raise

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Redis connection settings
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set this if your Redis server requires authentication
REDIS_KEY_PREFIX = 'apt_detection:'
ALERTS_KEY = f'{REDIS_KEY_PREFIX}alerts'

# Redis client
redis_client = None

def get_redis_client():
    """
    Get or create a Redis client.
    
    Returns:
        Redis client instance
    """
    global redis_client
    
    if redis_client is None:
        try:
            redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                decode_responses=True  # Automatically decode responses to strings
            )
            # Test connection
            redis_client.ping()
            logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            logger.error("Make sure Redis is installed and running.")
            logger.error("You can install Redis with: sudo apt-get install redis-server")
            logger.error("You can start Redis with: sudo service redis-server start")
            raise
    
    return redis_client

def initialize():
    """
    Initialize the Redis storage.
    This ensures the Redis connection is established.
    """
    logger.info("Initializing Redis storage")
    
    # Get Redis client
    client = get_redis_client()
    
    # Check if alerts list exists
    if not client.exists(ALERTS_KEY):
        # Create empty list
        client.delete(ALERTS_KEY)
        logger.info(f"Created empty alerts list in Redis with key: {ALERTS_KEY}")
    else:
        # Get count of alerts
        count = client.llen(ALERTS_KEY)
        logger.info(f"Redis storage initialized with {count} existing alerts")

def get_alerts() -> List[Dict[str, Any]]:
    """
    Get all alerts from Redis storage.
    
    Returns:
        List of alert dictionaries
    """
    client = get_redis_client()
    
    # Get all alerts from Redis list
    alerts_json = client.lrange(ALERTS_KEY, 0, -1)
    
    # Parse JSON strings to dictionaries
    alerts = []
    for alert_json in alerts_json:
        try:
            alert = json.loads(alert_json)
            alerts.append(alert)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing alert JSON: {e}")
    
    logger.info(f"Retrieved {len(alerts)} alerts from Redis")
    return alerts

def add_alert(alert: Dict[str, Any], max_alerts: int = 1000) -> bool:
    """
    Add a single alert to Redis storage.
    
    Args:
        alert: Alert dictionary to add
        max_alerts: Maximum number of alerts to keep (oldest will be removed)
        
    Returns:
        True if successful, False otherwise
    """
    return add_alerts([alert], max_alerts)

def add_alerts(new_alerts: List[Dict[str, Any]], max_alerts: int = 1000) -> bool:
    """
    Add multiple alerts to Redis storage.
    
    Args:
        new_alerts: List of alert dictionaries to add
        max_alerts: Maximum number of alerts to keep (oldest will be removed)
        
    Returns:
        True if successful, False otherwise
    """
    if not new_alerts:
        return True
    
    client = get_redis_client()
    
    try:
        # Convert alerts to JSON strings
        alerts_json = [json.dumps(alert) for alert in new_alerts]
        
        # Add alerts to Redis list (right push)
        for alert_json in alerts_json:
            client.rpush(ALERTS_KEY, alert_json)
        
        # Trim list to max_alerts
        client.ltrim(ALERTS_KEY, -max_alerts, -1)
        
        logger.info(f"Added {len(new_alerts)} alerts to Redis")
        return True
    except Exception as e:
        logger.error(f"Error adding alerts to Redis: {e}")
        return False

def clear_alerts() -> bool:
    """
    Clear all alerts from Redis storage.
    
    Returns:
        True if successful, False otherwise
    """
    client = get_redis_client()
    
    try:
        # Delete alerts list
        client.delete(ALERTS_KEY)
        logger.info("Cleared all alerts from Redis")
        return True
    except Exception as e:
        logger.error(f"Error clearing alerts from Redis: {e}")
        return False

def get_alert_count() -> int:
    """
    Get the number of alerts in Redis storage.
    
    Returns:
        Number of alerts
    """
    client = get_redis_client()
    
    try:
        # Get length of alerts list
        count = client.llen(ALERTS_KEY)
        return count
    except Exception as e:
        logger.error(f"Error getting alert count from Redis: {e}")
        return 0

def filter_alerts(
    severity: Optional[str] = None,
    source_type: Optional[str] = None,
    entity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    custom_filter: Optional[Callable[[Dict[str, Any]], bool]] = None
) -> List[Dict[str, Any]]:
    """
    Filter alerts based on criteria.
    
    Args:
        severity: Filter by severity
        source_type: Filter by source type
        entity: Filter by entity
        start_time: Filter by start time
        end_time: Filter by end time
        custom_filter: Custom filter function
        
    Returns:
        List of filtered alert dictionaries
    """
    all_alerts = get_alerts()
    filtered_alerts = []
    
    for alert in all_alerts:
        # Check severity
        if severity and alert.get('severity') != severity:
            continue
        
        # Check source type
        if source_type and alert.get('source', {}).get('type') != source_type:
            continue
        
        # Check entity
        if entity and alert.get('entity') != entity:
            continue
        
        # Check start time
        if start_time and 'timestamp' in alert:
            try:
                alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                if alert_time < start_time:
                    continue
            except (ValueError, TypeError):
                pass
        
        # Check end time
        if end_time and 'timestamp' in alert:
            try:
                alert_time = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                if alert_time > end_time:
                    continue
            except (ValueError, TypeError):
                pass
        
        # Check custom filter
        if custom_filter and not custom_filter(alert):
            continue
        
        filtered_alerts.append(alert)
    
    return filtered_alerts

# Test function
def main():
    """Test the Redis-based alert storage."""
    logger.info("Testing Redis-based alert storage...")
    
    # Initialize Redis storage
    initialize()
    
    # Clear any existing alerts
    clear_alerts()
    
    # Create some test alerts
    test_alerts = []
    for i in range(5):
        alert = {
            'entity': f"test-host-{i+1}",
            'timestamp': datetime.now().isoformat(),
            'severity': 'High',
            'prediction_score': 0.85,
            'source': {'type': 'test'},
            'message': f"Test alert {i+1}"
        }
        test_alerts.append(alert)
    
    # Add the alerts
    success = add_alerts(test_alerts)
    logger.info(f"Add alerts: {'Success' if success else 'Failed'}")
    
    # Get the alerts
    retrieved_alerts = get_alerts()
    logger.info(f"Retrieved {len(retrieved_alerts)} alerts")
    
    # Add more alerts
    more_alerts = []
    for i in range(3):
        alert = {
            'entity': f"another-host-{i+1}",
            'timestamp': datetime.now().isoformat(),
            'severity': 'Medium',
            'prediction_score': 0.75,
            'source': {'type': 'test'},
            'message': f"Another test alert {i+1}"
        }
        more_alerts.append(alert)
    
    success = add_alerts(more_alerts)
    logger.info(f"Add more alerts: {'Success' if success else 'Failed'}")
    
    # Get the final count
    count = get_alert_count()
    logger.info(f"Final alert count: {count}")
    
    # Filter alerts
    filtered = filter_alerts(severity='Medium')
    logger.info(f"Filtered alerts (Medium severity): {len(filtered)}")
    
    logger.info("Test complete")

if __name__ == "__main__":
    main()
