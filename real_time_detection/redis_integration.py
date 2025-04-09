"""
Redis integration module for APT Detection System.

This module provides Redis-based storage for alerts, with the same interface
as the in-memory storage used in the data_ingestion module.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any

try:
    import redis
except ImportError:
    logging.error("Redis package not installed. Please install it with: pip install redis")
    raise

# Set up logging
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
            logger.error("Falling back to in-memory storage")
            return None
    
    return redis_client

def initialize():
    """
    Initialize the Redis storage.
    This ensures the Redis connection is established.
    """
    logger.info("Initializing Redis storage")
    
    # Get Redis client
    client = get_redis_client()
    
    if client is None:
        logger.warning("Redis client not available, using in-memory storage")
        return False
    
    # Check if alerts list exists
    if not client.exists(ALERTS_KEY):
        # Create empty list
        client.delete(ALERTS_KEY)
        logger.info(f"Created empty alerts list in Redis with key: {ALERTS_KEY}")
    else:
        # Get count of alerts
        count = client.llen(ALERTS_KEY)
        logger.info(f"Redis storage initialized with {count} existing alerts")
    
    return True

def store_alert(alert: Dict[str, Any], max_alerts: int = 1000) -> bool:
    """
    Store an alert in Redis.
    
    Args:
        alert: Alert dictionary to store
        max_alerts: Maximum number of alerts to keep (oldest will be removed)
        
    Returns:
        True if successful, False otherwise
    """
    # Add timestamp if not present
    if 'timestamp' not in alert:
        alert['timestamp'] = datetime.now().isoformat()
    
    # Get Redis client
    client = get_redis_client()
    
    if client is None:
        # Fallback to in-memory storage
        from . import data_ingestion
        data_ingestion.store_alert(alert)
        return True
    
    try:
        # Convert alert to JSON string
        alert_json = json.dumps(alert)
        
        # Add alert to Redis list (right push)
        client.rpush(ALERTS_KEY, alert_json)
        
        # Trim list to max_alerts
        client.ltrim(ALERTS_KEY, -max_alerts, -1)
        
        return True
    except Exception as e:
        logger.error(f"Error storing alert in Redis: {e}")
        
        # Fallback to in-memory storage
        from . import data_ingestion
        data_ingestion.store_alert(alert)
        
        return False

def get_alerts() -> List[Dict[str, Any]]:
    """
    Get all alerts from Redis.
    
    Returns:
        List of alert dictionaries
    """
    # Get Redis client
    client = get_redis_client()
    
    if client is None:
        # Fallback to in-memory storage
        from . import data_ingestion
        return data_ingestion.get_alerts()
    
    try:
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
        
        return alerts
    except Exception as e:
        logger.error(f"Error getting alerts from Redis: {e}")
        
        # Fallback to in-memory storage
        from . import data_ingestion
        return data_ingestion.get_alerts()

def clear_alerts() -> bool:
    """
    Clear all alerts from Redis.
    
    Returns:
        True if successful, False otherwise
    """
    # Get Redis client
    client = get_redis_client()
    
    if client is None:
        # Fallback to in-memory storage
        from . import data_ingestion
        with data_ingestion.alerts_lock:
            data_ingestion.alerts.clear()
        return True
    
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
    Get the number of alerts in Redis.
    
    Returns:
        Number of alerts
    """
    # Get Redis client
    client = get_redis_client()
    
    if client is None:
        # Fallback to in-memory storage
        from . import data_ingestion
        with data_ingestion.alerts_lock:
            return len(data_ingestion.alerts)
    
    try:
        # Get length of alerts list
        count = client.llen(ALERTS_KEY)
        return count
    except Exception as e:
        logger.error(f"Error getting alert count from Redis: {e}")
        
        # Fallback to in-memory storage
        from . import data_ingestion
        with data_ingestion.alerts_lock:
            return len(data_ingestion.alerts)
