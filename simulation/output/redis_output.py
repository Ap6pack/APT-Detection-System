"""
Redis Output Module

This module provides the Redis output adapter for the simulation system.
"""

import json
import time
import random
from typing import Dict, Any

import redis

from ..config import SimulationConfig
from .base_output import BaseOutput

class RedisOutput(BaseOutput):
    """Redis output adapter for the simulation system."""
    
    def __init__(self, config: SimulationConfig):
        """
        Initialize the Redis output adapter.
        
        Args:
            config: Simulation configuration
        """
        super().__init__(config)
        
        # Get Redis configuration
        output_config = config.get_output_config()
        self.redis_key = output_config.get('redis_key', 'apt:alerts')
        
        # Initialize Redis client
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
            self.logger.info("Connected to Redis server")
        except Exception as e:
            self.logger.error(f"Error connecting to Redis server: {str(e)}")
            self.redis_client = None
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send an event to Redis.
        
        Args:
            event: Event data
            
        Returns:
            True if the event was sent successfully, False otherwise
        """
        if not self.redis_client:
            self.logger.error("Redis client not initialized")
            return False
        
        try:
            # Format the event
            formatted_event = self._format_event(event)
            
            # Convert to JSON
            event_json = json.dumps(formatted_event)
            
            # Generate a unique ID for the event
            event_id = f"event:{int(time.time() * 1000)}:{random.randint(1000, 9999)}"
            
            # Store the event in Redis
            self.redis_client.hset(self.redis_key, event_id, event_json)
            
            # Set expiration for the event (30 days)
            self.redis_client.expire(self.redis_key, 60 * 60 * 24 * 30)
            
            self.logger.debug(f"Sent event to Redis: {event_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error sending event to Redis: {str(e)}")
            return False
    
    def _format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format an event for Redis output.
        
        Args:
            event: Event data
            
        Returns:
            Formatted event data
        """
        # Apply base formatting
        formatted_event = super()._format_event(event)
        
        # Add Redis-specific formatting
        if 'detection_type' not in formatted_event:
            formatted_event['detection_type'] = 'simulation'
        
        return formatted_event
