"""
Simulation Configuration Module

This module provides configuration settings for the security event simulation system.
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    "simulation": {
        "enabled": True,
        "realism_level": "basic",  # Can be "basic", "intermediate", or "advanced"
        "output": {
            "type": "redis",  # Can be "redis", "kafka", or "both"
            "redis_key": "apt:alerts",
            "kafka_topic": "apt_topic"
        },
        "entities": {
            "hosts": {
                "count": 10,
                "prefix": "host"
            },
            "users": {
                "count": 20,
                "prefix": "user"
            },
            "networks": {
                "count": 3,
                "subnets": ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]
            }
        },
        "events": {
            "rate": 5,  # Events per minute
            "distribution": {
                "network": 0.4,
                "endpoint": 0.4,
                "user": 0.2
            }
        },
        "scenarios": {
            "enabled": True,
            "frequency": "medium",  # How often to trigger scenarios (low, medium, high)
            "concurrent": 2  # Maximum number of concurrent scenarios
        },
        "time_patterns": {
            "enabled": False,  # Set to true for intermediate realism
            "business_hours": {
                "start": 9,  # 9 AM
                "end": 17,   # 5 PM
                "days": [0, 1, 2, 3, 4]  # Monday to Friday (0 = Monday)
            }
        },
        "adaptive_behavior": {
            "enabled": False  # Set to true for advanced realism
        }
    }
}

class SimulationConfig:
    """Configuration manager for the simulation system."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.config = DEFAULT_CONFIG.copy()
        
        # Load configuration from file if provided
        if config_path:
            self.load_config(config_path)
        else:
            # Try to load from default location
            default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
            if os.path.exists(default_path):
                self.load_config(default_path)
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, 'r') as file:
                file_config = yaml.safe_load(file)
                
                # Update configuration if simulation section exists
                if 'simulation' in file_config:
                    self._update_dict(self.config['simulation'], file_config['simulation'])
                    self.logger.info(f"Loaded simulation configuration from {config_path}")
                else:
                    self.logger.warning(f"No simulation section found in {config_path}")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
    
    def _update_dict(self, target: Dict, source: Dict) -> None:
        """
        Recursively update a dictionary with values from another dictionary.
        
        Args:
            target: Dictionary to update
            source: Dictionary with new values
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict(target[key], value)
            else:
                target[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key (dot notation supported, e.g., 'simulation.enabled')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def is_enabled(self) -> bool:
        """
        Check if simulation is enabled.
        
        Returns:
            True if simulation is enabled, False otherwise
        """
        return self.get('simulation.enabled', False)
    
    def get_realism_level(self) -> str:
        """
        Get the realism level.
        
        Returns:
            Realism level (basic, intermediate, or advanced)
        """
        return self.get('simulation.realism_level', 'basic')
    
    def is_time_patterns_enabled(self) -> bool:
        """
        Check if time patterns are enabled.
        
        Returns:
            True if time patterns are enabled, False otherwise
        """
        return self.get('simulation.time_patterns.enabled', False)
    
    def is_adaptive_behavior_enabled(self) -> bool:
        """
        Check if adaptive behavior is enabled.
        
        Returns:
            True if adaptive behavior is enabled, False otherwise
        """
        return self.get('simulation.adaptive_behavior.enabled', False)
    
    def get_output_config(self) -> Dict[str, Any]:
        """
        Get the output configuration.
        
        Returns:
            Output configuration dictionary
        """
        return self.get('simulation.output', {})
    
    def get_entities_config(self) -> Dict[str, Any]:
        """
        Get the entities configuration.
        
        Returns:
            Entities configuration dictionary
        """
        return self.get('simulation.entities', {})
    
    def get_events_config(self) -> Dict[str, Any]:
        """
        Get the events configuration.
        
        Returns:
            Events configuration dictionary
        """
        return self.get('simulation.events', {})
    
    def get_scenarios_config(self) -> Dict[str, Any]:
        """
        Get the scenarios configuration.
        
        Returns:
            Scenarios configuration dictionary
        """
        return self.get('simulation.scenarios', {})
