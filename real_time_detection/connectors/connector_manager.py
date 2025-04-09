"""
Connector Manager Module

This module provides a unified interface for managing multiple data source connectors.
It handles the initialization, configuration, and data retrieval from various security data sources.
"""

import logging
import yaml
import os
import pandas as pd
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

# Import connectors
from .wazuh_connector import WazuhConnector
from .elasticsearch_connector import ElasticsearchConnector

class ConnectorManager:
    """
    Manager for data source connectors.
    
    This class provides a unified interface for managing multiple data source connectors,
    retrieving data from them, and normalizing the data for the APT detection system.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the connector manager.
        
        Args:
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.connectors = {}
        self.config = {}
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config.yaml')
        
        self.load_config(config_path)
        self.initialize_connectors()
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, 'r') as file:
                self.config = yaml.safe_load(file)
                self.logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.config = {}
    
    def initialize_connectors(self) -> None:
        """
        Initialize connectors based on the configuration.
        """
        # Check if data_sources section exists in config
        if 'data_sources' not in self.config:
            self.logger.warning("No data_sources section found in configuration")
            return
        
        data_sources = self.config.get('data_sources', {})
        
        # Initialize Wazuh connector if configured
        if 'wazuh' in data_sources and data_sources['wazuh'].get('enabled', False):
            try:
                wazuh_config = data_sources['wazuh']
                self.logger.info("Initializing Wazuh connector")
                
                wazuh_connector = WazuhConnector(
                    api_url=wazuh_config.get('api_url', ''),
                    username=wazuh_config.get('username', ''),
                    password=wazuh_config.get('password', ''),
                    verify_ssl=wazuh_config.get('verify_ssl', True)
                )
                
                self.connectors['wazuh'] = wazuh_connector
                self.logger.info("Wazuh connector initialized")
            except Exception as e:
                self.logger.error(f"Error initializing Wazuh connector: {str(e)}")
        
        # Initialize Elasticsearch connector if configured
        if 'elasticsearch' in data_sources and data_sources['elasticsearch'].get('enabled', False):
            try:
                es_config = data_sources['elasticsearch']
                self.logger.info("Initializing Elasticsearch connector")
                
                es_connector = ElasticsearchConnector(
                    hosts=es_config.get('hosts', []),
                    index_pattern=es_config.get('index_pattern', 'winlogbeat-*'),
                    username=es_config.get('username', None),
                    password=es_config.get('password', None),
                    api_key=es_config.get('api_key', None),
                    cloud_id=es_config.get('cloud_id', None),
                    verify_certs=es_config.get('verify_certs', True)
                )
                
                self.connectors['elasticsearch'] = es_connector
                self.logger.info("Elasticsearch connector initialized")
            except Exception as e:
                self.logger.error(f"Error initializing Elasticsearch connector: {str(e)}")
    
    def get_connector(self, name: str) -> Optional[Any]:
        """
        Get a specific connector by name.
        
        Args:
            name: Name of the connector
            
        Returns:
            Connector instance or None if not found
        """
        return self.connectors.get(name)
    
    def get_all_connectors(self) -> Dict[str, Any]:
        """
        Get all initialized connectors.
        
        Returns:
            Dictionary of connector instances
        """
        return self.connectors
    
    def collect_data(self, window_minutes: int = 10) -> pd.DataFrame:
        """
        Collect data from all connectors and extract features.
        
        Args:
            window_minutes: Time window for feature calculation in minutes
            
        Returns:
            DataFrame with extracted features from all data sources
        """
        all_features = []
        
        # Collect data from Wazuh
        wazuh_connector = self.connectors.get('wazuh')
        if wazuh_connector:
            try:
                self.logger.info("Collecting data from Wazuh")
                alerts = wazuh_connector.get_alerts(limit=1000)
                if alerts:
                    features = wazuh_connector.extract_features(alerts, window_minutes=window_minutes)
                    if not features.empty:
                        # Add source column
                        features['data_source'] = 'wazuh'
                        all_features.append(features)
                        self.logger.info(f"Collected {len(features)} feature sets from Wazuh")
            except Exception as e:
                self.logger.error(f"Error collecting data from Wazuh: {str(e)}")
        
        # Collect data from Elasticsearch
        es_connector = self.connectors.get('elasticsearch')
        if es_connector:
            try:
                self.logger.info("Collecting data from Elasticsearch")
                events = es_connector.get_security_events(limit=1000)
                if events:
                    features = es_connector.extract_features(events, window_minutes=window_minutes)
                    if not features.empty:
                        # Add source column
                        features['data_source'] = 'elasticsearch'
                        all_features.append(features)
                        self.logger.info(f"Collected {len(features)} feature sets from Elasticsearch")
            except Exception as e:
                self.logger.error(f"Error collecting data from Elasticsearch: {str(e)}")
        
        # Combine all features
        if all_features:
            combined_features = pd.concat(all_features, ignore_index=True)
            self.logger.info(f"Combined {len(combined_features)} feature sets from all data sources")
            return combined_features
        else:
            self.logger.warning("No features collected from any data source")
            return pd.DataFrame()
    
    def get_latest_data(self, minutes: int = 60) -> pd.DataFrame:
        """
        Get the latest data from all connectors within a specified time window.
        
        Args:
            minutes: Time window in minutes
            
        Returns:
            DataFrame with the latest data
        """
        # Calculate start time
        start_time = datetime.now() - timedelta(minutes=minutes)
        
        # Collect data
        features = self.collect_data()
        
        # Filter by time window
        if not features.empty and 'time_window' in features.columns:
            features['time_window'] = pd.to_datetime(features['time_window'])
            features = features[features['time_window'] >= start_time]
            self.logger.info(f"Filtered to {len(features)} feature sets within the last {minutes} minutes")
        
        return features

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create connector manager
    manager = ConnectorManager()
    
    # Get all connectors
    connectors = manager.get_all_connectors()
    print(f"Initialized {len(connectors)} connectors")
    
    # Collect data from all connectors
    features = manager.collect_data()
    if not features.empty:
        print(f"Collected {len(features)} feature sets")
        print(features.head())
    else:
        print("No data collected")
