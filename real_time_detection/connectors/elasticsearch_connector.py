"""
Elasticsearch Connector Module

This module provides functionality to connect to an Elasticsearch instance and fetch security events.
Elasticsearch is commonly used as part of the ELK Stack (Elasticsearch, Logstash, Kibana)
for security information and event management (SIEM).
"""

from elasticsearch import Elasticsearch
import logging
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Union

class ElasticsearchConnector:
    """
    Connector for Elasticsearch SIEM.
    
    This class provides methods to connect to an Elasticsearch instance,
    fetch security events, and normalize them for the APT detection system.
    """
    
    def __init__(
        self, 
        hosts: Union[str, List[str]], 
        index_pattern: str = "winlogbeat-*",
        username: Optional[str] = None, 
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        cloud_id: Optional[str] = None,
        verify_certs: bool = True
    ):
        """
        Initialize the Elasticsearch connector.
        
        Args:
            hosts: Elasticsearch host(s) to connect to
            index_pattern: Index pattern to search for events
            username: Username for authentication (if using basic auth)
            password: Password for authentication (if using basic auth)
            api_key: API key for authentication (if using API key auth)
            cloud_id: Cloud ID for Elastic Cloud (if using Elastic Cloud)
            verify_certs: Whether to verify SSL certificates
        """
        self.hosts = hosts
        self.index_pattern = index_pattern
        self.username = username
        self.password = password
        self.api_key = api_key
        self.cloud_id = cloud_id
        self.verify_certs = verify_certs
        self.last_fetch_time = datetime.now() - timedelta(hours=1)
        self.client = None
        self.logger = logging.getLogger(__name__)
    
    def connect(self) -> bool:
        """
        Connect to Elasticsearch.
        
        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            # Build connection parameters
            conn_params = {
                "hosts": self.hosts,
                "verify_certs": self.verify_certs
            }
            
            # Add authentication if provided
            if self.username and self.password:
                conn_params["basic_auth"] = (self.username, self.password)
            
            if self.api_key:
                conn_params["api_key"] = self.api_key
            
            if self.cloud_id:
                conn_params["cloud_id"] = self.cloud_id
            
            # Create Elasticsearch client
            self.client = Elasticsearch(**conn_params)
            
            # Check connection
            if self.client.ping():
                self.logger.info("Successfully connected to Elasticsearch")
                return True
            else:
                self.logger.error("Failed to connect to Elasticsearch")
                return False
                
        except Exception as e:
            self.logger.error(f"Error connecting to Elasticsearch: {str(e)}")
            return False
    
    def get_security_events(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Fetch security events from Elasticsearch.
        
        Args:
            limit: Maximum number of events to fetch
            
        Returns:
            List of normalized security events
        """
        if not self.client and not self.connect():
            self.logger.error("Failed to connect to Elasticsearch")
            return []
        
        # Format timestamp for Elasticsearch query
        timestamp = self.last_fetch_time.isoformat()
        
        try:
            # Query for security events
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gt": timestamp}}},
                            {"exists": {"field": "event.category"}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": limit
            }
            
            response = self.client.search(
                index=self.index_pattern,
                body=query
            )
            
            # Update last fetch time
            self.last_fetch_time = datetime.now()
            
            # Parse and normalize events
            events = [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
            self.logger.info(f"Fetched {len(events)} events from Elasticsearch")
            
            return self._normalize_events(events)
            
        except Exception as e:
            self.logger.error(f"Error fetching events from Elasticsearch: {str(e)}")
            return []
    
    def get_host_metrics(self, hosts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Fetch host metrics from Elasticsearch.
        
        Args:
            hosts: List of hosts to fetch metrics for (if None, fetch for all hosts)
            
        Returns:
            List of host metrics
        """
        if not self.client and not self.connect():
            self.logger.error("Failed to connect to Elasticsearch")
            return []
        
        try:
            # Build query for host metrics
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gt": "now-5m"}}},
                            {"exists": {"field": "system.cpu"}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 100
            }
            
            # Add host filter if hosts are specified
            if hosts:
                query["query"]["bool"]["must"].append({
                    "terms": {"host.name": hosts}
                })
            
            response = self.client.search(
                index="metricbeat-*",
                body=query
            )
            
            # Parse metrics
            metrics = [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
            self.logger.info(f"Fetched metrics for {len(metrics)} hosts from Elasticsearch")
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error fetching host metrics from Elasticsearch: {str(e)}")
            return []
    
    def _normalize_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert Elasticsearch events to a standard format for the detection system.
        
        Args:
            events: List of events from Elasticsearch
            
        Returns:
            List of normalized events
        """
        normalized_events = []
        
        for event in events:
            # Extract relevant fields and normalize to our feature format
            normalized_event = {
                'timestamp': event.get('@timestamp', ''),
                'host': self._get_nested_value(event, 'host.name', ''),
                'event_category': self._get_nested_value(event, 'event.category', ''),
                'event_type': self._get_nested_value(event, 'event.type', ''),
                'event_action': self._get_nested_value(event, 'event.action', ''),
                'source_ip': self._get_nested_value(event, 'source.ip', ''),
                'destination_ip': self._get_nested_value(event, 'destination.ip', ''),
                'user': self._get_nested_value(event, 'user.name', ''),
                'source': 'elasticsearch',
                
                # Initialize our feature set
                'network_traffic_volume_mean': 0.0,
                'number_of_logins_mean': 0.0,
                'number_of_failed_logins_mean': 0.0,
                'number_of_accessed_files_mean': 0.0,
                'number_of_email_sent_mean': 0.0,
                'cpu_usage_mean': 0.0,
                'memory_usage_mean': 0.0,
                'disk_io_mean': 0.0,
                'network_latency_mean': 0.0,
                'number_of_processes_mean': 0.0,
            }
            
            # Populate features based on event type
            event_category = self._get_nested_value(event, 'event.category', '')
            event_type = self._get_nested_value(event, 'event.type', '')
            event_action = self._get_nested_value(event, 'event.action', '')
            
            # Authentication events
            if event_category == 'authentication':
                if event_type == 'start' or event_action == 'logged-in':
                    normalized_event['number_of_logins_mean'] = 1.0
                elif event_type == 'error' or event_action == 'failed':
                    normalized_event['number_of_failed_logins_mean'] = 1.0
            
            # File events
            elif event_category == 'file':
                normalized_event['number_of_accessed_files_mean'] = 1.0
            
            # Network events
            elif event_category == 'network':
                normalized_event['network_traffic_volume_mean'] = 1.0
                
                # Extract network metrics if available
                network_bytes = self._get_nested_value(event, 'network.bytes', 0)
                if network_bytes:
                    # Normalize to a 0-1 scale (assuming max 1MB per event)
                    normalized_event['network_traffic_volume_mean'] = min(float(network_bytes) / (1024 * 1024), 1.0)
                
                network_latency = self._get_nested_value(event, 'network.latency', 0)
                if network_latency:
                    # Normalize to a 0-1 scale (assuming max 1000ms latency)
                    normalized_event['network_latency_mean'] = min(float(network_latency) / 1000, 1.0)
            
            # Process events
            elif event_category == 'process':
                normalized_event['number_of_processes_mean'] = 1.0
            
            # Email events
            elif event_category == 'email':
                if event_type == 'info' and event_action == 'send':
                    normalized_event['number_of_email_sent_mean'] = 1.0
            
            # System metrics
            if 'system' in event:
                system = event.get('system', {})
                
                # CPU usage
                cpu = system.get('cpu', {})
                if cpu:
                    cpu_pct = cpu.get('total', {}).get('pct', 0)
                    normalized_event['cpu_usage_mean'] = float(cpu_pct)
                
                # Memory usage
                memory = system.get('memory', {})
                if memory:
                    memory_pct = memory.get('actual', {}).get('used', {}).get('pct', 0)
                    normalized_event['memory_usage_mean'] = float(memory_pct)
                
                # Disk I/O
                filesystem = system.get('filesystem', {})
                if filesystem:
                    disk_io = filesystem.get('io', {}).get('total', 0)
                    # Normalize to a 0-1 scale (assuming max 100MB/s)
                    normalized_event['disk_io_mean'] = min(float(disk_io) / (100 * 1024 * 1024), 1.0)
            
            normalized_events.append(normalized_event)
        
        return normalized_events
    
    def _get_nested_value(self, obj: Dict[str, Any], path: str, default: Any = None) -> Any:
        """
        Get a value from a nested dictionary using a dot-separated path.
        
        Args:
            obj: Dictionary to get value from
            path: Dot-separated path to the value
            default: Default value to return if path doesn't exist
            
        Returns:
            Value at the specified path, or default if not found
        """
        keys = path.split('.')
        value = obj
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value

    def extract_features(self, events: List[Dict[str, Any]], window_minutes: int = 10) -> pd.DataFrame:
        """
        Extract time-series features from Elasticsearch events.
        
        Args:
            events: List of normalized events
            window_minutes: Time window for feature calculation in minutes
            
        Returns:
            DataFrame with extracted features
        """
        if not events:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Group by time windows and host
        df['time_window'] = df['timestamp'].dt.floor(f'{window_minutes}min')
        
        # Calculate features per time window and host
        features = df.groupby(['time_window', 'host']).agg({
            'network_traffic_volume_mean': 'sum',
            'number_of_logins_mean': 'sum',
            'number_of_failed_logins_mean': 'sum',
            'number_of_accessed_files_mean': 'sum',
            'number_of_email_sent_mean': 'sum',
            'cpu_usage_mean': 'mean',
            'memory_usage_mean': 'mean',
            'disk_io_mean': 'mean',
            'network_latency_mean': 'mean',
            'number_of_processes_mean': 'sum'
        }).reset_index()
        
        # Add additional features
        event_counts = df.groupby(['time_window', 'host']).size().reset_index(name='event_count')
        category_counts = df.groupby(['time_window', 'host'])['event_category'].nunique().reset_index(name='unique_category_count')
        
        # Merge additional features
        features = features.merge(event_counts, on=['time_window', 'host'])
        features = features.merge(category_counts, on=['time_window', 'host'])
        
        # Calculate rolling statistics (last 3 windows)
        features.sort_values(['host', 'time_window'], inplace=True)
        
        # Group by host to calculate rolling statistics per host
        for host in features['host'].unique():
            host_mask = features['host'] == host
            
            # Calculate rolling means
            for col in ['event_count', 'unique_category_count']:
                features.loc[host_mask, f'{col}_rolling_mean'] = features.loc[host_mask, col].rolling(3, min_periods=1).mean()
            
            # Calculate rate of change
            for col in ['event_count', 'unique_category_count']:
                features.loc[host_mask, f'{col}_rate'] = features.loc[host_mask, col].pct_change().fillna(0)
        
        # Fill NaN values
        features = features.fillna(0)
        
        return features

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example configuration
    hosts = ["localhost:9200"]
    username = "elastic"
    password = "changeme"
    
    # Create connector
    connector = ElasticsearchConnector(hosts, username=username, password=password)
    
    # Connect to Elasticsearch
    if connector.connect():
        # Get security events
        events = connector.get_security_events(limit=1000)
        print(f"Fetched {len(events)} events")
        
        # Extract features
        features = connector.extract_features(events)
        print(f"Extracted features for {len(features)} time windows")
        print(features.head())
    else:
        print("Connection failed")
