"""
Wazuh Connector Module

This module provides functionality to connect to a Wazuh server and fetch security events.
Wazuh is an open-source security monitoring solution that can be used as an EDR
(Endpoint Detection and Response) system.
"""

import requests
import logging
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any

class WazuhConnector:
    """
    Connector for Wazuh EDR system.
    
    This class provides methods to authenticate with a Wazuh server,
    fetch security events, and normalize them for the APT detection system.
    """
    
    def __init__(self, api_url: str, username: str, password: str, verify_ssl: bool = True):
        """
        Initialize the Wazuh connector.
        
        Args:
            api_url: The URL of the Wazuh API (e.g., https://wazuh.example.com:55000)
            username: The username for authentication
            password: The password for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.api_url = api_url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.auth_token = None
        self.last_fetch_time = datetime.now() - timedelta(hours=1)
        self.logger = logging.getLogger(__name__)
    
    def authenticate(self) -> bool:
        """
        Authenticate with the Wazuh API and get a token.
        
        Returns:
            bool: True if authentication was successful, False otherwise
        """
        try:
            auth_endpoint = f"{self.api_url}/security/user/authenticate"
            response = requests.get(
                auth_endpoint, 
                auth=(self.username, self.password), 
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                self.auth_token = response.headers.get('X-Wazuh-Token')
                self.logger.info("Successfully authenticated with Wazuh API")
                return True
            else:
                self.logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during authentication: {str(e)}")
            return False
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch alerts from the Wazuh API.
        
        Args:
            limit: Maximum number of alerts to fetch
            
        Returns:
            List of normalized alerts
        """
        if not self.auth_token and not self.authenticate():
            self.logger.error("Failed to authenticate with Wazuh API")
            return []
        
        # Format timestamp for Wazuh query
        timestamp = self.last_fetch_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        try:
            # Query for alerts after the last fetch time
            alerts_endpoint = f"{self.api_url}/alerts"
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            params = {
                "limit": limit,
                "q": f"timestamp>={timestamp}",
                "sort": "+timestamp"
            }
            
            response = requests.get(
                alerts_endpoint, 
                headers=headers, 
                params=params,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to fetch alerts: {response.status_code} - {response.text}")
                return []
            
            # Update last fetch time
            self.last_fetch_time = datetime.now()
            
            # Parse and normalize alerts
            alerts_data = response.json()
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            self.logger.info(f"Fetched {len(alerts)} alerts from Wazuh")
            
            return self._normalize_alerts(alerts)
            
        except Exception as e:
            self.logger.error(f"Error fetching alerts: {str(e)}")
            return []
    
    def get_agent_status(self) -> List[Dict[str, Any]]:
        """
        Fetch agent status information from the Wazuh API.
        
        Returns:
            List of agent status information
        """
        if not self.auth_token and not self.authenticate():
            self.logger.error("Failed to authenticate with Wazuh API")
            return []
        
        try:
            # Query for agent status
            agents_endpoint = f"{self.api_url}/agents"
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            response = requests.get(
                agents_endpoint, 
                headers=headers, 
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to fetch agent status: {response.status_code} - {response.text}")
                return []
            
            # Parse agent status
            agents_data = response.json()
            agents = agents_data.get('data', {}).get('affected_items', [])
            self.logger.info(f"Fetched status for {len(agents)} agents from Wazuh")
            
            return agents
            
        except Exception as e:
            self.logger.error(f"Error fetching agent status: {str(e)}")
            return []
    
    def _normalize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert Wazuh alerts to a standard format for the detection system.
        
        Args:
            alerts: List of alerts from Wazuh API
            
        Returns:
            List of normalized alerts
        """
        normalized_alerts = []
        
        for alert in alerts:
            # Extract relevant fields and normalize to our feature format
            normalized_alert = {
                'timestamp': alert.get('timestamp', ''),
                'agent_id': alert.get('agent_id', ''),
                'agent_name': alert.get('agent_name', ''),
                'rule_id': alert.get('rule', {}).get('id', ''),
                'rule_description': alert.get('rule', {}).get('description', ''),
                'level': int(alert.get('rule', {}).get('level', 0)),
                'groups': alert.get('rule', {}).get('groups', []),
                'source': 'wazuh',
                
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
            
            # Populate features based on alert type and rule groups
            groups = alert.get('rule', {}).get('groups', [])
            
            # Authentication events
            if 'authentication' in groups or 'authentication_success' in groups:
                normalized_alert['number_of_logins_mean'] = 1.0
            
            if 'authentication_failed' in groups:
                normalized_alert['number_of_failed_logins_mean'] = 1.0
            
            # File events
            if 'syscheck' in groups or 'ossec' in groups:
                normalized_alert['number_of_accessed_files_mean'] = 1.0
            
            # Process events
            if 'process' in groups:
                normalized_alert['number_of_processes_mean'] = 1.0
            
            # Network events
            if 'firewall' in groups or 'network' in groups:
                normalized_alert['network_traffic_volume_mean'] = 1.0
            
            # System metrics
            if 'system' in groups:
                data = alert.get('data', {})
                if 'cpu' in data:
                    normalized_alert['cpu_usage_mean'] = float(data.get('cpu', 0)) / 100.0
                if 'memory' in data:
                    normalized_alert['memory_usage_mean'] = float(data.get('memory', 0)) / 100.0
            
            normalized_alerts.append(normalized_alert)
        
        return normalized_alerts

    def extract_features(self, alerts: List[Dict[str, Any]], window_minutes: int = 10) -> pd.DataFrame:
        """
        Extract time-series features from Wazuh alerts.
        
        Args:
            alerts: List of normalized alerts
            window_minutes: Time window for feature calculation in minutes
            
        Returns:
            DataFrame with extracted features
        """
        if not alerts:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(alerts)
        
        # Convert timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Group by time windows and agent
        df['time_window'] = df['timestamp'].dt.floor(f'{window_minutes}min')
        
        # Calculate features per time window and agent
        features = df.groupby(['time_window', 'agent_id']).agg({
            'network_traffic_volume_mean': 'sum',
            'number_of_logins_mean': 'sum',
            'number_of_failed_logins_mean': 'sum',
            'number_of_accessed_files_mean': 'sum',
            'number_of_email_sent_mean': 'sum',
            'cpu_usage_mean': 'mean',
            'memory_usage_mean': 'mean',
            'disk_io_mean': 'mean',
            'network_latency_mean': 'mean',
            'number_of_processes_mean': 'sum',
            'level': 'max'
        }).reset_index()
        
        # Add additional features
        alert_counts = df.groupby(['time_window', 'agent_id']).size().reset_index(name='alert_count')
        rule_counts = df.groupby(['time_window', 'agent_id'])['rule_id'].nunique().reset_index(name='unique_rule_count')
        
        # Merge additional features
        features = features.merge(alert_counts, on=['time_window', 'agent_id'])
        features = features.merge(rule_counts, on=['time_window', 'agent_id'])
        
        # Calculate rolling statistics (last 3 windows)
        features.sort_values(['agent_id', 'time_window'], inplace=True)
        
        # Group by agent_id to calculate rolling statistics per agent
        for agent in features['agent_id'].unique():
            agent_mask = features['agent_id'] == agent
            
            # Calculate rolling means
            for col in ['alert_count', 'unique_rule_count', 'level']:
                features.loc[agent_mask, f'{col}_rolling_mean'] = features.loc[agent_mask, col].rolling(3, min_periods=1).mean()
            
            # Calculate rate of change
            for col in ['alert_count', 'unique_rule_count']:
                features.loc[agent_mask, f'{col}_rate'] = features.loc[agent_mask, col].pct_change().fillna(0)
        
        # Fill NaN values
        features = features.fillna(0)
        
        return features

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example configuration
    api_url = "https://wazuh.example.com:55000"
    username = "wazuh-api-user"
    password = "wazuh-api-password"
    
    # Create connector
    connector = WazuhConnector(api_url, username, password, verify_ssl=False)
    
    # Authenticate
    if connector.authenticate():
        # Get alerts
        alerts = connector.get_alerts(limit=100)
        print(f"Fetched {len(alerts)} alerts")
        
        # Extract features
        features = connector.extract_features(alerts)
        print(f"Extracted features for {len(features)} time windows")
        print(features.head())
    else:
        print("Authentication failed")
