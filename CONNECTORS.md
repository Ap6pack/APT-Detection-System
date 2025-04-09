# Connectors in the APT Detection System

This document provides detailed information about the connector architecture in the APT Detection System, including how connectors work, how to configure existing connectors, and how to develop new connectors for additional data sources.

## Overview

The connector architecture in the APT Detection System provides a flexible, extensible way to integrate with various security data sources. Connectors serve as adapters between external security systems (like EDR, SIEM, etc.) and the APT Detection System, normalizing data for processing and analysis.

## Connector Architecture

The connector system follows a plugin-based architecture that allows for easy addition of new data sources without modifying the core code.

### Key Components

1. **ConnectorManager** (`real_time_detection/connectors/connector_manager.py`)
   - Central manager for all connectors
   - Handles initialization, configuration, and data collection
   - Provides a unified interface for accessing data from multiple sources

2. **Base Connector Interface**
   - While not explicitly defined as an abstract class, all connectors follow a common interface
   - Key methods include:
     - `get_alerts()` or `get_security_events()`
     - `extract_features()`

3. **Specific Connectors**
   - **WazuhConnector** (`real_time_detection/connectors/wazuh_connector.py`)
     - Connects to Wazuh EDR/SIEM
     - Retrieves security alerts and events
   - **ElasticsearchConnector** (`real_time_detection/connectors/elasticsearch_connector.py`)
     - Connects to Elasticsearch
     - Retrieves security events from specified indices

### Data Flow

1. The `ConnectorManager` is initialized with configuration from `config.yaml`
2. Connectors are initialized based on their respective configurations
3. The `collect_data()` method is called periodically to retrieve data from all enabled connectors
4. Each connector retrieves data from its source and extracts features
5. Features are combined and returned for processing by the prediction engine
6. Alerts are generated based on prediction results

## Existing Connectors

### Wazuh Connector

The Wazuh connector integrates with the Wazuh EDR/SIEM platform to retrieve security alerts and events.

#### Configuration

```yaml
data_sources:
  wazuh:
    enabled: true
    api_url: "https://wazuh.example.com:55000"
    username: "wazuh-api-user"
    password: "wazuh-api-password"
    verify_ssl: false
    fetch_interval: 60
```

#### Parameters

- **enabled**: Whether the connector is enabled
- **api_url**: URL of the Wazuh API
- **username**: Username for API authentication
- **password**: Password for API authentication
- **verify_ssl**: Whether to verify SSL certificates
- **fetch_interval**: Interval in seconds between data fetches

#### Features Extracted

- Network traffic volume
- Number of logins
- Number of failed logins
- Number of accessed files
- Process creation events
- File modification events
- Registry modification events (Windows)
- Network connection events

### Elasticsearch Connector

The Elasticsearch connector integrates with Elasticsearch to retrieve security events from specified indices.

#### Configuration

```yaml
data_sources:
  elasticsearch:
    enabled: true
    hosts: ["localhost:9200"]
    index_pattern: "winlogbeat-*"
    username: "elastic"
    password: "changeme"
    verify_certs: false
    fetch_interval: 60
```

#### Parameters

- **enabled**: Whether the connector is enabled
- **hosts**: List of Elasticsearch hosts
- **index_pattern**: Pattern to match indices containing security events
- **username**: Username for API authentication
- **password**: Password for API authentication
- **verify_certs**: Whether to verify SSL certificates
- **fetch_interval**: Interval in seconds between data fetches

#### Features Extracted

- Authentication events
- Process execution events
- Network connection events
- File access events
- Security log events
- System events
- Application events

## Developing New Connectors

You can extend the system by developing new connectors for additional data sources. Here's how to create a new connector:

### Step 1: Create a New Connector Class

Create a new file in the `real_time_detection/connectors` directory, e.g., `my_connector.py`:

```python
"""
MyConnector Module

This module provides integration with MySecurityTool.
"""

import logging
import requests
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

class MyConnector:
    """
    Connector for MySecurityTool.
    
    This class provides methods for retrieving security events from MySecurityTool
    and extracting features for the APT detection system.
    """
    
    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = True):
        """
        Initialize the MyConnector.
        
        Args:
            api_url: URL of the MySecurityTool API
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.logger = logging.getLogger(__name__)
        self.api_url = api_url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        
        # Test connection
        self.test_connection()
    
    def test_connection(self) -> bool:
        """
        Test the connection to MySecurityTool.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f"{self.api_url}/api/status",
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                self.logger.info("Successfully connected to MySecurityTool")
                return True
            else:
                self.logger.error(f"Failed to connect to MySecurityTool: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error connecting to MySecurityTool: {str(e)}")
            return False
    
    def get_security_events(self, start_time: Optional[datetime] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get security events from MySecurityTool.
        
        Args:
            start_time: Start time for events (default: 1 hour ago)
            limit: Maximum number of events to retrieve
            
        Returns:
            List of security events
        """
        if start_time is None:
            start_time = datetime.now() - timedelta(hours=1)
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'start_time': start_time.isoformat(),
                'limit': limit
            }
            
            response = requests.get(
                f"{self.api_url}/api/events",
                headers=headers,
                params=params,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                events = response.json().get('events', [])
                self.logger.info(f"Retrieved {len(events)} events from MySecurityTool")
                return events
            else:
                self.logger.error(f"Failed to retrieve events from MySecurityTool: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error retrieving events from MySecurityTool: {str(e)}")
            return []
    
    def extract_features(self, events: List[Dict[str, Any]], window_minutes: int = 10) -> pd.DataFrame:
        """
        Extract features from security events.
        
        Args:
            events: List of security events
            window_minutes: Time window for feature calculation in minutes
            
        Returns:
            DataFrame with extracted features
        """
        if not events:
            return pd.DataFrame()
        
        # Group events by entity (e.g., hostname, IP)
        entities = {}
        for event in events:
            entity = event.get('entity', 'unknown')
            if entity not in entities:
                entities[entity] = []
            entities[entity].append(event)
        
        # Extract features for each entity
        features_list = []
        for entity, entity_events in entities.items():
            # Calculate time window
            now = datetime.now()
            window_start = now - timedelta(minutes=window_minutes)
            
            # Filter events in the time window
            window_events = [
                e for e in entity_events 
                if datetime.fromisoformat(e.get('timestamp', now.isoformat()).replace('Z', '+00:00')) >= window_start
            ]
            
            if not window_events:
                continue
            
            # Count event types
            event_types = {}
            for event in window_events:
                event_type = event.get('type', 'unknown')
                event_types[event_type] = event_types.get(event_type, 0) + 1
            
            # Create feature dictionary
            features = {
                'entity': entity,
                'time_window': now.isoformat(),
                'window_minutes': window_minutes,
                'total_events': len(window_events),
                'network_traffic_volume_mean': self._calculate_network_traffic(window_events),
                'number_of_logins_mean': event_types.get('login', 0) / window_minutes,
                'number_of_failed_logins_mean': event_types.get('failed_login', 0) / window_minutes,
                'number_of_accessed_files_mean': event_types.get('file_access', 0) / window_minutes,
                'number_of_processes_mean': event_types.get('process_creation', 0) / window_minutes,
                'number_of_network_connections_mean': event_types.get('network_connection', 0) / window_minutes
            }
            
            features_list.append(features)
        
        # Convert to DataFrame
        if features_list:
            return pd.DataFrame(features_list)
        else:
            return pd.DataFrame()
    
    def _calculate_network_traffic(self, events: List[Dict[str, Any]]) -> float:
        """
        Calculate network traffic volume from events.
        
        Args:
            events: List of security events
            
        Returns:
            Network traffic volume in bytes per minute
        """
        total_bytes = 0
        for event in events:
            if event.get('type') == 'network_connection':
                total_bytes += event.get('bytes_transferred', 0)
        
        # Normalize to bytes per minute
        window_minutes = 10  # Default window
        return total_bytes / window_minutes
```

### Step 2: Update the Connector Manager

Modify `real_time_detection/connectors/connector_manager.py` to include your new connector:

```python
# Import your new connector
from .my_connector import MyConnector

# In the initialize_connectors method, add:
# Initialize MyConnector if configured
if 'my_security_tool' in data_sources and data_sources['my_security_tool'].get('enabled', False):
    try:
        my_config = data_sources['my_security_tool']
        self.logger.info("Initializing MyConnector")
        
        my_connector = MyConnector(
            api_url=my_config.get('api_url', ''),
            api_key=my_config.get('api_key', ''),
            verify_ssl=my_config.get('verify_ssl', True)
        )
        
        self.connectors['my_security_tool'] = my_connector
        self.logger.info("MyConnector initialized")
    except Exception as e:
        self.logger.error(f"Error initializing MyConnector: {str(e)}")
```

### Step 3: Update the Configuration

Add your connector configuration to `config.yaml`:

```yaml
data_sources:
  my_security_tool:
    enabled: true
    api_url: "https://mysecuritytool.example.com/api"
    api_key: "your-api-key"
    verify_ssl: true
    fetch_interval: 60
```

### Step 4: Test Your Connector

Create a test script to verify your connector works correctly:

```python
import logging
from real_time_detection.connectors.connector_manager import ConnectorManager

# Set up logging
logging.basicConfig(level=logging.INFO)

# Create connector manager
manager = ConnectorManager()

# Get your connector
my_connector = manager.get_connector('my_security_tool')
if my_connector:
    # Get events
    events = my_connector.get_security_events(limit=10)
    print(f"Retrieved {len(events)} events")
    
    # Extract features
    features = my_connector.extract_features(events)
    print(f"Extracted features for {len(features)} entities")
    print(features.head())
else:
    print("MyConnector not initialized")
```

## Best Practices for Connector Development

1. **Error Handling**: Implement robust error handling to ensure the connector can recover from failures.

2. **Logging**: Use the logging module to provide detailed information about connector operations.

3. **Rate Limiting**: Respect API rate limits to avoid being blocked by the data source.

4. **Authentication**: Securely handle authentication credentials.

5. **Feature Normalization**: Normalize features to a common scale (0-1 or z-score) to ensure compatibility with the prediction engine.

6. **Caching**: Implement caching to reduce API calls and improve performance.

7. **Pagination**: Handle pagination for APIs that limit the number of results per request.

8. **Timeouts**: Set appropriate timeouts for API requests to prevent hanging.

9. **Retry Logic**: Implement retry logic for transient failures.

10. **Documentation**: Document your connector thoroughly, including configuration parameters and extracted features.

## Troubleshooting Connectors

### Common Issues

1. **Connection Failures**:
   - Check network connectivity
   - Verify API URL is correct
   - Ensure authentication credentials are valid
   - Check SSL certificate if using HTTPS

2. **Authentication Errors**:
   - Verify username/password or API key
   - Check if the API key has expired
   - Ensure the account has the necessary permissions

3. **Data Retrieval Issues**:
   - Check API rate limits
   - Verify query parameters
   - Ensure the data source has events in the specified time range

4. **Feature Extraction Issues**:
   - Check if events have the expected structure
   - Verify that required fields are present in the events
   - Ensure feature calculations are correct

### Debugging

1. **Enable Debug Logging**:
   ```python
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **Print API Responses**:
   ```python
   response = requests.get(...)
   print(f"Status Code: {response.status_code}")
   print(f"Response: {response.text}")
   ```

3. **Test Individual Methods**:
   ```python
   # Test connection
   connector.test_connection()
   
   # Test event retrieval
   events = connector.get_security_events(limit=5)
   print(events)
   
   # Test feature extraction
   features = connector.extract_features(events)
   print(features)
   ```

## Conclusion

The connector architecture in the APT Detection System provides a flexible, extensible way to integrate with various security data sources. By following the guidelines in this document, you can effectively use existing connectors and develop new ones to meet your specific security monitoring needs.
