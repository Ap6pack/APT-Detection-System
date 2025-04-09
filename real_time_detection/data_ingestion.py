import logging
import time
import json
import numpy as np
import os
import yaml
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from kafka import KafkaConsumer

# Import internal modules
from .prediction_engine import PredictionEngine
from .connectors.connector_manager import ConnectorManager
from . import redis_integration

# Global alerts storage
# In-memory storage as fallback if Redis is not available
alerts = []
alerts_lock = threading.Lock()

# Initialize Redis storage
redis_available = redis_integration.initialize()

class DataIngestionManager:
    """
    Data Ingestion Manager for APT detection.
    
    This class provides methods for ingesting data from multiple sources,
    processing it, and generating alerts.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the data ingestion manager.
        
        Args:
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.config = {}
        self.running = False
        self.kafka_thread = None
        self.connector_thread = None
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        
        self.load_config(config_path)
        
        # Initialize prediction engine
        self.prediction_engine = PredictionEngine(use_saved_models=True, config_path=config_path)
        
        # Initialize connector manager
        self.connector_manager = ConnectorManager(config_path)
        
        # Set up collection interval
        self.collection_interval = self.config.get('settings', {}).get('collection_interval_seconds', 60)
    
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
    
    def process_kafka_message(self, message) -> Optional[Dict[str, Any]]:
        """
        Process a message from Kafka and generate alerts.
        
        Args:
            message: The Kafka message
            
        Returns:
            Alert dictionary if an alert was generated, None otherwise
        """
        try:
            # Get the message value (could be already deserialized or still bytes)
            if isinstance(message.value, dict):
                # Already deserialized by the consumer
                data = message.value
            elif isinstance(message.value, bytes):
                # Need to deserialize
                data = json.loads(message.value.decode('utf-8'))
            else:
                # Unexpected type
                self.logger.error(f"Unexpected message value type: {type(message.value)}")
                return None
            
            self.logger.info(f"Processing Kafka message: {data}")
            
            # Extract features
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
            
            # Ensure all required features are present
            features = []
            for name in feature_names:
                if name in data:
                    features.append(float(data[name]))
                else:
                    self.logger.warning(f"Missing feature: {name}")
                    features.append(0.0)  # Default value
            
            # Convert to numpy array for prediction
            features_array = np.array(features).reshape(1, -1)
            
            # Make prediction
            result = self.prediction_engine.predict(features_array, feature_names)
            
            # Process alerts
            if result['alerts']:
                alert = result['alerts'][0]  # Get first alert
                
                # Add entity if not present (use a default or extract from message)
                if 'entity' not in alert:
                    alert['entity'] = data.get('entity', 'unknown_entity')
                
                # Add source information to alert
                alert['source'] = {
                    'type': 'kafka',
                    'topic': message.topic,
                    'partition': message.partition,
                    'offset': message.offset,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Store alert for dashboard access
                self.store_alert(alert)
                
                self.logger.info(f"Alert generated from Kafka message with severity: {alert['severity']}")
                if 'mitre_attack' in alert:
                    techniques = alert['mitre_attack']['techniques']
                    self.logger.info(f"MITRE ATT&CK techniques identified: {len(techniques)}")
                    for technique in techniques[:3]:  # Log first 3 techniques
                        self.logger.info(f"- {technique['id']}: {technique['name']}")
                
                return alert
            else:
                # Even if no alert was generated by the prediction engine,
                # create a basic alert if the message has high anomaly features
                high_anomaly_features = []
                for name, value in data.items():
                    if name in feature_names and isinstance(value, (int, float)) and value > 0.8:
                        high_anomaly_features.append(f"{name}: {value:.2f}")
                
                if high_anomaly_features:
                    # Create a basic alert
                    alert = {
                        'entity': data.get('entity', 'unknown_entity'),
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'Medium',
                        'prediction_score': 0.75,
                        'features': {name: data.get(name, 0.0) for name in feature_names},
                        'source': {
                            'type': 'kafka',
                            'topic': message.topic,
                            'partition': message.partition,
                            'offset': message.offset,
                            'timestamp': datetime.now().isoformat()
                        },
                        'message': f"Potential anomaly detected with features: {', '.join(high_anomaly_features)}"
                    }
                    
                    # Store the alert
                    self.store_alert(alert)
                    self.logger.info(f"Created basic alert for high anomaly features: {high_anomaly_features}")
                    return alert
            
            return None
            
        except json.JSONDecodeError:
            self.logger.error("Failed to parse Kafka message as JSON")
        except Exception as e:
            self.logger.error(f"Error processing Kafka message: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
        
        return None
    
    def store_alert(self, alert: Dict[str, Any]) -> None:
        """
        Store alert for dashboard access.
        
        Args:
            alert: Alert dictionary to store
        """
        global alerts, alerts_lock, redis_available
        
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        # Try to store in Redis first
        if redis_available:
            success = redis_integration.store_alert(alert)
            if success:
                return
        
        # Fallback to in-memory storage if Redis is not available or failed
        with alerts_lock:
            alerts.append(alert)
            
            # Limit to 1000 most recent alerts
            if len(alerts) > 1000:
                alerts = alerts[-1000:]
    
    def kafka_consumer_loop(self) -> None:
        """
        Run the Kafka consumer loop.
        """
        # Check if Kafka is configured
        if 'kafka' not in self.config:
            self.logger.warning("Kafka not configured, skipping Kafka consumer")
            return
        
        # Get Kafka configuration
        bootstrap_servers = self.config['kafka'].get('bootstrap_servers', 'localhost:9092')
        topic = self.config['kafka'].get('topic', 'apt_topic')
        
        # Connect to Kafka and process messages
        retries = 5
        for attempt in range(retries):
            try:
                self.logger.info(f"Connecting to Kafka at {bootstrap_servers}, topic: {topic} (attempt {attempt+1}/{retries})")
                consumer = KafkaConsumer(
                    topic, 
                    bootstrap_servers=bootstrap_servers,
                    auto_offset_reset='earliest',  # Changed from 'latest' to ensure we get all messages
                    enable_auto_commit=True,
                    group_id='apt_detection_group',  # Added group_id for better consumer management
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')) if m else None,  # Added deserializer
                    session_timeout_ms=30000,  # Increased timeout
                    request_timeout_ms=40000,
                    consumer_timeout_ms=60000
                )
                
                self.logger.info("Connected to Kafka, waiting for messages...")
                
                # Process messages while running
                while self.running:
                    try:
                        # Get messages with timeout
                        messages = consumer.poll(timeout_ms=1000)
                        
                        if not messages:
                            # No messages received, continue polling
                            continue
                            
                        self.logger.info(f"Received {sum(len(msgs) for msgs in messages.values())} messages from Kafka")
                        
                        # Process messages
                        for topic_partition, partition_messages in messages.items():
                            for message in partition_messages:
                                try:
                                    # Process message and generate alert
                                    alert = self.process_kafka_message(message)
                                    
                                    # Log message receipt
                                    if alert:
                                        self.logger.info(f"Processed Kafka message and generated alert with severity: {alert['severity']}")
                                    else:
                                        self.logger.info("Processed Kafka message, no alert generated")
                                except Exception as msg_error:
                                    self.logger.error(f"Error processing individual message: {msg_error}")
                    except Exception as poll_error:
                        self.logger.error(f"Error polling Kafka: {poll_error}")
                        # Continue the loop rather than breaking out
                        time.sleep(1)
                
                # Close consumer when done
                self.logger.info("Closing Kafka consumer")
                consumer.close()
                break
                
            except Exception as e:
                self.logger.error(f"Kafka connection error: {e}")
                time.sleep(5)
        else:
            self.logger.error("Failed to connect to Kafka after several retries")
            # Create a sample alert to indicate Kafka connection failure
            self._create_kafka_connection_failure_alert()
    
    def _create_kafka_connection_failure_alert(self):
        """Create an alert to indicate Kafka connection failure."""
        alert = {
            'entity': 'system',
            'timestamp': datetime.now().isoformat(),
            'severity': 'High',
            'prediction_score': 0.85,
            'features': {
                'connection_failure': 1.0
            },
            'source': {
                'type': 'system',
                'timestamp': datetime.now().isoformat(),
                'message': 'Failed to connect to Kafka after multiple attempts'
            },
            'message': 'Kafka connection failure detected. Check Kafka server status and configuration.'
        }
        
        # Store the alert
        self.store_alert(alert)
        self.logger.info("Created Kafka connection failure alert")
    
    def connector_collection_loop(self) -> None:
        """
        Run the connector data collection loop.
        """
        self.logger.info("Starting connector data collection loop")
        
        # Run while the manager is running
        while self.running:
            try:
                # Collect data from connectors
                data = self.connector_manager.collect_data()
                
                if not data.empty:
                    self.logger.info(f"Collected {len(data)} data points from connectors")
                    
                    # Make predictions
                    result = self.prediction_engine.predict(data)
                    
                    # Process alerts
                    for alert in result['alerts']:
                        # Add source information
                        alert['source'] = {
                            'type': 'connector',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Store alert
                        self.store_alert(alert)
                        
                        self.logger.info(f"Alert generated from connector data with severity: {alert['severity']}")
                    
                    # Process anomalies
                    for anomaly in result['anomalies']:
                        # Create alert from anomaly
                        alert = {
                            'entity': anomaly['entity'],
                            'timestamp': anomaly['timestamp'],
                            'severity': anomaly['severity'],
                            'anomaly_score': anomaly['anomaly_score'],
                            'features': anomaly['features'],
                            'source': {
                                'type': 'behavioral_analytics',
                                'timestamp': datetime.now().isoformat()
                            }
                        }
                        
                        # Store alert
                        self.store_alert(alert)
                        
                        self.logger.info(f"Anomaly alert generated for {alert['entity']} with severity: {alert['severity']}")
                
                # Sleep for the collection interval
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in connector collection loop: {str(e)}")
                time.sleep(self.collection_interval)
    
    def start(self) -> None:
        """
        Start the data ingestion process.
        """
        if self.running:
            self.logger.warning("Data ingestion already running")
            return
        
        self.logger.info("Starting data ingestion")
        self.running = True
        
        # Start Kafka consumer thread
        self.kafka_thread = threading.Thread(target=self.kafka_consumer_loop)
        self.kafka_thread.daemon = True
        self.kafka_thread.start()
        
        # Start connector collection thread
        self.connector_thread = threading.Thread(target=self.connector_collection_loop)
        self.connector_thread.daemon = True
        self.connector_thread.start()
        
        self.logger.info("Data ingestion started")
    
    def stop(self) -> None:
        """
        Stop the data ingestion process.
        """
        if not self.running:
            self.logger.warning("Data ingestion not running")
            return
        
        self.logger.info("Stopping data ingestion")
        self.running = False
        
        # Wait for threads to finish
        if self.kafka_thread:
            self.kafka_thread.join(timeout=5)
        
        if self.connector_thread:
            self.connector_thread.join(timeout=5)
        
        self.logger.info("Data ingestion stopped")

def get_alerts() -> List[Dict[str, Any]]:
    """
    Get stored alerts for dashboard access.
    
    Returns:
        List of alert dictionaries
    """
    global alerts, alerts_lock, redis_available
    
    # Try to get alerts from Redis first
    if redis_available:
        redis_alerts = redis_integration.get_alerts()
        if redis_alerts:
            return redis_alerts
    
    # Fallback to in-memory storage if Redis is not available or failed
    with alerts_lock:
        # Return a copy of the alerts list
        return alerts.copy()

def run():
    """
    Run the data ingestion process.
    
    This function is maintained for backward compatibility.
    """
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create data ingestion manager
    manager = DataIngestionManager()
    
    try:
        # Start data ingestion
        manager.start()
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        # Stop data ingestion
        manager.stop()
        
    except Exception as e:
        logging.error(f"Error in data ingestion: {str(e)}")

# Testing data ingestion
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create data ingestion manager
    manager = DataIngestionManager()
    
    # Establish baseline if needed
    if not manager.prediction_engine.behavioral_analytics.baseline_models:
        manager.prediction_engine.establish_baseline(days=7)
    
    # Start data ingestion
    manager.start()
    
    try:
        # Keep running for a while
        time.sleep(300)  # 5 minutes
        
        # Get alerts
        all_alerts = get_alerts()
        print(f"Collected {len(all_alerts)} alerts")
        
        # Print some alerts
        for i, alert in enumerate(all_alerts[:5]):
            print(f"\nAlert {i+1}:")
            print(f"Severity: {alert.get('severity', 'Unknown')}")
            print(f"Entity: {alert.get('entity', 'Unknown')}")
            print(f"Source: {alert.get('source', {}).get('type', 'Unknown')}")
            
            if 'mitre_attack' in alert:
                print("MITRE ATT&CK Techniques:")
                for technique in alert['mitre_attack']['techniques'][:3]:
                    print(f"- {technique['id']}: {technique['name']}")
        
    except KeyboardInterrupt:
        pass
    finally:
        # Stop data ingestion
        manager.stop()
