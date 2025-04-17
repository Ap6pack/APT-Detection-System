import logging
import time
import json
import numpy as np
import os
import yaml
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
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
            
            # Check if this is a simulation event
            is_simulation = data.get('is_simulated', False) or data.get('source', {}).get('type', '') == 'simulation'
            
            # Extract event type and entity type for MITRE ATT&CK mapping
            event_type = data.get('event_type', '')
            entity_type = data.get('entity_type', 'host')
            
            if is_simulation:
                # For simulation events, extract features from event data
                features, feature_names = self._extract_features_from_simulation_event(data)
            else:
                # For regular events, use standard features
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
            
            # Make prediction
            try:
                # Convert features to a pandas DataFrame with proper feature names
                import pandas as pd
                features_df = pd.DataFrame([features], columns=feature_names)
                
                # Log the features for debugging
                self.logger.debug(f"Prediction features: {dict(zip(feature_names, features))}")
                
                # Make prediction using DataFrame instead of numpy array
                result = self.prediction_engine.predict(features_df)
            except Exception as e:
                self.logger.error(f"Error making predictions: {str(e)}")
                import traceback
                self.logger.error(traceback.format_exc())
                # Create a basic alert for simulation events even if prediction fails
                if is_simulation:
                    return self._create_simulation_alert(data)
                return None
            
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
                        'entity_type': entity_type,
                        'event_type': event_type,
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
                
                # Try to create the consumer
                try:
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
                except Exception as consumer_error:
                    error_message = str(consumer_error)
                    self.logger.error(f"Error creating Kafka consumer: {error_message}")
                    
                    # Check for cluster ID mismatch error
                    if "Invalid cluster.id" in error_message:
                        self.logger.warning("Detected Kafka cluster ID mismatch. Cleaning up Kafka logs...")
                        if self._cleanup_kafka_logs():
                            self.logger.info("Kafka logs cleaned up. Restarting Kafka...")
                            if self._restart_kafka():
                                self.logger.info("Kafka restarted successfully. Retrying connection...")
                                time.sleep(5)  # Wait for Kafka to initialize
                                continue
                    
                    # For other errors, just wait and retry
                    time.sleep(5)
                    continue
                
                # Ensure topic exists
                self._ensure_topic_exists(topic, bootstrap_servers)
                
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
    
    def _cleanup_kafka_logs(self) -> bool:
        """
        Clean up Kafka logs to resolve cluster ID mismatch.
        
        Returns:
            True if cleanup was successful, False otherwise
        """
        try:
            # Stop Kafka and ZooKeeper if they're running
            self._stop_kafka_and_zookeeper()
            
            # Remove Kafka logs
            kafka_logs_dir = "/tmp/kafka-logs"
            zookeeper_data_dir = "/tmp/zookeeper"
            
            if os.path.exists(kafka_logs_dir):
                self.logger.info(f"Removing Kafka logs directory: {kafka_logs_dir}")
                subprocess.run(["rm", "-rf", kafka_logs_dir], check=True)
            
            if os.path.exists(zookeeper_data_dir):
                self.logger.info(f"Removing ZooKeeper data directory: {zookeeper_data_dir}")
                subprocess.run(["rm", "-rf", zookeeper_data_dir], check=True)
            
            return True
        except Exception as e:
            self.logger.error(f"Error cleaning up Kafka logs: {str(e)}")
            return False
    
    def _stop_kafka_and_zookeeper(self) -> None:
        """Stop Kafka and ZooKeeper servers if they're running."""
        try:
            # Find Kafka installation directory - use absolute path
            kafka_dir = None
            current_dir = os.getcwd()
            
            # Try direct path first
            if os.path.exists(os.path.join(current_dir, "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(current_dir, "kafka_2.13-3.8.0")
            # Try parent directory
            elif os.path.exists(os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")
            # Try relative paths as fallback
            else:
                for path in ["kafka_2.13-3.8.0", "../kafka_2.13-3.8.0", "../../kafka_2.13-3.8.0"]:
                    if os.path.exists(path):
                        kafka_dir = os.path.abspath(path)
                        break
            
            if kafka_dir:
                self.logger.info(f"Found Kafka installation at {kafka_dir}")
                
                # Stop Kafka
                kafka_stop_script = os.path.join(kafka_dir, "bin", "kafka-server-stop.sh")
                if os.path.exists(kafka_stop_script):
                    self.logger.info("Stopping Kafka server...")
                    # Use shell=True to ensure proper execution in different environments
                    kafka_stop_command = f"{kafka_stop_script}"
                    self.logger.info(f"Executing: {kafka_stop_command}")
                    subprocess.run(kafka_stop_command, shell=True, check=False)
                
                # Stop ZooKeeper
                zk_stop_script = os.path.join(kafka_dir, "bin", "zookeeper-server-stop.sh")
                if os.path.exists(zk_stop_script):
                    self.logger.info("Stopping ZooKeeper server...")
                    # Use shell=True to ensure proper execution in different environments
                    zk_stop_command = f"{zk_stop_script}"
                    self.logger.info(f"Executing: {zk_stop_command}")
                    subprocess.run(zk_stop_command, shell=True, check=False)
                
                # Wait for processes to stop
                self.logger.info("Waiting for Kafka and ZooKeeper to stop...")
                time.sleep(10)
                
                # Check if Kafka is still running
                try:
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    result = s.connect_ex(('localhost', 9092))
                    s.close()
                    if result == 0:
                        self.logger.warning("Kafka is still running on port 9092 after stop command")
                    else:
                        self.logger.info("Confirmed Kafka is no longer running on port 9092")
                except Exception as e:
                    self.logger.error(f"Error checking Kafka port: {str(e)}")
            else:
                self.logger.error("Kafka installation directory not found")
                # Try to find Kafka in common locations
                self.logger.info("Searching for Kafka in common locations...")
                for path in ["/opt/kafka", "/usr/local/kafka", "/home/localhost/kafka"]:
                    if os.path.exists(path):
                        self.logger.info(f"Found potential Kafka installation at {path}")
        except Exception as e:
            self.logger.error(f"Error stopping Kafka and ZooKeeper: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def _restart_kafka(self) -> bool:
        """
        Restart Kafka and ZooKeeper servers.
        
        Returns:
            True if restart was successful, False otherwise
        """
        try:
            # Find Kafka installation directory - use absolute path
            kafka_dir = None
            current_dir = os.getcwd()
            
            # Try direct path first
            if os.path.exists(os.path.join(current_dir, "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(current_dir, "kafka_2.13-3.8.0")
            # Try parent directory
            elif os.path.exists(os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")
            # Try relative paths as fallback
            else:
                for path in ["kafka_2.13-3.8.0", "../kafka_2.13-3.8.0", "../../kafka_2.13-3.8.0"]:
                    if os.path.exists(path):
                        kafka_dir = os.path.abspath(path)
                        break
            
            if kafka_dir:
                self.logger.info(f"Found Kafka installation at {kafka_dir}")
                
                # Start ZooKeeper with full path
                zk_start_script = os.path.join(kafka_dir, "bin", "zookeeper-server-start.sh")
                zk_config = os.path.join(kafka_dir, "config", "zookeeper.properties")
                
                if os.path.exists(zk_start_script) and os.path.exists(zk_config):
                    self.logger.info("Starting ZooKeeper server...")
                    # Use shell=True to ensure proper execution in different environments
                    zk_command = f"{zk_start_script} -daemon {zk_config}"
                    self.logger.info(f"Executing: {zk_command}")
                    subprocess.run(zk_command, shell=True, check=False)
                    
                    # Wait for ZooKeeper to initialize
                    self.logger.info("Waiting for ZooKeeper to initialize...")
                    time.sleep(10)
                    
                    # Start Kafka with full path
                    kafka_start_script = os.path.join(kafka_dir, "bin", "kafka-server-start.sh")
                    kafka_config = os.path.join(kafka_dir, "config", "server.properties")
                    
                    if os.path.exists(kafka_start_script) and os.path.exists(kafka_config):
                        self.logger.info("Starting Kafka server...")
                        # Use shell=True to ensure proper execution in different environments
                        kafka_command = f"{kafka_start_script} -daemon {kafka_config}"
                        self.logger.info(f"Executing: {kafka_command}")
                        subprocess.run(kafka_command, shell=True, check=False)
                        
                        # Wait for Kafka to initialize
                        self.logger.info("Waiting for Kafka to initialize...")
                        time.sleep(15)
                        
                        # Verify Kafka is running by checking if port 9092 is open
                        self.logger.info("Verifying Kafka is running...")
                        for _ in range(5):  # Try 5 times
                            try:
                                import socket
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.settimeout(1)
                                result = s.connect_ex(('localhost', 9092))
                                s.close()
                                if result == 0:
                                    self.logger.info("Kafka is running on port 9092")
                                    return True
                                else:
                                    self.logger.warning("Kafka not yet running on port 9092, waiting...")
                                    time.sleep(3)
                            except Exception as e:
                                self.logger.error(f"Error checking Kafka port: {str(e)}")
                                time.sleep(3)
                        
                        self.logger.warning("Could not verify Kafka is running, but continuing anyway")
                        return True
                    else:
                        self.logger.error(f"Kafka start script or config not found at {kafka_start_script} or {kafka_config}")
                else:
                    self.logger.error(f"ZooKeeper start script or config not found at {zk_start_script} or {zk_config}")
            else:
                self.logger.error("Kafka installation directory not found")
                # Try to find Kafka in common locations
                self.logger.info("Searching for Kafka in common locations...")
                for path in ["/opt/kafka", "/usr/local/kafka", "/home/localhost/kafka"]:
                    if os.path.exists(path):
                        self.logger.info(f"Found potential Kafka installation at {path}")
            
            return False
        except Exception as e:
            self.logger.error(f"Error restarting Kafka: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    def _ensure_topic_exists(self, topic: str, bootstrap_servers: str) -> None:
        """
        Ensure that the Kafka topic exists.
        
        Args:
            topic: Kafka topic name
            bootstrap_servers: Kafka bootstrap servers
        """
        try:
            # Find Kafka installation directory - use absolute path
            kafka_dir = None
            current_dir = os.getcwd()
            
            # Try direct path first
            if os.path.exists(os.path.join(current_dir, "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(current_dir, "kafka_2.13-3.8.0")
            # Try parent directory
            elif os.path.exists(os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")):
                kafka_dir = os.path.join(os.path.dirname(current_dir), "kafka_2.13-3.8.0")
            # Try relative paths as fallback
            else:
                for path in ["kafka_2.13-3.8.0", "../kafka_2.13-3.8.0", "../../kafka_2.13-3.8.0"]:
                    if os.path.exists(path):
                        kafka_dir = os.path.abspath(path)
                        break
            
            if kafka_dir:
                # Create topic if it doesn't exist
                kafka_topics_script = os.path.join(kafka_dir, "bin", "kafka-topics.sh")
                if os.path.exists(kafka_topics_script):
                    # Check if topic exists
                    self.logger.info(f"Checking if Kafka topic exists: {topic}")
                    check_cmd = f"{kafka_topics_script} --list --bootstrap-server {bootstrap_servers}"
                    self.logger.info(f"Executing: {check_cmd}")
                    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, check=False)
                    
                    if result.returncode != 0:
                        self.logger.warning(f"Error checking Kafka topics: {result.stderr}")
                        return
                    
                    topics = result.stdout.strip().split("\n")
                    
                    if topic not in topics:
                        self.logger.info(f"Creating Kafka topic: {topic}")
                        create_cmd = f"{kafka_topics_script} --create --topic {topic} --bootstrap-server {bootstrap_servers} --partitions 1 --replication-factor 1"
                        self.logger.info(f"Executing: {create_cmd}")
                        create_result = subprocess.run(create_cmd, shell=True, capture_output=True, text=True, check=False)
                        
                        if create_result.returncode == 0:
                            self.logger.info(f"Kafka topic created: {topic}")
                        else:
                            self.logger.error(f"Error creating Kafka topic: {create_result.stderr}")
                    else:
                        self.logger.info(f"Kafka topic already exists: {topic}")
                else:
                    self.logger.error(f"Kafka topics script not found at {kafka_topics_script}")
            else:
                self.logger.error("Kafka installation directory not found")
        except Exception as e:
            self.logger.error(f"Error ensuring topic exists: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def _extract_features_from_simulation_event(self, data: Dict[str, Any]) -> Tuple[List[float], List[str]]:
        """
        Extract features from a simulation event.
        
        Args:
            data: Simulation event data
            
        Returns:
            Tuple of (list of feature values, list of feature names)
        """
        # Define feature names - these must match exactly what the model expects
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
        
        # Initialize features with default values
        features = [0.0] * len(feature_names)
        
        # Extract features based on event type
        event_type = data.get('event_type', '')
        
        if event_type == 'network_connection':
            # Network connection event
            features[0] = float(data.get('bytes_sent', 0)) / 10000.0  # Normalize network traffic
            features[8] = float(data.get('connection_duration', 0)) / 300.0  # Normalize latency
            
            # Check for suspicious destination ports
            suspicious_ports = [22, 3389, 445, 1433, 3306, 5432, 8080, 8443]
            if data.get('destination_port') in suspicious_ports:
                features[0] += 0.3  # Increase network traffic score
        
        elif event_type == 'process':
            # Process event
            features[9] = 0.5  # Base process activity
            
            # Check for suspicious process names
            suspicious_processes = ['cmd.exe', 'powershell.exe', 'bash', 'sh', 'python', 'nc', 'nmap']
            if any(proc in data.get('process_name', '') for proc in suspicious_processes):
                features[9] += 0.3  # Increase process score
            
            # Check for suspicious command lines
            if 'command_line' in data:
                cmd = data['command_line'].lower()
                if any(term in cmd for term in ['password', 'secret', 'admin', 'sudo', 'wget', 'curl']):
                    features[9] += 0.2  # Increase process score
        
        elif event_type == 'authentication':
            # Authentication event
            if data.get('authentication_status') == 'success':
                features[1] = 0.5  # Login activity
            else:
                features[2] = 0.7  # Failed login (higher score)
        
        elif event_type == 'file':
            # File event
            features[3] = 0.5  # File access activity
            
            # Check for suspicious file operations
            if data.get('action') in ['created', 'modified', 'deleted']:
                features[3] += 0.2  # Increase file activity score
            
            # Check for suspicious file extensions
            suspicious_extensions = ['.exe', '.dll', '.sh', '.bat', '.ps1', '.py']
            if any(ext in data.get('file_extension', '') for ext in suspicious_extensions):
                features[3] += 0.3  # Increase file activity score
        
        # Add severity as a general indicator
        severity = data.get('severity', 'Low')
        severity_score = {'Low': 0.2, 'Medium': 0.5, 'High': 0.8, 'Critical': 1.0}.get(severity, 0.2)
        
        # Adjust all features based on severity
        for i in range(len(features)):
            features[i] = min(1.0, features[i] + (severity_score * 0.2))
        
        # Ensure all features are float type
        features = [float(f) for f in features]
        
        self.logger.debug(f"Extracted features for {event_type} event: {dict(zip(feature_names, features))}")
        
        return features, feature_names
    
    def _create_simulation_alert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an alert from a simulation event when prediction fails.
        
        Args:
            data: Simulation event data
            
        Returns:
            Alert dictionary
        """
        # Determine severity based on event type and data
        event_type = data.get('event_type', '')
        severity = data.get('severity', 'Low')
        
        # Increase severity for certain event types
        if event_type == 'network_connection' and data.get('destination_port') in [22, 3389, 445]:
            severity = 'Medium'
        elif event_type == 'process' and any(proc in data.get('process_name', '') for proc in ['cmd.exe', 'powershell.exe']):
            severity = 'Medium'
        elif event_type == 'authentication' and data.get('authentication_status') == 'failure':
            severity = 'Medium'
        
        # Create alert
        alert = {
            'entity': data.get('entity', 'unknown_entity'),
            'entity_type': data.get('entity_type', 'host'),
            'timestamp': data.get('timestamp', datetime.now().isoformat()),
            'severity': severity,
            'prediction_score': 0.7,
            'detection_type': 'simulation',
            'event_type': event_type,
            'source': data.get('source', {'type': 'simulation'}),
            'message': f"Simulation event detected: {event_type}"
        }
        
        # Add event-specific details
        if event_type == 'network_connection':
            alert['details'] = {
                'source_ip': data.get('source_ip', ''),
                'destination_ip': data.get('destination_ip', ''),
                'destination_port': data.get('destination_port', ''),
                'protocol': data.get('protocol', '')
            }
        elif event_type == 'process':
            alert['details'] = {
                'process_name': data.get('process_name', ''),
                'command_line': data.get('command_line', '')
            }
        elif event_type == 'authentication':
            alert['details'] = {
                'authentication_status': data.get('authentication_status', ''),
                'user_name': data.get('user_name', '')
            }
        
        # Store the alert
        self.store_alert(alert)
        self.logger.info(f"Created simulation alert for {event_type} event with severity: {severity}")
        
        return alert
    
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
                            'entity_type': anomaly.get('entity_type', 'host'),
                            'event_type': anomaly.get('event_type', ''),
                            'timestamp': anomaly['timestamp'],
                            'severity': anomaly['severity'],
                            'anomaly_score': anomaly['anomaly_score'],
                            'prediction_score': anomaly['anomaly_score'],  # Use anomaly score as prediction score
                            'features': anomaly['features'],
                            'detection_type': 'behavioral_analytics',
                            'source': {
                                'type': 'behavioral_analytics',
                                'timestamp': datetime.now().isoformat()
                            }
                        }
                        
                        # Enrich with MITRE ATT&CK information
                        from .mitre_attack_mapping import enrich_alert_with_mitre_attack
                        alert = enrich_alert_with_mitre_attack(alert)
                        
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
