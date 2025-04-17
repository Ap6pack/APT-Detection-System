"""
Kafka Output Module

This module provides the Kafka output adapter for the simulation system.
"""

import json
import os
import subprocess
import time
from typing import Dict, Any, Optional

from kafka import KafkaProducer
from kafka.errors import KafkaError

from ..config import SimulationConfig
from .base_output import BaseOutput

class KafkaOutput(BaseOutput):
    """Kafka output adapter for the simulation system."""
    
    def __init__(self, config: SimulationConfig):
        """
        Initialize the Kafka output adapter.
        
        Args:
            config: Simulation configuration
        """
        super().__init__(config)
        
        # Get Kafka configuration
        output_config = config.get_output_config()
        kafka_config = config.get('kafka', {})
        
        self.bootstrap_servers = kafka_config.get('bootstrap_servers', 'localhost:9092')
        self.topic = output_config.get('kafka_topic', kafka_config.get('topic', 'apt_topic'))
        
        # Initialize Kafka producer with retry logic
        self.producer = self._initialize_kafka_producer(max_retries=3)
    
    def _initialize_kafka_producer(self, max_retries: int = 3) -> Optional[KafkaProducer]:
        """
        Initialize Kafka producer with retry logic and error handling.
        
        Args:
            max_retries: Maximum number of retry attempts
            
        Returns:
            KafkaProducer instance or None if initialization fails
        """
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Connecting to Kafka broker at {self.bootstrap_servers} (attempt {attempt+1}/{max_retries})")
                producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    acks='all'
                )
                self.logger.info(f"Connected to Kafka broker at {self.bootstrap_servers}")
                
                # Ensure topic exists
                self._ensure_topic_exists()
                
                return producer
            except Exception as e:
                error_message = str(e)
                self.logger.error(f"Error connecting to Kafka broker: {error_message}")
                
                # Check for cluster ID mismatch error
                if "Invalid cluster.id" in error_message:
                    self.logger.warning("Detected Kafka cluster ID mismatch. Cleaning up Kafka logs...")
                    if self._cleanup_kafka_logs():
                        self.logger.info("Kafka logs cleaned up. Restarting Kafka...")
                        if self._restart_kafka():
                            self.logger.info("Kafka restarted successfully. Retrying connection...")
                            time.sleep(5)  # Wait for Kafka to initialize
                            continue
                
                # If this is the last attempt, log a more detailed error
                if attempt == max_retries - 1:
                    self.logger.error("Failed to connect to Kafka after multiple attempts")
                else:
                    time.sleep(2)  # Wait before retrying
        
        return None
    
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
    
    def _ensure_topic_exists(self) -> None:
        """Ensure that the Kafka topic exists."""
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
                    self.logger.info(f"Checking if Kafka topic exists: {self.topic}")
                    check_cmd = f"{kafka_topics_script} --list --bootstrap-server {self.bootstrap_servers}"
                    self.logger.info(f"Executing: {check_cmd}")
                    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, check=False)
                    
                    if result.returncode != 0:
                        self.logger.warning(f"Error checking Kafka topics: {result.stderr}")
                        return
                    
                    topics = result.stdout.strip().split("\n")
                    
                    if self.topic not in topics:
                        self.logger.info(f"Creating Kafka topic: {self.topic}")
                        create_cmd = f"{kafka_topics_script} --create --topic {self.topic} --bootstrap-server {self.bootstrap_servers} --partitions 1 --replication-factor 1"
                        self.logger.info(f"Executing: {create_cmd}")
                        create_result = subprocess.run(create_cmd, shell=True, capture_output=True, text=True, check=False)
                        
                        if create_result.returncode == 0:
                            self.logger.info(f"Kafka topic created: {self.topic}")
                        else:
                            self.logger.error(f"Error creating Kafka topic: {create_result.stderr}")
                    else:
                        self.logger.info(f"Kafka topic already exists: {self.topic}")
                else:
                    self.logger.error(f"Kafka topics script not found at {kafka_topics_script}")
            else:
                self.logger.error("Kafka installation directory not found")
        except Exception as e:
            self.logger.error(f"Error ensuring topic exists: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send an event to Kafka.
        
        Args:
            event: Event data
            
        Returns:
            True if the event was sent successfully, False otherwise
        """
        if not self.producer:
            self.logger.error("Kafka producer not initialized")
            return False
        
        try:
            # Format the event
            formatted_event = self._format_event(event)
            
            # Send the event to Kafka
            future = self.producer.send(self.topic, formatted_event)
            
            # Wait for the result
            record_metadata = future.get(timeout=10)
            
            self.logger.debug(f"Sent event to Kafka topic {self.topic} partition {record_metadata.partition} offset {record_metadata.offset}")
            return True
        except KafkaError as e:
            self.logger.error(f"Error sending event to Kafka: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending event to Kafka: {str(e)}")
            return False
    
    def _format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format an event for Kafka output.
        
        Args:
            event: Event data
            
        Returns:
            Formatted event data
        """
        # Apply base formatting
        formatted_event = super()._format_event(event)
        
        # Add Kafka-specific formatting
        if 'detection_type' not in formatted_event:
            formatted_event['detection_type'] = 'simulation'
        
        return formatted_event
