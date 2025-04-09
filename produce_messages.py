from kafka import KafkaProducer
import json
import random
import time
import argparse
from datetime import datetime

def produce_messages(num_messages=20, include_anomalies=True):
    """
    Produce test messages for the APT detection system.
    These messages simulate security events with features that the system expects.
    
    Args:
        num_messages: Number of messages to generate
        include_anomalies: Whether to include anomalous events
    """
    # Entity names for variation
    entities = ['host1', 'host2', 'host3', 'workstation4', 'server5', 'laptop6']
    
    try:
        # Create Kafka producer
        producer = KafkaProducer(
            bootstrap_servers='localhost:9092',
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        
        print(f"Connected to Kafka. Generating {num_messages} messages...")
        
        # Generate test messages
        for i in range(num_messages):
            # Select a random entity
            entity = random.choice(entities)
            
            # Create a message with the expected features
            message = {
                'entity': entity,
                'network_traffic_volume_mean': random.uniform(0.1, 0.7),
                'number_of_logins_mean': random.uniform(0.1, 0.5),
                'number_of_failed_logins_mean': random.uniform(0.1, 0.3),
                'number_of_accessed_files_mean': random.uniform(0.1, 0.7),
                'number_of_email_sent_mean': random.uniform(0.1, 0.4),
                'cpu_usage_mean': random.uniform(0.1, 0.6),
                'memory_usage_mean': random.uniform(0.2, 0.6),
                'disk_io_mean': random.uniform(0.1, 0.6),
                'network_latency_mean': random.uniform(0.1, 0.5),
                'number_of_processes_mean': random.uniform(0.1, 0.6),
                'timestamp': datetime.now().isoformat()
            }
            
            # Every third message, simulate an anomalous event if enabled
            if include_anomalies and i % 3 == 0:
                # Choose which features to make anomalous
                anomalous_features = random.sample([
                    'network_traffic_volume_mean',
                    'number_of_failed_logins_mean',
                    'cpu_usage_mean',
                    'memory_usage_mean',
                    'disk_io_mean'
                ], k=random.randint(2, 3))
                
                # Make selected features anomalous
                for feature in anomalous_features:
                    message[feature] = random.uniform(0.8, 0.95)
                
                print(f"Message {i+1} is anomalous with high values for: {', '.join(anomalous_features)}")
            
            # Send the message
            producer.send('apt_topic', value=message)
            print(f"Sent message {i+1} for entity '{entity}'")
            
            # Wait a bit between messages
            time.sleep(0.5)
        
        # Ensure all messages are sent
        producer.flush()
        print(f"All {num_messages} messages sent successfully")
        
    except Exception as e:
        print(f"Error producing messages: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Produce test messages for APT detection')
    parser.add_argument('--num', type=int, default=20, help='Number of messages to generate')
    parser.add_argument('--no-anomalies', action='store_true', help='Disable anomalous events')
    args = parser.parse_args()
    
    # Produce messages
    produce_messages(num_messages=args.num, include_anomalies=not args.no_anomalies)
