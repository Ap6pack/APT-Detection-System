from kafka import KafkaConsumer
import json
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def consume():
    """
    Consume messages from the Kafka topic and process them.
    This is a simple test consumer that displays the received messages.
    For production use, see the implementation in data_ingestion.py.
    """
    logger.info("Starting Kafka consumer for apt_topic")
    
    # Create consumer with JSON deserializer
    consumer = KafkaConsumer(
        'apt_topic', 
        bootstrap_servers='localhost:9092',
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='latest'
    )
    
    try:
        # Process messages
        for message in consumer:
            # Extract data from message
            data = message.value
            
            # Log message receipt
            logger.info(f"Received message from partition {message.partition}, offset {message.offset}")
            
            # Check for anomalous features
            anomalous_features = []
            for feature, value in data.items():
                if feature.endswith('_mean') and isinstance(value, (int, float)) and value > 0.7:
                    anomalous_features.append(f"{feature}: {value:.2f}")
            
            # Log anomalous features if any
            if anomalous_features:
                logger.warning(f"Potential anomaly detected with features: {', '.join(anomalous_features)}")
            else:
                logger.info("No anomalies detected in message")
            
            # Print full message for debugging
            logger.debug(f"Message data: {json.dumps(data, indent=2)}")
            
    except KeyboardInterrupt:
        logger.info("Consumer stopped by user")
    except Exception as e:
        logger.error(f"Error consuming messages: {str(e)}")
    finally:
        # Close consumer
        consumer.close()
        logger.info("Consumer closed")

# Testing Kafka consumer
if __name__ == "__main__":
    consume()
