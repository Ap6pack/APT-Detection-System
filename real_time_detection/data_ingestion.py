from kafka import KafkaConsumer
import logging
import time

def run():
    retries = 5
    for _ in range(retries):
        try:
            consumer = KafkaConsumer('apt_topic', bootstrap_servers='localhost:9092')
            for message in consumer:
                # Process incoming message
                logging.info(f"Received message: {message.value}")
            break
        except Exception as e:
            logging.error(f"Kafka connection error: {e}")
            time.sleep(5)
    else:
        logging.error("Failed to connect to Kafka after several retries")
