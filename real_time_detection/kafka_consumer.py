from kafka import KafkaConsumer

def consume():
    consumer = KafkaConsumer('apt_topic', bootstrap_servers='localhost:9092')
    for message in consumer:
        # Process the message
        print(message.value)

# Testing Kafka consumer
if __name__ == "__main__":
    consume()
