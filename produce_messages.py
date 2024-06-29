from kafka import KafkaProducer

def produce_messages():
    producer = KafkaProducer(bootstrap_servers='localhost:9092')
    for i in range(10):
        message = f"Message {i}"
        producer.send('apt_topic', value=message.encode('utf-8'))
        print(f"Sent: {message}")
    producer.flush()

if __name__ == "__main__":
    produce_messages()
