# Kafka Integration for APT Detection System

This document provides detailed information about the Kafka integration in the APT Detection System, including how it works, why it's optional, how to configure it, and how to troubleshoot common issues.

## Overview

Kafka is used in the APT Detection System as a high-throughput, real-time data streaming platform that enables the ingestion of security events from multiple sources. It serves as one of several possible data input mechanisms for the system.

## Why Kafka is Optional

The APT Detection System is designed with a flexible, multi-source data ingestion architecture that can operate with different combinations of data sources:

1. **Multiple Data Source Support**: The system includes a `ConnectorManager` that can collect data from various security tools:
   - Wazuh (EDR/SIEM)
   - Elasticsearch
   - Other connectors can be added

2. **Fallback Mechanisms**: The system has built-in fallback mechanisms:
   ```python
   # Check if Kafka is configured
   if 'kafka' not in self.config:
       self.logger.warning("Kafka not configured, skipping Kafka consumer")
       return
   ```
   This shows that the system will continue to function even without Kafka, by:
   - Skipping the Kafka consumer if not configured
   - Still collecting data from other sources via the connector system
   - Generating alerts from these alternative data sources

3. **Deployment Flexibility**: Not all environments need or can support Kafka's infrastructure requirements

## When to Use Kafka

You should integrate Kafka when:

- You need high-throughput, real-time data streaming
- You have multiple data producers and consumers
- You want a scalable message queue between your data sources and the APT detection system
- You need guaranteed message delivery with persistence
- You have a distributed architecture where components run on different machines

## When to Skip Kafka

You might skip Kafka when:

- You're using a simpler deployment with direct connector integrations
- Your data volume doesn't require Kafka's throughput capabilities
- You want to reduce operational complexity
- You're in a resource-constrained environment

## How Kafka Integration Works

### Architecture

The Kafka integration consists of the following components:

1. **Kafka Consumer**: Implemented in `real_time_detection/kafka_consumer.py`
   - Connects to Kafka brokers
   - Subscribes to specified topics
   - Processes messages in real-time

2. **Message Processing**: Implemented in `real_time_detection/data_ingestion.py`
   - Extracts features from Kafka messages
   - Passes features to the prediction engine
   - Generates alerts based on prediction results

3. **Test Producer**: Implemented in `produce_messages.py`
   - Generates test messages for Kafka
   - Useful for testing the system without real data sources

### Data Flow

1. Security events are published to Kafka topics by external systems
2. The Kafka consumer subscribes to these topics and receives messages
3. Messages are processed to extract features
4. Features are passed to the prediction engine
5. Alerts are generated based on prediction results
6. Alerts are stored in Redis for persistence and sharing

## Installation and Configuration

### Prerequisites

- Java Development Kit (JDK) 11 or higher
- Kafka 2.13-3.8.0 or higher
- Python 3.8 or higher with kafka-python package

### Installing Kafka

1. Download Kafka from the [official Apache website](https://kafka.apache.org/downloads)
   - Select the latest stable release (e.g., 3.5.x)
   - Download the binary distribution (e.g., kafka_2.13-3.5.1.tgz)
   - Extract the archive to your preferred location

2. Start Zookeeper and Kafka servers:
   ```bash
   # Navigate to the Kafka directory
   cd kafka_2.13-3.5.1
   
   # Start Zookeeper first
   ./bin/zookeeper-server-start.sh config/zookeeper.properties
   
   # In a new terminal, start Kafka
   ./bin/kafka-server-start.sh config/server.properties
   ```

3. Create a topic for APT detection:
   ```bash
   ./bin/kafka-topics.sh --create --topic apt-topic --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
   ```

4. Verify the topic was created:
   ```bash
   ./bin/kafka-topics.sh --list --bootstrap-server localhost:9092
   ```

### Configuring the APT Detection System

Edit the `config.yaml` file to include Kafka configuration:

```yaml
kafka:
  bootstrap_servers: "localhost:9092"
  topic: "apt-topic"
  group_id: "apt_detection_group"
  auto_offset_reset: "earliest"
  enable_auto_commit: true
  session_timeout_ms: 30000
  request_timeout_ms: 40000
  consumer_timeout_ms: 60000
```

### Configuration Parameters

- **bootstrap_servers**: Comma-separated list of Kafka broker addresses
- **topic**: The Kafka topic to subscribe to
- **group_id**: Consumer group ID for load balancing
- **auto_offset_reset**: Where to start consuming from if no offset is stored
  - "earliest": Start from the beginning of the topic
  - "latest": Start from the end of the topic
- **enable_auto_commit**: Whether to automatically commit offsets
- **session_timeout_ms**: The timeout used to detect consumer failures
- **request_timeout_ms**: The timeout for client requests
- **consumer_timeout_ms**: The timeout for the consumer to poll for messages

## Testing the Kafka Integration

You can test the Kafka integration using the provided `produce_messages.py` script:

```bash
python produce_messages.py --num 20
```

This will generate 20 test messages and send them to the Kafka topic. The APT Detection System will process these messages and generate alerts if anomalies are detected.

## Troubleshooting

### Kafka Connection Issues

If the system is unable to connect to Kafka, check the following:

1. **Kafka Server Running**: Verify that Kafka and Zookeeper are running:
   ```bash
   # Check Zookeeper
   echo ruok | nc localhost 2181
   # Should return "imok"
   
   # Check Kafka
   nc -z localhost 9092
   # Should return success
   ```

2. **Firewall Settings**: Ensure that the firewall allows connections to Kafka (port 9092) and Zookeeper (port 2181).

3. **Configuration**: Verify that the bootstrap_servers in config.yaml matches your Kafka broker addresses.

4. **Logs**: Check the Kafka server logs for errors:
   ```bash
   cat kafka_2.13-3.5.1/logs/server.log
   ```

### Kafka Server Crashes

If the Kafka server crashes unexpectedly, check the following:

1. **Memory Allocation**: Increase memory allocation:
   ```bash
   export KAFKA_HEAP_OPTS="-Xmx512M -Xms512M"
   ```

2. **Disk Space**: Ensure that there is enough disk space for Kafka logs.

3. **Log Retention**: Adjust log retention settings in `config/server.properties`:
   ```
   log.retention.hours=168
   log.retention.bytes=1073741824
   ```

4. **JVM Settings**: Adjust JVM settings in `bin/kafka-server-start.sh`.

### Message Processing Issues

If messages are received but not processed correctly, check the following:

1. **Message Format**: Ensure that the messages have the expected format.

2. **Feature Names**: Verify that the feature names in the messages match the expected feature names in the system.

3. **Deserialization**: Check for deserialization errors in the logs.

4. **Consumer Group**: Ensure that the consumer group ID is unique if you have multiple instances of the system.

## Advanced Configuration

### Multiple Topics

You can configure the system to consume from multiple topics:

```yaml
kafka:
  bootstrap_servers: "localhost:9092"
  topics:
    - "apt-topic-1"
    - "apt-topic-2"
  # Other settings...
```

### Security

To enable security features:

1. **SSL/TLS**:
   ```yaml
   kafka:
     bootstrap_servers: "localhost:9092"
     security_protocol: "SSL"
     ssl_cafile: "/path/to/ca.pem"
     ssl_certfile: "/path/to/cert.pem"
     ssl_keyfile: "/path/to/key.pem"
     # Other settings...
   ```

2. **SASL Authentication**:
   ```yaml
   kafka:
     bootstrap_servers: "localhost:9092"
     security_protocol: "SASL_SSL"
     sasl_mechanism: "PLAIN"
     sasl_plain_username: "user"
     sasl_plain_password: "password"
     # Other settings...
   ```

### Performance Tuning

To optimize performance:

1. **Batch Size**:
   ```yaml
   kafka:
     bootstrap_servers: "localhost:9092"
     fetch_max_bytes: 52428800
     max_partition_fetch_bytes: 1048576
     # Other settings...
   ```

2. **Compression**:
   ```yaml
   kafka:
     bootstrap_servers: "localhost:9092"
     compression_type: "snappy"
     # Other settings...
   ```

## Conclusion

The Kafka integration in the APT Detection System provides a robust, scalable solution for ingesting security events from multiple sources. While it's optional and the system can function with other data sources, Kafka offers significant advantages for high-throughput, real-time data streaming in larger deployments.

By following the guidelines in this document, you can effectively configure, use, and troubleshoot the Kafka integration to meet your specific security monitoring needs.
