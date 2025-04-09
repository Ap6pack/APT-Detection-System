# Redis Integration for APT Detection System

This document provides detailed information about the Redis integration in the APT Detection System, including how it works, how to configure it, and how to troubleshoot common issues.

## Overview

The APT Detection System uses Redis as a robust storage solution for alerts. Redis provides several advantages over in-memory storage:

- **Persistence**: Alerts are stored in Redis and persist across system restarts
- **Shared Storage**: Multiple processes can access the same alerts
- **Scalability**: Redis can handle large volumes of alerts efficiently
- **Performance**: Redis is an in-memory data store with disk persistence, providing fast access to data

## How It Works

The Redis integration is implemented in the `real_time_detection/redis_integration.py` module, which provides the following functionality:

- **Connection Management**: Establishes and maintains a connection to the Redis server
- **Alert Storage**: Stores alerts in a Redis list
- **Alert Retrieval**: Retrieves alerts from Redis
- **Fallback Mechanism**: Falls back to in-memory storage if Redis is unavailable

The `data_ingestion.py` module has been updated to use Redis for alert storage and retrieval, with a fallback to in-memory storage if Redis is unavailable.

## Installation

### Prerequisites

- Redis server (version 5.0 or higher recommended)
- Python Redis client (included in requirements.txt)

### Installing Redis

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install redis-server
```

#### CentOS/RHEL

```bash
sudo yum install redis
```

#### macOS

```bash
brew install redis
```

#### Windows

Download the Redis installer from the [Redis website](https://redis.io/download) or use WSL (Windows Subsystem for Linux) to install Redis.

### Starting Redis

#### Ubuntu/Debian

```bash
sudo systemctl start redis-server
```

#### CentOS/RHEL

```bash
sudo systemctl start redis
```

#### macOS

```bash
brew services start redis
```

#### Windows

Start Redis using the Redis server executable or through WSL.

### Verifying Redis Installation

```bash
redis-cli ping
```

You should receive a response of `PONG`.

## Configuration

The Redis integration uses the following default configuration:

- Host: localhost
- Port: 6379
- Database: 0
- Password: None
- Key Prefix: apt_detection:

These settings can be modified in the `real_time_detection/redis_integration.py` file if needed.

## Testing

You can test the Redis integration using the provided `test_redis.py` script:

```bash
python test_redis.py
```

This script will:

1. Connect to Redis
2. Clear any existing alerts
3. Create test alerts
4. Store them in Redis
5. Retrieve them from Redis
6. Print them to the console

## Troubleshooting

### Redis Connection Issues

If the system is unable to connect to Redis, it will log an error message and fall back to in-memory storage. Check the following:

1. **Redis Server Running**: Verify that the Redis server is running:
   ```bash
   redis-cli ping
   ```

2. **Connection Settings**: Verify that the connection settings in `redis_integration.py` match your Redis server configuration.

3. **Firewall Settings**: If Redis is running on a different machine, ensure that the firewall allows connections to the Redis port (default: 6379).

### Data Not Appearing in Dashboard

If data is not appearing in the dashboard, check the following:

1. **Redis Storage**: Verify that alerts are being stored in Redis:
   ```bash
   python check_alerts.py
   ```

2. **Redis List**: Check the Redis list directly:
   ```bash
   redis-cli llen apt_detection:alerts
   ```

3. **Dashboard Logs**: Check the dashboard logs for any error messages related to Redis.

### Performance Issues

If you experience performance issues with Redis, consider the following:

1. **Redis Configuration**: Adjust the Redis configuration to optimize performance for your specific use case.

2. **Alert Limit**: Adjust the maximum number of alerts stored in Redis by modifying the `max_alerts` parameter in the `store_alert` function.

3. **Redis Persistence**: Configure Redis persistence to balance performance and durability.

## Advanced Configuration

### Redis Persistence

Redis provides several persistence options:

1. **RDB**: Point-in-time snapshots at specified intervals
2. **AOF**: Append-only file that logs every write operation
3. **RDB + AOF**: Combination of both approaches

Configure persistence in the Redis configuration file (`redis.conf`).

### Redis Authentication

To enable Redis authentication:

1. Set a password in the Redis configuration file:
   ```
   requirepass your_password
   ```

2. Update the `REDIS_PASSWORD` variable in `redis_integration.py`:
   ```python
   REDIS_PASSWORD = "your_password"
   ```

### Redis Replication

For high availability, you can set up Redis replication:

1. Configure a Redis master and one or more Redis slaves
2. Update the `redis_integration.py` file to connect to the appropriate Redis instance

## Further Reading

- [Redis Documentation](https://redis.io/documentation)
- [Python Redis Client Documentation](https://redis-py.readthedocs.io/)
