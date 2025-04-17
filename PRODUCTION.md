# APT Detection System - Production Deployment Guide

This guide provides instructions for deploying the APT Detection System in a production environment.

## Prerequisites

- Python 3.8 or higher
- Kafka server running (for event ingestion)
- Redis server (optional, for alert storage)
- Wazuh EDR and/or Elasticsearch SIEM (for real data sources)

## Configuration

The system is configured through the `config.yaml` file. For production deployment, ensure the following settings are properly configured:

### Data Source Connectors

Configure at least one data source connector:

#### Wazuh EDR

```yaml
data_sources:
  wazuh:
    enabled: true
    api_url: "https://your-wazuh-server:55000"
    username: "your-wazuh-username"
    password: "your-wazuh-password"
    verify_ssl: true
    fetch_interval: 60
```

#### Elasticsearch SIEM

```yaml
data_sources:
  elasticsearch:
    enabled: true
    hosts: ["your-elasticsearch-host:9200"]
    index_pattern: "winlogbeat-*"
    username: "your-elasticsearch-username"
    password: "your-elasticsearch-password"
    verify_certs: true
    fetch_interval: 60
```

### Kafka Configuration

```yaml
kafka:
  bootstrap_servers: your-kafka-server:9092
  topic: apt_topic
  group_id: apt_detection_group
  auto_offset_reset: earliest
  enable_auto_commit: true
  session_timeout_ms: 30000
  request_timeout_ms: 40000
```

### Dashboard Configuration

```yaml
dashboard:
  host: 0.0.0.0  # Allow external connections
  port: 5000
  debug: false  # Disable debug mode in production
```

### Other Settings

```yaml
settings:
  overwrite_models: false  # Don't overwrite models in production
  log_level: INFO
  collection_interval_seconds: 60
  behavioral_analytics:
    baseline_period_days: 7
    anomaly_threshold: 0.6
    time_window_minutes: 10
  alerts:
    max_alerts: 10000
    retention_days: 90
```

### Simulation

Ensure simulation is disabled for production:

```yaml
simulation:
  enabled: false
```

## Deployment Steps

1. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Train Models** (if not already trained)

   ```bash
   python main.py --train
   ```

3. **Run in Production Mode**

   ```bash
   ./run_production.sh
   ```

   Or manually:

   ```bash
   python main.py --production
   ```

## Production Considerations

### Security

- Use HTTPS for the dashboard by setting up a reverse proxy (e.g., Nginx, Apache)
- Secure all API credentials and passwords
- Use SSL/TLS for Kafka and Redis connections
- Implement proper authentication for the dashboard

### Monitoring

- Set up monitoring for the APT Detection System process
- Configure log rotation for the `apt_detection.log` file
- Monitor disk space for log files and alert storage

### High Availability

- Consider running multiple instances behind a load balancer
- Set up redundant Kafka and Redis servers
- Implement database backup strategies for alert storage

### Performance Tuning

- Adjust `collection_interval_seconds` based on your data volume
- Tune Kafka consumer settings for optimal throughput
- Adjust `time_window_minutes` for feature aggregation based on your environment

## Troubleshooting

### Common Issues

1. **Connection to data sources fails**
   - Check network connectivity
   - Verify credentials
   - Ensure API endpoints are correct

2. **No alerts are generated**
   - Check if data is being ingested from sources
   - Verify Kafka topic exists and is receiving messages
   - Check log files for errors

3. **Dashboard is not accessible**
   - Verify the dashboard is running
   - Check firewall settings
   - Ensure the correct host and port are configured

### Logs

The system logs to `apt_detection.log` in the project directory. Check this file for detailed error messages and debugging information.

## Maintenance

### Updating Models

To update the machine learning models:

1. Stop the running instance
2. Run `python main.py --train`
3. Restart the system

### Updating Baseline Models

Baseline models are automatically created if they don't exist. To force an update:

1. Stop the running instance
2. Delete the files in `models/baselines/`
3. Restart the system

## Support

For additional support, please refer to the project documentation or contact the development team.
