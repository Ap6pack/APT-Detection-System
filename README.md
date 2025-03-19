# APT Detection System

This project is a Python-based Advanced Persistent Threat (APT) detection system that uses the Hybrid HHOSSA optimization technique for feature selection and data balancing. It integrates LightGBM and Bi-LSTM models for classification and provides a real-time detection system with a monitoring dashboard.

## Table of Contents

- [Project Overview](#project-overview)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Integrating Real-Time Data Sources for APT Detection](#integrating-real-time-data-sources-for-apt-detection)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

This APT detection system consists of the following components:
- **Data Preprocessing**: Load and clean the dataset, and extract features.
- **Feature Selection**: Select significant features using the HHOSSA technique.
- **Data Balancing**: Balance the dataset using HHOSSA-SMOTE.
- **Model Training**: Train LightGBM and Bi-LSTM models.
- **Model Persistence**: Save and load trained models for reuse.
- **Model Evaluation**: Evaluate models using accuracy and ROC-AUC.
- **Real-Time Detection**: Ingest real-time data using Kafka.
- **Monitoring Dashboard**: Visualize data and model performance using Flask and Plotly.

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- Java Development Kit (JDK) 11 or higher
- Kafka
- Zookeeper

### Installation

1. **Clone the Repository**

    ```sh
    git clone https://github.com/Ap6pack/APT-Detection-System.git
    cd APT-Detection-System
    ```

2. **Create and Activate a Virtual Environment**

    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install Dependencies**

    ```sh
    pip install -r requirements.txt
    ```

4. **Install Java (if not already installed)**

    #### On Ubuntu/Debian

    ```sh
    sudo apt update
    sudo apt install openjdk-11-jdk
    java -version
    ```

    #### On CentOS/RHEL

    ```sh
    sudo yum install java-11-openjdk-devel
    java -version
    ```

    #### On macOS

    ```sh
    brew update
    brew install openjdk@11
    echo 'export PATH="/usr/local/opt/openjdk@11/bin:$PATH"' >> ~/.zshrc
    echo 'export JAVA_HOME=$(/usr/libexec/java_home -v 11)' >> ~/.zshrc
    source ~/.zshrc
    java -version
    ```

5. **Download Kafka**

    Download Kafka from the [official Apache website](https://www.apache.org/dyn/closer.cgi?path=/kafka/).

6. **Start Zookeeper and Kafka**

    ```sh
    # Start Zookeeper
    kafka_2.13-3.8.0/bin/zookeeper-server-start.sh kafka_2.13-3.8.0/config/zookeeper.properties

    # Start Kafka (in a new terminal)
    kafka_2.13-3.8.0/bin/kafka-server-start.sh kafka_2.13-3.8.0/config/server.properties
    ```

7. **Create Kafka Topic**

    ```sh
    kafka_2.13-3.8.0/bin/kafka-topics.sh --create --topic apt_topic --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
    ```

## Usage

### Producing Messages to Kafka

Create a new file `produce_messages.py`:

```python
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
```

Run the script to send messages to the Kafka topic:

```sh
python3 produce_messages.py
```

### Configuration

The system uses a `config.yaml` file for configuration. You can modify this file to customize various aspects of the system:

```yaml
# APT Detection System Configuration

# Model paths for persistence
model_paths:
  lightgbm: models/saved/lightgbm_model.pkl
  bilstm: models/saved/bilstm_model.h5
  
# Data paths
data_paths:
  dataset: synthetic_apt_dataset.csv
  
# Kafka configuration
kafka:
  bootstrap_servers: localhost:9092
  topic: apt_topic
  
# Training parameters
training:
  test_size: 0.2
  random_state: 42
  
# Dashboard configuration
dashboard:
  host: 127.0.0.1
  port: 5000
  debug: true
```

### Running the Main Script

The main script now supports command-line arguments to run specific components:

```sh
# Run all components (training, prediction, dashboard)
python3 main.py --all

# Run only the training component
python3 main.py --train

# Run only the prediction engine
python3 main.py --predict

# Run only the dashboard
python3 main.py --dashboard

# Run training and prediction without the dashboard
python3 main.py --train --predict
```

If no arguments are provided, the system will run all components by default.

### Model Persistence

The system now supports saving and loading trained models:

- Models are automatically saved after training to the paths specified in `config.yaml`
- When running the prediction engine without training, models are loaded from disk
- The dashboard includes a new page at `/models` that shows the status of saved models

### Accessing the Dashboard

Open your web browser and go to `http://127.0.0.1:5000/` to view the dashboard. The dashboard now includes:

- Main page with visualization plots
- Plotly charts page with interactive visualizations
- Models page showing the status of saved models

## File Structure

```
APT_Detection_System/
├── config.yaml                      # Configuration file
├── dashboard/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
│       ├── index.html               # Main dashboard page
│       └── models.html              # Model status page
├── data_preprocessing/
│   ├── __init__.py
│   ├── preprocess.py
│   ├── data_cleaning.py
│   └── feature_engineering.py
├── evaluation/
│   ├── __init__.py
│   ├── evaluation_metrics.py
│   └── cross_validation.py
├── feature_selection/
│   ├── __init__.py
│   └── hhosssa_feature_selection.py
├── data_balancing/
│   ├── __init__.py
│   └── hhosssa_smote.py
├── models/
│   ├── __init__.py
│   ├── train_models.py              # Updated with model saving
│   ├── lightgbm_model.py
│   ├── bilstm_model.py
│   ├── hybrid_classifier.py
│   └── saved/                       # Directory for saved models
│       ├── lightgbm_model.pkl       # Saved LightGBM model
│       └── bilstm_model.h5          # Saved Bi-LSTM model
├── real_time_detection/
│   ├── __init__.py
│   ├── data_ingestion.py
│   └── prediction_engine.py         # Updated with model loading
├── visualization.py
├── main.py                          # Updated with CLI arguments
├── produce_messages.py
└── requirements.txt                 # Updated with new dependencies
```

## Integrating Real-Time Data Sources for APT Detection

This guide provides detailed configurations for integrating various real-time data sources to enhance Advanced Persistent Threat (APT) detection capabilities.

### Table of Contents
1. [Security Information and Event Management (SIEM)](#siem-systems)
2. [Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)](#ids-and-ips)
3. [Endpoint Detection and Response (EDR)](#endpoint-detection-and-response-edr)
4. [Threat Intelligence Feeds](#threat-intelligence-feeds)
5. [Network Traffic Analysis](#network-traffic-analysis)

### SIEM Systems

#### Splunk
1. **Install Splunk Forwarder**:
   ```sh
   wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/8.1.3/linux/splunkforwarder-8.1.3-aeae3fe429ae-Linux-x86_64.tgz"
   tar -xvf splunkforwarder.tgz
   ./splunkforwarder/bin/splunk start --accept-license
   ./splunkforwarder/bin/splunk enable boot-start
   ```

2. **Configure Data Inputs**:
   - Add data inputs through Splunk Web UI (Settings > Data Inputs).
   - Monitor specific directories, files, or network ports.

3. **Create Dashboards and Alerts**:
   - Use the Splunk Search Processing Language (SPL) to create queries.
   - Build dashboards in the Splunk Web UI (Dashboard > Create New Dashboard).
   - Set up alerts (Alerts > Create New Alert) based on query results.

### IDS and IPS

#### Snort
1. **Install Snort**:
   ```sh
   sudo apt-get install snort
   ```

2. **Configure snort.conf**:
   - Edit `/etc/snort/snort.conf` to set HOME_NET and EXTERNAL_NET.
   - Define rule paths: `var RULE_PATH /etc/snort/rules`.
   - Set output plugins for logging.

3. **Update Rules**:
   - Download rules from Snort.org or subscribe to rule updates.
   - Place rule files in `/etc/snort/rules`.

4. **Start Snort**:
   ```sh
   sudo snort -c /etc/snort/snort.conf -i eth0
   ```

5. **Log Management**:
   - Configure Snort to log to a centralized log management system like Splunk or ELK Stack.

### Endpoint Detection and Response (EDR)

#### CrowdStrike Falcon
1. **Deploy Falcon Agent**:
   - Obtain the Falcon installer from the CrowdStrike portal.
   - Install on endpoints:
     ```sh
     sudo apt-get install falcon-sensor
     sudo systemctl start falconsensor
     sudo systemctl enable falconsensor
     ```

2. **Configure Policies**:
   - In the CrowdStrike console, configure detection and prevention policies.

3. **Integrate with SIEM**:
   - Use CrowdStrike API to pull event data into your SIEM.

4. **Set Alerts**:
   - Configure alerts in the CrowdStrike console based on detection events.

### Threat Intelligence Feeds

#### AlienVault OTX
1. **Create OTX Account**:
   - Sign up at [AlienVault OTX](https://otx.alienvault.com).

2. **Integrate with SIEM**:
   - Use OTX API to integrate threat data with SIEM systems.

3. **Set Alerts and Workflows**:
   - In your SIEM, create correlation rules based on OTX indicators.

### Network Traffic Analysis

#### Zeek
1. **Install Zeek**:
   ```sh
   sudo apt-get
   ``` 
2. **Configure Network Interfaces**:
   - Edit `/usr/local/zeek/etc/node.cfg` to define network interfaces for monitoring.

3. **Edit zeek.cfg**:
   - Set paths for logs and scripts: `LogDir = /var/log/zeek`.

4. **Deploy Scripts**:
   - Use built-in and custom Zeek scripts for specific detections.

5. **Integrate with SIEM**:
   - Send Zeek logs to SIEM for correlation and analysis.

---

By following these configurations, you can effectively integrate various real-time data sources to enhance your APT detection capabilities.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or additions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
