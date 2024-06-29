# APT Detection System

This project is a Python-based Advanced Persistent Threat (APT) detection system that uses the Hybrid HHOSSA optimization technique for feature selection and data balancing. It integrates LightGBM and Bi-LSTM models for classification and provides a real-time detection system with a monitoring dashboard.

## Table of Contents

- [Project Overview](#project-overview)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

This APT detection system consists of the following components:
- **Data Preprocessing**: Load and clean the dataset, and extract features.
- **Feature Selection**: Select significant features using the HHOSSA technique.
- **Data Balancing**: Balance the dataset using HHOSSA-SMOTE.
- **Model Training**: Train LightGBM and Bi-LSTM models.
- **Model Evaluation**: Evaluate models using accuracy and ROC-AUC.
- **Real-Time Detection**: Ingest real-time data using Kafka.
- **Monitoring Dashboard**: Visualize data and model performance using Flask and Plotly.

## Setup Instructions

### Prerequisites

- Python 3.8 or higher
- Kafka
- Zookeeper

### Installation

1. **Clone the Repository**

    ```sh
    git clone https://github.com/your-username/APT_Detection_System.git
    cd APT_Detection_System
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

4. **Start Zookeeper and Kafka**

    ```sh
    # Start Zookeeper
    bin/zookeeper-server-start.sh config/zookeeper.properties

    # Start Kafka (in a new terminal)
    bin/kafka-server-start.sh config/server.properties
    ```

5. **Create Kafka Topic**

    ```sh
    bin/kafka-topics.sh --create --topic apt_topic --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
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

### Running the Main Script

```sh
python3 main.py
```

### Accessing the Dashboard

Open your web browser and go to `http://127.0.0.1:5000/` to view the dashboard.

## File Structure

```
APT_Detection_System/
├── dashboard/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
│       └── index.html
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
│   ├── train_models.py
│   ├── lightgbm_model.py
│   ├── bilstm_model.py
│   └── hybrid_classifier.py
├── real_time_detection/
│   ├── __init__.py
│   ├── data_ingestion.py
│   └── prediction_engine.py
├── visualization.py
├── main.py
├── produce_messages.py
└── requirements.txt
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or additions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.