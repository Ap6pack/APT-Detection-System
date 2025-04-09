import os
import yaml
import joblib
import numpy as np
import logging
import pandas as pd
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from tensorflow.keras.models import load_model

# Import internal modules
from .mitre_attack_mapping import generate_alert
from .behavioral_analytics import BehavioralAnalytics
from .connectors.connector_manager import ConnectorManager

class PredictionEngine:
    """
    Prediction Engine for APT detection.
    
    This class provides methods for making predictions using machine learning models,
    behavioral analytics, and generating alerts with MITRE ATT&CK TTPs.
    """
    
    def __init__(
        self, 
        models: Optional[Dict[str, Any]] = None, 
        use_saved_models: bool = True, 
        alert_threshold: float = 0.7,
        config_path: Optional[str] = None
    ):
        """
        Initialize the prediction engine.
        
        Args:
            models: Dictionary of models to use for prediction
            use_saved_models: Whether to load saved models from disk
            alert_threshold: Threshold for generating alerts (0.0 to 1.0)
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.models = models
        self.alert_threshold = alert_threshold
        self.config = {}
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        
        self.load_config(config_path)
        
        # If no models provided and use_saved_models is True, load models from disk
        if self.models is None and use_saved_models:
            self.models = self.load_models()
            if not self.models:
                self.logger.warning("No saved models found. Prediction engine will rely on behavioral analytics only.")
        
        # Initialize connector manager
        self.connector_manager = ConnectorManager(config_path)
        
        # Initialize behavioral analytics
        self.behavioral_analytics = BehavioralAnalytics(config_path)
        
        # Load baseline models if available
        try:
            self.behavioral_analytics.load_baseline_models()
        except Exception as e:
            self.logger.warning(f"Failed to load baseline models: {str(e)}")
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, 'r') as file:
                self.config = yaml.safe_load(file)
                self.logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.config = {}
    
    def load_models(self) -> Dict[str, Any]:
        """
        Load trained models from disk.
        
        Returns:
            Dictionary of loaded models
        """
        models = {}
        
        try:
            # Get base directory for models
            base_dir = self.config.get('model_paths', {}).get('base_dir', 'models/')
            
            # Construct full paths to model files
            lgbm_path = os.path.join(base_dir, self.config.get('model_paths', {}).get('lightgbm', 'lightgbm_model.pkl'))
            bilstm_path = os.path.join(base_dir, self.config.get('model_paths', {}).get('bilstm', 'bilstm_model.h5'))
            
            # Check if models exist
            if os.path.exists(lgbm_path):
                # Load LightGBM model
                lgbm_model = joblib.load(lgbm_path)
                models['lgbm_model'] = lgbm_model
                self.logger.info(f"LightGBM model loaded from {lgbm_path}")
            
            if os.path.exists(bilstm_path):
                # Load Bi-LSTM model
                bilstm_model = load_model(bilstm_path)
                models['bilstm_model'] = bilstm_model
                self.logger.info(f"Bi-LSTM model loaded from {bilstm_path}")
            
            return models
            
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            return {}
    
    def collect_data(self) -> pd.DataFrame:
        """
        Collect data from all connectors.
        
        Returns:
            DataFrame with collected data
        """
        try:
            # Get time window from config
            time_window_minutes = self.config.get('settings', {}).get('behavioral_analytics', {}).get('time_window_minutes', 10)
            
            # Collect data from connectors
            data = self.connector_manager.collect_data(window_minutes=time_window_minutes)
            
            if data.empty:
                self.logger.warning("No data collected from connectors")
            else:
                self.logger.info(f"Collected {len(data)} data points from connectors")
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error collecting data: {str(e)}")
            return pd.DataFrame()
    
    def establish_baseline(self, days: int = 7) -> None:
        """
        Establish baseline behavior from historical data.
        
        Args:
            days: Number of days of historical data to use
        """
        try:
            # Calculate start time
            start_time = datetime.now() - timedelta(days=days)
            
            # Collect historical data
            self.logger.info(f"Collecting {days} days of historical data for baseline")
            
            # TODO: In a real implementation, this would collect historical data from a database
            # For now, we'll use synthetic data for demonstration
            
            # Create synthetic data
            historical_data = self._create_synthetic_historical_data(days)
            
            if historical_data.empty:
                self.logger.warning("No historical data available for baseline")
                return
            
            # Establish baseline
            self.behavioral_analytics.establish_baseline(historical_data)
            
            # Save baseline models
            self.behavioral_analytics.save_baseline_models()
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {str(e)}")
    
    def _create_synthetic_historical_data(self, days: int) -> pd.DataFrame:
        """
        Create synthetic historical data for demonstration purposes.
        
        Args:
            days: Number of days of data to generate
            
        Returns:
            DataFrame with synthetic historical data
        """
        # Create normal data
        normal_data = []
        start_time = datetime.now() - timedelta(days=days)
        
        # Generate data points every 10 minutes
        for i in range(days * 24 * 6):  # 6 data points per hour
            time_window = start_time + timedelta(minutes=i * 10)
            
            # Add data for a few hosts
            for host in ['host1', 'host2', 'host3']:
                # Normal behavior with some randomness
                normal_data.append({
                    'time_window': time_window,
                    'host': host,
                    'network_traffic_volume_mean': np.random.normal(0.3, 0.1),
                    'number_of_logins_mean': np.random.normal(0.2, 0.05),
                    'number_of_failed_logins_mean': np.random.normal(0.1, 0.05),
                    'number_of_accessed_files_mean': np.random.normal(0.4, 0.1),
                    'number_of_email_sent_mean': np.random.normal(0.2, 0.05),
                    'cpu_usage_mean': np.random.normal(0.3, 0.1),
                    'memory_usage_mean': np.random.normal(0.4, 0.1),
                    'disk_io_mean': np.random.normal(0.2, 0.05),
                    'network_latency_mean': np.random.normal(0.1, 0.05),
                    'number_of_processes_mean': np.random.normal(0.3, 0.1),
                    'data_source': 'synthetic'
                })
        
        return pd.DataFrame(normal_data)
    
    def predict(
        self, 
        data: Optional[Union[np.ndarray, pd.DataFrame]] = None, 
        feature_names: Optional[List[str]] = None,
        use_real_time_data: bool = False,
        entity_column: str = 'host'
    ) -> Dict[str, Any]:
        """
        Make predictions and generate alerts.
        
        Args:
            data: Input data for prediction (if None and use_real_time_data is True, collect data from connectors)
            feature_names: List of feature names corresponding to data columns
            use_real_time_data: Whether to use real-time data from connectors
            entity_column: Column name for the entity (e.g., 'host', 'agent_id')
            
        Returns:
            Dictionary containing predictions, alerts, and anomalies
        """
        result = {
            'predictions': {},
            'alerts': [],
            'anomalies': []
        }
        
        try:
            # If no data provided and use_real_time_data is True, collect data from connectors
            if data is None and use_real_time_data:
                data = self.collect_data()
                
                if data.empty:
                    self.logger.warning("No data available for prediction")
                    return result
            
            # If data is a numpy array, convert to DataFrame
            if isinstance(data, np.ndarray):
                if feature_names is None:
                    # Default feature names
                    feature_names = [
                        'network_traffic_volume_mean',
                        'number_of_logins_mean',
                        'number_of_failed_logins_mean',
                        'number_of_accessed_files_mean',
                        'number_of_email_sent_mean',
                        'cpu_usage_mean',
                        'memory_usage_mean',
                        'disk_io_mean',
                        'network_latency_mean',
                        'number_of_processes_mean'
                    ]
                
                # Convert to DataFrame
                data_df = pd.DataFrame(data, columns=feature_names)
                
                # Add entity column if not present
                if entity_column not in data_df.columns:
                    data_df[entity_column] = 'unknown'
                
                # Add timestamp if not present
                if 'time_window' not in data_df.columns:
                    data_df['time_window'] = datetime.now()
            else:
                data_df = data
            
            # Apply behavioral analytics for anomaly detection
            data_with_scores, anomaly_alerts = self.behavioral_analytics.detect_anomalies(data_df, entity_column=entity_column)
            
            # Add anomalies to result
            result['anomalies'] = anomaly_alerts
            
            # If we have ML models, use them for prediction
            if self.models:
                # For each row in the DataFrame
                for index, row in data_df.iterrows():
                    # Extract features
                    features = row.to_dict()
                    
                    # Convert to numpy array for ML models
                    feature_array = np.array([row[feature_names].values])
                    
                    # Reshape data for Bi-LSTM if needed
                    bilstm_data = None
                    if 'bilstm_model' in self.models:
                        bilstm_data = feature_array.reshape((feature_array.shape[0], feature_array.shape[1], 1))
                    
                    # Get predictions from all models
                    predictions = {}
                    for model_name, model in self.models.items():
                        if model_name == 'bilstm_model' and bilstm_data is not None:
                            predictions[model_name] = model.predict(bilstm_data)
                        else:
                            predictions[model_name] = model.predict(feature_array)
                    
                    # Add predictions to result
                    result['predictions'][index] = predictions
                    
                    # Generate alert with MITRE ATT&CK TTPs
                    alert = generate_alert(predictions, features, threshold=self.alert_threshold)
                    
                    if alert:
                        # Add entity and timestamp information
                        alert['entity'] = row.get(entity_column, 'unknown')
                        alert['timestamp'] = row.get('time_window', datetime.now())
                        
                        # Add anomaly score if available
                        if 'anomaly_score' in row:
                            alert['anomaly_score'] = float(row['anomaly_score'])
                        
                        # Add to alerts list
                        result['alerts'].append(alert)
                        
                        self.logger.info(f"Alert generated for {alert['entity']} with severity: {alert['severity']}")
                        if 'mitre_attack' in alert:
                            techniques = alert['mitre_attack']['techniques']
                            self.logger.info(f"MITRE ATT&CK techniques identified: {len(techniques)}")
                            for technique in techniques[:3]:  # Log first 3 techniques
                                self.logger.info(f"- {technique['id']}: {technique['name']}")
            
            # If we have anomaly alerts but no ML model alerts, add them to the alerts list
            if not result['alerts'] and anomaly_alerts:
                for anomaly in anomaly_alerts:
                    # Create alert from anomaly
                    alert = {
                        'entity': anomaly['entity'],
                        'timestamp': anomaly['timestamp'],
                        'severity': anomaly['severity'],
                        'anomaly_score': anomaly['anomaly_score'],
                        'features': anomaly['features'],
                        'prediction_score': anomaly['anomaly_score'],  # Use anomaly score as prediction score
                        'detection_type': 'behavioral_analytics'
                    }
                    
                    # Add to alerts list
                    result['alerts'].append(alert)
                    
                    self.logger.info(f"Anomaly alert generated for {alert['entity']} with severity: {alert['severity']}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error making predictions: {str(e)}")
            return result
    
    def analyze_entity(self, entity: str, data: Optional[pd.DataFrame] = None, entity_column: str = 'host') -> Dict[str, Any]:
        """
        Analyze behavior for a specific entity.
        
        Args:
            entity: Entity to analyze
            data: DataFrame containing security data (if None, collect data from connectors)
            entity_column: Column name for the entity
            
        Returns:
            Dictionary with behavior analysis results
        """
        try:
            # If no data provided, collect data from connectors
            if data is None:
                data = self.collect_data()
            
            # Check if we have any data
            if data.empty:
                self.logger.warning("No data available from connectors for entity analysis")
                # Generate synthetic data for this entity if we don't have real data
                data = self._generate_synthetic_entity_data(entity, entity_column)
            
            # Check if we have baseline models for this entity
            if entity not in self.behavioral_analytics.baseline_models:
                self.logger.info(f"No baseline model found for entity {entity}. Establishing baseline.")
                # Generate historical data and establish baseline
                historical_data = self._generate_synthetic_historical_data(entity, entity_column)
                self.behavioral_analytics.establish_baseline(historical_data, entity_column=entity_column)
                self.behavioral_analytics.save_baseline_models()
            
            # Analyze entity behavior
            behavior = self.behavioral_analytics.analyze_entity_behavior(entity, data, entity_column=entity_column)
            
            # If behavior is empty, generate a default behavior object
            if not behavior:
                behavior = self._generate_default_behavior(entity, entity_column)
            
            return behavior
            
        except Exception as e:
            self.logger.error(f"Error analyzing entity behavior: {str(e)}")
            # Return a default behavior object in case of error
            return self._generate_default_behavior(entity, entity_column)
    
    def _generate_synthetic_entity_data(self, entity: str, entity_column: str = 'host') -> pd.DataFrame:
        """
        Generate synthetic data for an entity when no real data is available.
        
        Args:
            entity: Entity to generate data for
            entity_column: Column name for the entity
            
        Returns:
            DataFrame with synthetic data
        """
        self.logger.info(f"Generating synthetic data for entity {entity}")
        
        # Create synthetic data
        synthetic_data = []
        now = datetime.now()
        
        # Generate data points for the last hour
        for i in range(6):  # 6 data points (10-minute intervals)
            time_window = now - timedelta(minutes=i * 10)
            
            # Create a data point with some randomness
            data_point = {
                'time_window': time_window,
                entity_column: entity,
                'network_traffic_volume_mean': np.random.normal(0.3, 0.1),
                'number_of_logins_mean': np.random.normal(0.2, 0.05),
                'number_of_failed_logins_mean': np.random.normal(0.1, 0.05),
                'number_of_accessed_files_mean': np.random.normal(0.4, 0.1),
                'number_of_email_sent_mean': np.random.normal(0.2, 0.05),
                'cpu_usage_mean': np.random.normal(0.3, 0.1),
                'memory_usage_mean': np.random.normal(0.4, 0.1),
                'disk_io_mean': np.random.normal(0.2, 0.05),
                'network_latency_mean': np.random.normal(0.1, 0.05),
                'number_of_processes_mean': np.random.normal(0.3, 0.1),
                'data_source': 'synthetic'
            }
            
            synthetic_data.append(data_point)
        
        return pd.DataFrame(synthetic_data)
    
    def _generate_synthetic_historical_data(self, entity: str, entity_column: str = 'host') -> pd.DataFrame:
        """
        Generate synthetic historical data for baseline establishment.
        
        Args:
            entity: Entity to generate data for
            entity_column: Column name for the entity
            
        Returns:
            DataFrame with synthetic historical data
        """
        self.logger.info(f"Generating synthetic historical data for entity {entity}")
        
        # Create synthetic data
        synthetic_data = []
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        
        # Generate data points every 10 minutes for the past 7 days
        for i in range(7 * 24 * 6):  # 7 days * 24 hours * 6 data points per hour
            time_window = start_time + timedelta(minutes=i * 10)
            
            # Create a data point with some randomness
            data_point = {
                'time_window': time_window,
                entity_column: entity,
                'network_traffic_volume_mean': np.random.normal(0.3, 0.1),
                'number_of_logins_mean': np.random.normal(0.2, 0.05),
                'number_of_failed_logins_mean': np.random.normal(0.1, 0.05),
                'number_of_accessed_files_mean': np.random.normal(0.4, 0.1),
                'number_of_email_sent_mean': np.random.normal(0.2, 0.05),
                'cpu_usage_mean': np.random.normal(0.3, 0.1),
                'memory_usage_mean': np.random.normal(0.4, 0.1),
                'disk_io_mean': np.random.normal(0.2, 0.05),
                'network_latency_mean': np.random.normal(0.1, 0.05),
                'number_of_processes_mean': np.random.normal(0.3, 0.1),
                'data_source': 'synthetic'
            }
            
            synthetic_data.append(data_point)
        
        return pd.DataFrame(synthetic_data)
    
    def _generate_default_behavior(self, entity: str, entity_column: str = 'host') -> Dict[str, Any]:
        """
        Generate a default behavior object when no real data is available.
        
        Args:
            entity: Entity to generate behavior for
            entity_column: Column name for the entity
            
        Returns:
            Dictionary with default behavior
        """
        self.logger.info(f"Generating default behavior for entity {entity}")
        
        # Create default statistics
        stats = {}
        
        # Default feature values
        features = [
            'network_traffic_volume_mean',
            'number_of_logins_mean',
            'number_of_failed_logins_mean',
            'number_of_accessed_files_mean',
            'number_of_email_sent_mean',
            'cpu_usage_mean',
            'memory_usage_mean',
            'disk_io_mean',
            'network_latency_mean',
            'number_of_processes_mean'
        ]
        
        for feature in features:
            stats[feature] = {
                'mean': 0.3,
                'median': 0.3,
                'min': 0.1,
                'max': 0.5,
                'std': 0.1,
                'current': 0.3
            }
        
        # Add activity by hour
        stats['activity_by_hour'] = {str(h): 10 for h in range(24)}
        
        # Add anomaly score
        stats['anomaly_score'] = {
            'current': 0.2,
            'mean': 0.2,
            'max': 0.4
        }
        
        # Create behavior object
        behavior = {
            'entity': entity,
            'entity_type': entity_column,
            'data_points': 1008,  # 7 days * 24 hours * 6 data points per hour
            'time_range': {
                'start': (datetime.now() - timedelta(days=7)).isoformat(),
                'end': datetime.now().isoformat()
            },
            'statistics': stats,
            'is_synthetic': True  # Flag to indicate this is synthetic data
        }
        
        return behavior

def run(models=None, use_saved_models=True, alert_threshold=0.7):
    """
    Initialize prediction engine.
    
    This function is maintained for backward compatibility.
    
    Args:
        models: Dictionary of models to use for prediction
        use_saved_models: Whether to load saved models from disk
        alert_threshold: Threshold for generating alerts (0.0 to 1.0)
        
    Returns:
        Prediction function
    """
    # Create prediction engine
    engine = PredictionEngine(models, use_saved_models, alert_threshold)
    
    # Create prediction function for backward compatibility
    def predict(data, feature_names=None):
        """
        Make predictions and generate alerts.
        
        Args:
            data: Input data for prediction
            feature_names: List of feature names corresponding to data columns
            
        Returns:
            Dictionary containing predictions and alerts
        """
        result = engine.predict(data, feature_names)
        
        # Format result for backward compatibility
        compat_result = {
            'predictions': result.get('predictions', {}).get(0, {}),
            'alert': result.get('alerts', [None])[0]
        }
        
        return compat_result
    
    return predict

# Testing prediction engine
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create prediction engine
    engine = PredictionEngine(use_saved_models=True)
    
    # Establish baseline if needed
    if not engine.behavioral_analytics.baseline_models:
        engine.establish_baseline(days=7)
    
    # Test with synthetic data
    print("\nTesting with synthetic data:")
    
    # Create synthetic data
    feature_names = [
        'network_traffic_volume_mean',
        'number_of_logins_mean',
        'number_of_failed_logins_mean',
        'number_of_accessed_files_mean',
        'number_of_email_sent_mean',
        'cpu_usage_mean',
        'memory_usage_mean',
        'disk_io_mean',
        'network_latency_mean',
        'number_of_processes_mean'
    ]
    
    # Normal data
    normal_data = np.array([0.3, 0.2, 0.1, 0.4, 0.2, 0.3, 0.4, 0.2, 0.1, 0.3]).reshape(1, -1)
    
    # Anomalous data
    anomalous_data = np.array([0.9, 0.2, 0.8, 0.9, 0.2, 0.8, 0.4, 0.2, 0.1, 0.7]).reshape(1, -1)
    
    # Make predictions
    normal_result = engine.predict(normal_data, feature_names)
    anomalous_result = engine.predict(anomalous_data, feature_names)
    
    # Print results
    print("\nNormal data predictions:")
    print(f"Alerts: {len(normal_result['alerts'])}")
    print(f"Anomalies: {len(normal_result['anomalies'])}")
    
    print("\nAnomalous data predictions:")
    print(f"Alerts: {len(anomalous_result['alerts'])}")
    print(f"Anomalies: {len(anomalous_result['anomalies'])}")
    
    for alert in anomalous_result['alerts']:
        print(f"\nAlert for {alert.get('entity', 'unknown')} with severity: {alert.get('severity', 'Unknown')}")
        print(f"Score: {alert.get('prediction_score', 0)}")
        
        if 'mitre_attack' in alert:
            print("\nMITRE ATT&CK Techniques:")
            for technique in alert['mitre_attack']['techniques'][:3]:  # Show first 3 techniques
                print(f"- {technique['id']}: {technique['name']}")
    
    # Test with real-time data (if connectors are enabled)
    print("\nTesting with real-time data:")
    realtime_result = engine.predict(use_real_time_data=True)
    
    print(f"Collected data points: {len(realtime_result.get('predictions', {}))}")
    print(f"Alerts: {len(realtime_result['alerts'])}")
    print(f"Anomalies: {len(realtime_result['anomalies'])}")
