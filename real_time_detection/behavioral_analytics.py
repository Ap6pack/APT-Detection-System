"""
Behavioral Analytics Module

This module provides advanced behavioral analytics capabilities for the APT detection system.
It implements techniques for establishing baselines, detecting anomalies, and identifying
suspicious patterns in security data.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import yaml
import os
import joblib

class BehavioralAnalytics:
    """
    Behavioral Analytics for APT detection.
    
    This class provides methods for establishing baselines, detecting anomalies,
    and identifying suspicious patterns in security data.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the behavioral analytics module.
        
        Args:
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.config = {}
        self.baseline_models = {}
        self.baseline_scalers = {}
        self.baseline_data = {}
        
        # Load configuration
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
        
        self.load_config(config_path)
        
        # Set default parameters
        self.baseline_period_days = self.config.get('settings', {}).get('behavioral_analytics', {}).get('baseline_period_days', 7)
        self.anomaly_threshold = self.config.get('settings', {}).get('behavioral_analytics', {}).get('anomaly_threshold', 0.8)
        self.time_window_minutes = self.config.get('settings', {}).get('behavioral_analytics', {}).get('time_window_minutes', 10)
    
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
    
    def establish_baseline(self, historical_data: pd.DataFrame, entity_column: str = 'host') -> None:
        """
        Establish baseline behavior from historical data.
        
        Args:
            historical_data: DataFrame containing historical security data
            entity_column: Column name for the entity (e.g., 'host', 'agent_id')
        """
        if historical_data.empty:
            self.logger.warning("No historical data provided for baseline establishment")
            return
        
        self.logger.info(f"Establishing baseline from {len(historical_data)} data points")
        
        # Store a copy of the baseline data
        self.baseline_data = historical_data.copy()
        
        # Get unique entities
        entities = historical_data[entity_column].unique()
        self.logger.info(f"Found {len(entities)} unique entities for baseline")
        
        # Features to use for anomaly detection
        numeric_features = [
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
        
        # Add additional features if they exist
        additional_features = [
            'alert_count', 'unique_rule_count', 'event_count', 'unique_category_count',
            'alert_count_rolling_mean', 'unique_rule_count_rolling_mean',
            'event_count_rolling_mean', 'unique_category_count_rolling_mean',
            'alert_count_rate', 'unique_rule_count_rate',
            'event_count_rate', 'unique_category_count_rate'
        ]
        
        for feature in additional_features:
            if feature in historical_data.columns:
                numeric_features.append(feature)
        
        # Establish baseline for each entity
        for entity in entities:
            try:
                # Get data for this entity
                entity_data = historical_data[historical_data[entity_column] == entity]
                
                if len(entity_data) < 10:  # Need enough data points
                    self.logger.warning(f"Not enough data for entity {entity}, skipping baseline")
                    continue
                
                # Select numeric features
                X = entity_data[numeric_features].select_dtypes(include=['number'])
                
                # Handle missing values
                X = X.fillna(0)
                
                # Scale the data
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                # Train isolation forest model
                model = IsolationForest(
                    n_estimators=100,
                    max_samples='auto',
                    contamination=0.1,  # Assume 10% of data points are anomalies
                    random_state=42
                )
                model.fit(X_scaled)
                
                # Store model and scaler for this entity
                self.baseline_models[entity] = model
                self.baseline_scalers[entity] = scaler
                
                self.logger.info(f"Established baseline for entity {entity} using {len(X)} data points")
                
            except Exception as e:
                self.logger.error(f"Error establishing baseline for entity {entity}: {str(e)}")
    
    def save_baseline_models(self, directory: str = 'models/baselines') -> None:
        """
        Save baseline models to disk.
        
        Args:
            directory: Directory to save models to
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(directory, exist_ok=True)
            
            # Save models and scalers
            for entity, model in self.baseline_models.items():
                model_path = os.path.join(directory, f"{entity}_model.pkl")
                scaler_path = os.path.join(directory, f"{entity}_scaler.pkl")
                
                joblib.dump(model, model_path)
                joblib.dump(self.baseline_scalers[entity], scaler_path)
            
            self.logger.info(f"Saved {len(self.baseline_models)} baseline models to {directory}")
            
        except Exception as e:
            self.logger.error(f"Error saving baseline models: {str(e)}")
    
    def load_baseline_models(self, directory: str = 'models/baselines') -> None:
        """
        Load baseline models from disk.
        
        Args:
            directory: Directory to load models from
        """
        try:
            # Check if directory exists
            if not os.path.exists(directory):
                self.logger.warning(f"Baseline models directory {directory} does not exist")
                return
            
            # Clear existing models
            self.baseline_models = {}
            self.baseline_scalers = {}
            
            # Find all model files
            model_files = [f for f in os.listdir(directory) if f.endswith('_model.pkl')]
            
            # Load models and scalers
            for model_file in model_files:
                entity = model_file.replace('_model.pkl', '')
                model_path = os.path.join(directory, model_file)
                scaler_path = os.path.join(directory, f"{entity}_scaler.pkl")
                
                if os.path.exists(model_path) and os.path.exists(scaler_path):
                    self.baseline_models[entity] = joblib.load(model_path)
                    self.baseline_scalers[entity] = joblib.load(scaler_path)
            
            self.logger.info(f"Loaded {len(self.baseline_models)} baseline models from {directory}")
            
        except Exception as e:
            self.logger.error(f"Error loading baseline models: {str(e)}")
    
    def detect_anomalies(
        self, 
        data: pd.DataFrame, 
        entity_column: str = 'host'
    ) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
        """
        Detect anomalies in the provided data.
        
        Args:
            data: DataFrame containing security data to analyze
            entity_column: Column name for the entity (e.g., 'host', 'agent_id')
            
        Returns:
            Tuple of (DataFrame with anomaly scores, List of anomaly alerts)
        """
        if data.empty:
            self.logger.warning("No data provided for anomaly detection")
            return data, []
        
        self.logger.info(f"Detecting anomalies in {len(data)} data points")
        
        # Create a copy of the data
        result_data = data.copy()
        
        # Add anomaly score column
        result_data['anomaly_score'] = 0.0
        
        # List to store anomaly alerts
        anomaly_alerts = []
        
        # Features to use for anomaly detection
        numeric_features = [
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
        
        # Add additional features if they exist
        additional_features = [
            'alert_count', 'unique_rule_count', 'event_count', 'unique_category_count',
            'alert_count_rolling_mean', 'unique_rule_count_rolling_mean',
            'event_count_rolling_mean', 'unique_category_count_rolling_mean',
            'alert_count_rate', 'unique_rule_count_rate',
            'event_count_rate', 'unique_category_count_rate'
        ]
        
        for feature in additional_features:
            if feature in data.columns:
                numeric_features.append(feature)
        
        # Get unique entities
        entities = data[entity_column].unique()
        
        # Detect anomalies for each entity
        for entity in entities:
            try:
                # Get data for this entity
                entity_data = data[data[entity_column] == entity]
                
                # Check if we have a baseline model for this entity
                if entity not in self.baseline_models:
                    self.logger.warning(f"No baseline model for entity {entity}, creating one on-the-fly")
                    
                    # Create a baseline model for this entity using the current data
                    # This is a simplified baseline, but better than nothing
                    self._create_baseline_for_entity(entity, entity_data, numeric_features)
                    
                    # If we still don't have a model (creation failed), skip this entity
                    if entity not in self.baseline_models:
                        self.logger.warning(f"Failed to create baseline model for entity {entity}, skipping anomaly detection")
                        continue
                
                # Get model and scaler for this entity
                model = self.baseline_models[entity]
                scaler = self.baseline_scalers[entity]
                
                # Select numeric features
                X = entity_data[numeric_features].select_dtypes(include=['number'])
                
                # Handle missing values
                X = X.fillna(0)
                
                # Scale the data
                X_scaled = scaler.transform(X)
                
                # Get anomaly scores
                # Isolation Forest returns -1 for anomalies and 1 for normal points
                # Convert to 0-1 scale where 1 is anomalous
                raw_scores = model.decision_function(X_scaled)
                anomaly_scores = 1 - (raw_scores + 1) / 2
                
                # Add anomaly scores to result data
                entity_indices = result_data[result_data[entity_column] == entity].index
                result_data.loc[entity_indices, 'anomaly_score'] = anomaly_scores
                
                # Generate alerts for anomalies
                for i, score in enumerate(anomaly_scores):
                    if score >= self.anomaly_threshold:
                        # Get the row data
                        row_data = entity_data.iloc[i].to_dict()
                        
                        # Create anomaly alert
                        alert = {
                            'timestamp': row_data.get('time_window', datetime.now()),
                            'entity': entity,
                            'entity_type': entity_column,
                            'event_type': row_data.get('event_type', ''),
                            'anomaly_score': float(score),
                            'features': {},
                            'severity': self._calculate_severity(score)
                        }
                        
                        # Add feature values
                        for feature in numeric_features:
                            if feature in row_data:
                                alert['features'][feature] = float(row_data[feature])
                        
                        # Add data source if available
                        if 'data_source' in row_data:
                            alert['data_source'] = row_data['data_source']
                        
                        # Add to alerts list
                        anomaly_alerts.append(alert)
                
                self.logger.info(f"Detected {len([s for s in anomaly_scores if s >= self.anomaly_threshold])} anomalies for entity {entity}")
                
            except Exception as e:
                self.logger.error(f"Error detecting anomalies for entity {entity}: {str(e)}")
                import traceback
                self.logger.error(traceback.format_exc())
        
        self.logger.info(f"Total anomalies detected: {len(anomaly_alerts)}")
        
        return result_data, anomaly_alerts
        
    def _create_baseline_for_entity(self, entity: str, entity_data: pd.DataFrame, features: List[str]) -> None:
        """
        Create a baseline model for an entity using the provided data.
        
        Args:
            entity: Entity to create baseline for
            entity_data: DataFrame containing data for this entity
            features: List of feature names to use for the baseline
        """
        try:
            self.logger.info(f"Creating baseline model for entity {entity} using {len(entity_data)} data points")
            
            # Select numeric features
            X = entity_data[features].select_dtypes(include=['number'])
            
            # Handle missing values
            X = X.fillna(0)
            
            # Need enough data points for a meaningful model
            if len(X) < 5:
                self.logger.warning(f"Not enough data points for entity {entity}, using default model")
                # Create a default model with some reasonable parameters
                model = IsolationForest(
                    n_estimators=100,
                    max_samples='auto',
                    contamination=0.1,
                    random_state=42
                )
                # Fit with some synthetic data that's close to normal
                synthetic_data = np.random.normal(0.3, 0.1, size=(100, len(features)))
                model.fit(synthetic_data)
                
                # Create a scaler that centers around typical values
                scaler = StandardScaler()
                scaler.fit(synthetic_data)
            else:
                # Scale the data
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)
                
                # Train isolation forest model
                model = IsolationForest(
                    n_estimators=100,
                    max_samples='auto',
                    contamination=0.1,
                    random_state=42
                )
                model.fit(X_scaled)
            
            # Store model and scaler for this entity
            self.baseline_models[entity] = model
            self.baseline_scalers[entity] = scaler
            
            # Save the updated models to disk
            try:
                self.save_baseline_models()
            except Exception as save_error:
                self.logger.warning(f"Failed to save baseline model for entity {entity}: {str(save_error)}")
            
            self.logger.info(f"Successfully created baseline model for entity {entity}")
            
        except Exception as e:
            self.logger.error(f"Error creating baseline for entity {entity}: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def analyze_entity_behavior(
        self, 
        entity: str, 
        data: pd.DataFrame, 
        entity_column: str = 'host'
    ) -> Dict[str, Any]:
        """
        Analyze behavior for a specific entity.
        
        Args:
            entity: Entity to analyze
            data: DataFrame containing security data
            entity_column: Column name for the entity
            
        Returns:
            Dictionary with behavior analysis results
        """
        if data.empty:
            self.logger.warning(f"No data provided for entity {entity} behavior analysis")
            return {}
        
        # Filter data for this entity
        entity_data = data[data[entity_column] == entity]
        
        if entity_data.empty:
            self.logger.warning(f"No data found for entity {entity}")
            return {}
        
        self.logger.info(f"Analyzing behavior for entity {entity} with {len(entity_data)} data points")
        
        # Features to analyze
        numeric_features = [
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
        
        # Add additional features if they exist
        additional_features = [
            'alert_count', 'unique_rule_count', 'event_count', 'unique_category_count'
        ]
        
        for feature in additional_features:
            if feature in data.columns:
                numeric_features.append(feature)
        
        # Calculate statistics
        stats = {}
        
        for feature in numeric_features:
            if feature in entity_data.columns:
                feature_data = entity_data[feature].dropna()
                
                if not feature_data.empty:
                    stats[feature] = {
                        'mean': float(feature_data.mean()),
                        'median': float(feature_data.median()),
                        'min': float(feature_data.min()),
                        'max': float(feature_data.max()),
                        'std': float(feature_data.std()),
                        'current': float(feature_data.iloc[-1]) if len(feature_data) > 0 else 0.0
                    }
        
        # Calculate time-based patterns
        if 'time_window' in entity_data.columns:
            entity_data['hour'] = pd.to_datetime(entity_data['time_window']).dt.hour
            
            # Activity by hour
            activity_by_hour = entity_data.groupby('hour').size().to_dict()
            stats['activity_by_hour'] = {str(h): int(c) for h, c in activity_by_hour.items()}
        
        # Get anomaly score if available
        if 'anomaly_score' in entity_data.columns:
            stats['anomaly_score'] = {
                'current': float(entity_data['anomaly_score'].iloc[-1]) if len(entity_data) > 0 else 0.0,
                'mean': float(entity_data['anomaly_score'].mean()),
                'max': float(entity_data['anomaly_score'].max())
            }
        
        return {
            'entity': entity,
            'entity_type': entity_column,
            'data_points': len(entity_data),
            'time_range': {
                'start': entity_data['time_window'].min().isoformat() if 'time_window' in entity_data.columns else None,
                'end': entity_data['time_window'].max().isoformat() if 'time_window' in entity_data.columns else None
            },
            'statistics': stats
        }
    
    def _calculate_severity(self, anomaly_score: float) -> str:
        """
        Calculate severity based on anomaly score.
        
        Args:
            anomaly_score: Anomaly score (0.0-1.0)
            
        Returns:
            Severity level (Critical, High, Medium, Low)
        """
        if anomaly_score >= 0.95:
            return 'Critical'
        elif anomaly_score >= 0.9:
            return 'High'
        elif anomaly_score >= 0.8:
            return 'Medium'
        else:
            return 'Low'

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create behavioral analytics module
    analytics = BehavioralAnalytics()
    
    # Example: Create synthetic data for testing
    import pandas as pd
    import numpy as np
    from datetime import datetime, timedelta
    
    # Create normal data
    normal_data = []
    start_time = datetime.now() - timedelta(days=7)
    
    for i in range(1000):
        time_window = start_time + timedelta(minutes=i * 10)
        
        # Normal behavior
        normal_data.append({
            'time_window': time_window,
            'host': 'host1',
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
            'data_source': 'test'
        })
    
    # Create anomalous data
    anomalous_data = []
    start_time = datetime.now() - timedelta(hours=1)
    
    for i in range(10):
        time_window = start_time + timedelta(minutes=i * 10)
        
        # Anomalous behavior
        anomalous_data.append({
            'time_window': time_window,
            'host': 'host1',
            'network_traffic_volume_mean': np.random.normal(0.9, 0.1),  # High network traffic
            'number_of_logins_mean': np.random.normal(0.2, 0.05),
            'number_of_failed_logins_mean': np.random.normal(0.8, 0.1),  # High failed logins
            'number_of_accessed_files_mean': np.random.normal(0.9, 0.1),  # High file access
            'number_of_email_sent_mean': np.random.normal(0.2, 0.05),
            'cpu_usage_mean': np.random.normal(0.8, 0.1),  # High CPU usage
            'memory_usage_mean': np.random.normal(0.4, 0.1),
            'disk_io_mean': np.random.normal(0.2, 0.05),
            'network_latency_mean': np.random.normal(0.1, 0.05),
            'number_of_processes_mean': np.random.normal(0.7, 0.1),  # High process count
            'data_source': 'test'
        })
    
    # Combine data
    df_normal = pd.DataFrame(normal_data)
    df_anomalous = pd.DataFrame(anomalous_data)
    
    # Establish baseline from normal data
    analytics.establish_baseline(df_normal, entity_column='host')
    
    # Detect anomalies in new data
    result_data, anomaly_alerts = analytics.detect_anomalies(df_anomalous, entity_column='host')
    
    # Print results
    print(f"Detected {len(anomaly_alerts)} anomalies")
    for alert in anomaly_alerts:
        print(f"Anomaly at {alert['timestamp']} for {alert['entity']} with score {alert['anomaly_score']:.2f} ({alert['severity']})")
    
    # Analyze entity behavior
    behavior = analytics.analyze_entity_behavior('host1', pd.concat([df_normal, df_anomalous]), entity_column='host')
    print(f"Behavior analysis for {behavior['entity']}:")
    print(f"Data points: {behavior['data_points']}")
    print(f"Time range: {behavior['time_range']['start']} to {behavior['time_range']['end']}")
    
    # Print statistics for a few features
    for feature in ['network_traffic_volume_mean', 'number_of_failed_logins_mean', 'cpu_usage_mean']:
        stats = behavior['statistics'].get(feature, {})
        if stats:
            print(f"{feature}: mean={stats['mean']:.2f}, current={stats['current']:.2f}, max={stats['max']:.2f}")
