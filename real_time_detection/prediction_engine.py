import os
import yaml
import joblib
import numpy as np
from tensorflow.keras.models import load_model

def load_config():
    """Load configuration from config.yaml file."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

def load_models():
    """Load trained models from disk."""
    config = load_config()
    models = {}
    
    # Get base directory for models
    base_dir = config['model_paths']['base_dir']
    
    # Construct full paths to model files
    lgbm_path = os.path.join(base_dir, config['model_paths']['lightgbm'])
    bilstm_path = os.path.join(base_dir, config['model_paths']['bilstm'])
    
    # Check if models exist
    if os.path.exists(lgbm_path):
        # Load LightGBM model
        lgbm_model = joblib.load(lgbm_path)
        models['lgbm_model'] = lgbm_model
        print(f"[+] LightGBM model loaded from {lgbm_path}")
    
    if os.path.exists(bilstm_path):
        # Load Bi-LSTM model
        bilstm_model = load_model(bilstm_path)
        models['bilstm_model'] = bilstm_model
        print(f"[+] Bi-LSTM model loaded from {bilstm_path}")
    
    return models

def run(models=None, use_saved_models=True):
    """
    Initialize prediction engine with models.
    
    Args:
        models: Dictionary of models to use for prediction
        use_saved_models: Whether to load saved models from disk
        
    Returns:
        Prediction function
    """
    # If no models provided and use_saved_models is True, load models from disk
    if models is None and use_saved_models:
        models = load_models()
        if not models:
            raise ValueError("No saved models found and no models provided.")
    
    # Use models for real-time prediction
    def predict(data):
        predictions = {}
        
        # Reshape data for Bi-LSTM if needed
        bilstm_data = None
        if 'bilstm_model' in models and len(data.shape) == 2:
            bilstm_data = data.reshape((data.shape[0], data.shape[1], 1))
        
        for model_name, model in models.items():
            if model_name == 'bilstm_model' and bilstm_data is not None:
                predictions[model_name] = model.predict(bilstm_data)
            else:
                predictions[model_name] = model.predict(data)
        
        return predictions
    
    return predict

# Testing prediction engine
if __name__ == "__main__":
    class MockModel:
        def predict(self, data):
            return [0]

    # Test with provided models
    models = {'model1': MockModel(), 'model2': MockModel()}
    data = np.array([1, 2, 3, 4, 5]).reshape(1, -1)
    predictions = run(models, use_saved_models=False).predict(data)
    print("Predictions with provided models:", predictions)
    
    # Test with saved models (if available)
    try:
        predict_fn = run(use_saved_models=True)
        predictions = predict_fn(data)
        print("Predictions with saved models:", predictions)
    except ValueError as e:
        print(f"Could not load saved models: {e}")
