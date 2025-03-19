import os
import yaml
import joblib
from tensorflow.keras.models import save_model
from .lighgbm_model import train as train_lgbm
from .bilstm_model import train as train_bilstm
from .hybrid_classifier import combine

def load_config():
    """Load configuration from config.yaml file."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

def save_models(lgbm_model, bilstm_model):
    """Save trained models to disk."""
    config = load_config()
    
    # Get base directory for models
    base_dir = config['model_paths']['base_dir']
    
    # Construct full paths to model files
    lgbm_path = os.path.join(base_dir, config['model_paths']['lightgbm'])
    bilstm_path = os.path.join(base_dir, config['model_paths']['bilstm'])
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(lgbm_path), exist_ok=True)
    os.makedirs(os.path.dirname(bilstm_path), exist_ok=True)
    
    # Save LightGBM model
    joblib.dump(lgbm_model, lgbm_path)
    print(f"[+] LightGBM model saved to {lgbm_path}")
    
    # Save Bi-LSTM model
    save_model(bilstm_model, bilstm_path)
    print(f"[+] Bi-LSTM model saved to {bilstm_path}")

def run(df, save=True):
    """Train models and optionally save them to disk."""
    lgbm_model = train_lgbm(df)
    bilstm_model = train_bilstm(df)
    hybrid_model = combine(lgbm_model, bilstm_model)
    
    if save:
        save_models(lgbm_model, bilstm_model)
    
    return lgbm_model, bilstm_model, hybrid_model
