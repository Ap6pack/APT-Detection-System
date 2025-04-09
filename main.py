import os
import yaml
import logging
import argparse
from threading import Thread
from data_preprocessing import preprocess
from feature_selection import hhosssa_feature_selection
from data_balancing import hhosssa_smote
from models import train_models
from evaluation import evaluation_metrics
from real_time_detection import data_ingestion, prediction_engine
from dashboard import app

logging.basicConfig(level=logging.INFO)

def load_config():
    """Load configuration from config.yaml file."""
    with open('config.yaml', 'r') as file:
        return yaml.safe_load(file)

def run_data_ingestion(config):
    logging.info("Starting real-time data ingestion...")
    data_ingestion.run()
    logging.info("Real-time data ingestion and prediction setup completed.")

def initialize_baselines():
    """Initialize baseline models if they don't exist."""
    logging.info("Checking for baseline models...")
    engine = prediction_engine.PredictionEngine()
    
    # Check if baseline models exist
    if not engine.behavioral_analytics.baseline_models:
        logging.info("No baseline models found. Establishing baselines...")
        try:
            # Generate synthetic data and establish baselines
            engine.establish_baseline(days=7)
            logging.info("Baseline models established successfully.")
        except Exception as e:
            logging.error(f"Failed to establish baseline models: {e}")
    else:
        logging.info("Baseline models already exist.")

def run_dashboard(config):
    logging.info("Starting dashboard...")
    app.run(
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        debug=config['dashboard']['debug']
    )

def parse_arguments():
    parser = argparse.ArgumentParser(description='APT Detection System')
    parser.add_argument('--train', action='store_true', help='Train models')
    parser.add_argument('--predict', action='store_true', help='Run prediction engine')
    parser.add_argument('--dashboard', action='store_true', help='Run dashboard')
    parser.add_argument('--all', action='store_true', help='Run all components')
    return parser.parse_args()

if __name__ == "__main__":
    try:
        # Load configuration
        config = load_config()
        
        # Parse command line arguments
        args = parse_arguments()
        
        # If no arguments provided, run all components
        if not (args.train or args.predict or args.dashboard):
            args.all = True
        
        # Train models if requested
        if args.train or args.all:
            # Load and preprocess data
            logging.info("Starting data preprocessing...")
            dataset_path = os.path.join(os.getcwd(), config['data_paths']['dataset'])
            df = preprocess.run(dataset_path)
            logging.info("Data preprocessing completed.")

            # Feature selection
            logging.info("Starting feature selection...")
            selected_features = hhosssa_feature_selection.run(df)
            logging.info("Feature selection completed.")

            # Data balancing
            logging.info("Starting data balancing...")
            balanced_data = hhosssa_smote.run(selected_features)
            logging.info("Data balancing completed.")

            # Train models
            logging.info("Starting model training...")
            lgbm_model, bilstm_model, hybrid_model = train_models.run(balanced_data, save=True)
            logging.info("Model training completed.")

            # Evaluate models
            logging.info("Starting model evaluation...")
            accuracy, roc_auc = evaluation_metrics.evaluate(hybrid_model, balanced_data)
            logging.info(f"Model evaluation completed with Accuracy: {accuracy}, ROC-AUC: {roc_auc}")
        
        # Initialize models for prediction
        models = None
        if args.train or args.all:
            # Use freshly trained models
            models = {'lgbm_model': lgbm_model, 'bilstm_model': bilstm_model}
        
        # Initialize threads
        ingestion_thread = None
        dashboard_thread = None
        
        # Initialize baseline models if needed
        if args.predict or args.dashboard or args.all:
            initialize_baselines()
        
        # Run prediction engine if requested
        if args.predict or args.all:
            # Real-time detection setup
            ingestion_thread = Thread(target=run_data_ingestion, args=(config,))
            ingestion_thread.start()

            # Start prediction engine
            logging.info("Starting prediction engine...")
            try:
                if models:
                    # Use freshly trained models
                    predict_fn = prediction_engine.run(models, use_saved_models=False)
                else:
                    # Load models from disk
                    predict_fn = prediction_engine.run(use_saved_models=True)
                logging.info("Prediction engine started successfully.")
            except Exception as e:
                logging.error(f"Failed to start prediction engine: {e}")
                # Continue with other components even if prediction engine fails
        
        # Run dashboard if requested
        if args.dashboard or args.all:
            dashboard_thread = Thread(target=run_dashboard, args=(config,))
            dashboard_thread.start()
            
        # Wait for threads to complete
        if dashboard_thread:
            dashboard_thread.join()
            
        if ingestion_thread:
            ingestion_thread.join()

    except Exception as e:
        logging.error(f"An error occurred: {e}")
