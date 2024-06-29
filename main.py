import logging
from threading import Thread
from data_preprocessing import preprocess
from feature_selection import hhosssa_feature_selection
from data_balancing import hhosssa_smote
from models import train_models
from evaluation import evaluation_metrics, cross_validation
from real_time_detection import data_ingestion, prediction_engine
from dashboard import app

logging.basicConfig(level=logging.INFO)

def run_data_ingestion():
    logging.info("Starting real-time data ingestion...")
    data_ingestion.run()
    logging.info("Real-time data ingestion and prediction setup completed.")

def run_dashboard():
    logging.info("Starting dashboard...")
    app.run(debug=True, use_reloader=False)

if __name__ == "__main__":
    try:
        # Load and preprocess data
        logging.info("Starting data preprocessing...")
        df = preprocess.run('/home/localhost/Projects/APT_Detection_System/synthetic_apt_dataset.csv')
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
        lgbm_model, bilstm_model, hybrid_model = train_models.run(balanced_data)
        logging.info("Model training completed.")

        # Evaluate models
        logging.info("Starting model evaluation...")
        accuracy, roc_auc = evaluation_metrics.evaluate(hybrid_model, balanced_data)
        logging.info(f"Model evaluation completed with Accuracy: {accuracy}, ROC-AUC: {roc_auc}")

        # Real-time detection setup
        ingestion_thread = Thread(target=run_data_ingestion)
        ingestion_thread.start()

        # Start prediction engine
        prediction_engine.run({'lgbm_model': lgbm_model, 'bilstm_model': bilstm_model})

        # Run dashboard
        dashboard_thread = Thread(target=run_dashboard)
        dashboard_thread.start()

        # Wait for threads to complete
        ingestion_thread.join()
        dashboard_thread.join()

    except Exception as e:
        logging.error(f"An error occurred: {e}")
