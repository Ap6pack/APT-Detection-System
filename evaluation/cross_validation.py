import sys
import os
import numpy as np
import pandas as pd
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import logging
from sklearn.model_selection import KFold
from sklearn.metrics import accuracy_score, roc_auc_score
from data_preprocessing import preprocess
from feature_selection import hhosssa_feature_selection
from data_balancing import hhosssa_smote
from models.lighgbm_model import train as train_lgbm
from models.bilstm_model import train as train_bilstm
from models.hybrid_classifier import combine

def run_cross_validation(df):
    logging.info("Starting cross-validation...")

    # Preprocess and prepare data
    selected_features = hhosssa_feature_selection.run(df)
    balanced_data = hhosssa_smote.run(selected_features)
    
    X = balanced_data.drop('label', axis=1)
    y = balanced_data['label']

    # Ensure data is in float32 format
    X = X.astype(np.float32)

    # Cross-validation setup
    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    scores = {'accuracy': [], 'roc_auc': []}

    for train_index, test_index in kf.split(X):
        X_train, X_test = X.iloc[train_index], X.iloc[test_index]
        y_train, y_test = y.iloc[train_index], y.iloc[test_index]

        # Reshape data for LSTM model
        X_train_reshaped = X_train.values.reshape((X_train.shape[0], X_train.shape[1], 1))
        X_test_reshaped = X_test.values.reshape((X_test.shape[0], X_test.shape[1], 1))

        # Ensure reshaped data is in float32 format
        X_train_reshaped = X_train_reshaped.astype(np.float32)
        X_test_reshaped = X_test_reshaped.astype(np.float32)

        # Train LightGBM model
        lgbm_model = train_lgbm(balanced_data)
        lgbm_model.fit(X_train, y_train)
        
        # Correct the concatenation for Bi-LSTM model
        bilstm_train_data = pd.concat([X_train, y_train], axis=1)
        bilstm_train_data_features = bilstm_train_data.drop('label', axis=1)
        bilstm_train_data_reshaped = bilstm_train_data_features.values.reshape((bilstm_train_data_features.shape[0], bilstm_train_data_features.shape[1], 1))
        bilstm_train_data_reshaped_df = pd.DataFrame(bilstm_train_data_reshaped.reshape(bilstm_train_data_reshaped.shape[0], -1))
        bilstm_train_data_reshaped_df['label'] = y_train.reset_index(drop=True)

        bilstm_model = train_bilstm(bilstm_train_data_reshaped_df)
        
        # Combine models
        hybrid_model = combine(lgbm_model, bilstm_model)
        
        # Get combined predictions
        combined_predictions = hybrid_model(X_test)
        combined_predictions = (combined_predictions >= 0.5).astype(int)

        # Evaluate combined predictions
        accuracy = accuracy_score(y_test, combined_predictions)
        roc_auc = roc_auc_score(y_test, combined_predictions)

        scores['accuracy'].append(accuracy)
        scores['roc_auc'].append(roc_auc)

        logging.info(f"Fold Accuracy: {accuracy}, ROC-AUC: {roc_auc}")

    logging.info(f"Average Accuracy: {sum(scores['accuracy']) / len(scores['accuracy'])}")
    logging.info(f"Average ROC-AUC: {sum(scores['roc_auc']) / len(scores['roc_auc'])}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Load and preprocess data
    logging.info("Starting data preprocessing...")
    df = preprocess.run('synthetic_apt_dataset.csv')
    logging.info("Data preprocessing completed.")

    # Run cross-validation
    run_cross_validation(df)
