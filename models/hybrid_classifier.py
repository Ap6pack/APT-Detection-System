def combine(lightgbm_model, bilstm_model):
    def hybrid_predict(X):
        lgbm_pred = lightgbm_model.predict_proba(X)[:, 1]
        bilstm_pred = bilstm_model.predict(X).flatten()
        final_pred = (lgbm_pred + bilstm_pred) / 2
        return final_pred
    return hybrid_predict

# Testing the hybrid classifier
if __name__ == "__main__":
    import pandas as pd
    import numpy as np

    # Sample data
    data = {
        'network_traffic_volume_mean': [1, 2, 3, 4, 5],
        'number_of_logins_mean': [5, 4, 3, 2, 1],
        'number_of_failed_logins_mean': [1, 2, 1, 2, 1],
        'number_of_accessed_files_mean': [1, 1, 1, 1, 1],
        'number_of_email_sent_mean': [2, 2, 2, 2, 2],
        'cpu_usage_mean': [0.1, 0.2, 0.3, 0.4, 0.5],
        'memory_usage_mean': [0.5, 0.4, 0.3, 0.2, 0.1],
        'disk_io_mean': [0.01, 0.02, 0.03, 0.04, 0.05],
        'network_latency_mean': [10, 20, 30, 40, 50],
        'number_of_processes_mean': [1, 1, 1, 1, 1],
        'label': [0, 1, 0, 1, 0]
    }
    df = pd.DataFrame(data)

    # Placeholder models for testing
    class MockLightGBM:
        def predict_proba(self, X):
            return np.array([[0.1, 0.9]] * len(X))

    class MockBiLSTM:
        def predict(self, X):
            return np.ones((len(X), 1))

    lightgbm_model = MockLightGBM()
    bilstm_model = MockBiLSTM()
    hybrid_model = combine(lightgbm_model, bilstm_model)
    predictions = hybrid_model(df.drop('label', axis=1))
    print(predictions)
