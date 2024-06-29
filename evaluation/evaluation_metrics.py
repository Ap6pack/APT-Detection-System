from sklearn.metrics import accuracy_score, roc_auc_score

def evaluate(model, df):
    X = df.drop('label', axis=1)
    y = df['label']
    predictions = model(X)
    accuracy = accuracy_score(y, predictions >= 0.5)
    roc_auc = roc_auc_score(y, predictions)
    return accuracy, roc_auc

# Testing the evaluation metrics
if __name__ == "__main__":
    import pandas as pd
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

    class MockModel:
        def __call__(self, X):
            return [0.1, 0.9, 0.1, 0.9, 0.1]

    model = MockModel()
    accuracy, roc_auc = evaluate(model, df)
    print(f'Accuracy: {accuracy}, ROC-AUC: {roc_auc}')
