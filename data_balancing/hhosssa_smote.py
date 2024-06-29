from imblearn.over_sampling import SMOTE

def run(df):
    X = df.drop('label', axis=1)
    y = df['label']
    smote = SMOTE()
    X_res, y_res = smote.fit_resample(X, y)
    balanced_data = X_res.copy()
    balanced_data['label'] = y_res
    return balanced_data

# Testing the data balancing module
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
    balanced_data = run(df)
    print(balanced_data)
