def run(df):
    # List of features after preprocessing
    selected_columns = [
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

    if not all(column in df.columns for column in selected_columns):
        raise ValueError(f"Expected columns {selected_columns} not found in the dataset")

    selected_features = df[selected_columns + ['label']]
    return selected_features

# Testing the feature selection module
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
    selected_features = run(df)
    print(selected_features)
