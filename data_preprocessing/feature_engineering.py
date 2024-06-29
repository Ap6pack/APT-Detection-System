def extract_features(df):
    # Example: extracting time-domain statistical features
    df['network_traffic_volume_mean'] = df['network_traffic_volume'].rolling(window=10).mean()
    df['number_of_logins_mean'] = df['number_of_logins'].rolling(window=10).mean()
    df['number_of_failed_logins_mean'] = df['number_of_failed_logins'].rolling(window=10).mean()
    df['number_of_accessed_files_mean'] = df['number_of_accessed_files'].rolling(window=10).mean()
    df['number_of_email_sent_mean'] = df['number_of_email_sent'].rolling(window=10).mean()
    df['cpu_usage_mean'] = df['cpu_usage'].rolling(window=10).mean()
    df['memory_usage_mean'] = df['memory_usage'].rolling(window=10).mean()
    df['disk_io_mean'] = df['disk_io'].rolling(window=10).mean()
    df['network_latency_mean'] = df['network_latency'].rolling(window=10).mean()
    df['number_of_processes_mean'] = df['number_of_processes'].rolling(window=10).mean()

    # Fill any remaining NaNs after rolling
    df.bfill(inplace=True)
    df.ffill(inplace=True)

    return df
