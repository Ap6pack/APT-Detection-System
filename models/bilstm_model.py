import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, Embedding, Bidirectional, LSTM, Dense
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd

def train(df):
    X = df.drop('label', axis=1).values
    y = df['label'].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = Sequential()
    model.add(Input(shape=(X_train.shape[1],)))
    model.add(Embedding(input_dim=1000, output_dim=64))
    model.add(Bidirectional(LSTM(64)))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(np.array(X_train), np.array(y_train), epochs=10, batch_size=32)

    return model

# Testing the Bi-LSTM model
if __name__ == "__main__":
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
    model = train(df)
    print(model.summary())
