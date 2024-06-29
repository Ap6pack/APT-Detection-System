import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dense

print("TensorFlow version:", tf.__version__)
print("Keras version:", tf.keras.__version__)

# Simple model to verify imports
model = Sequential()
model.add(Embedding(input_dim=1000, output_dim=64, input_length=10))
model.add(Bidirectional(LSTM(64)))
model.add(Dense(1, activation='sigmoid'))

print(model.summary())
