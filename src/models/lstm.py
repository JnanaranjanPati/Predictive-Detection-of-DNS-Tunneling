from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input

def get_model(input_dim: int) -> Sequential:
    """
    NOTE (Issue #6 Fix): This LSTM uses timesteps=1. 
    It is being evaluated strictly as a non-linear tabular architecture, 
    not a temporal sequence model. It maps the feature vector to a hidden state 
    without looking across multiple requests.
    """
    model = Sequential([
        Input(shape=(1, input_dim)),
        LSTM(64, activation='tanh', return_sequences=False),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model