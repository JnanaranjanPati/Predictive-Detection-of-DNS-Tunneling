from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import GRU, Dense, Dropout, Input

def get_model(input_dim: int) -> Sequential:
    """
    NOTE (Issue #6 Fix): This GRU uses timesteps=1. 
    Evaluated as a tabular architecture, not a true sequence model.
    """
    model = Sequential([
        Input(shape=(1, input_dim)),
        GRU(64, activation='tanh', return_sequences=False),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model