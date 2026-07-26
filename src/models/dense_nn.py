from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Input

def get_model(input_dim: int) -> Sequential:
    """Standard Multi-Layer Perceptron for tabular data."""
    model = Sequential([
        Input(shape=(input_dim,)),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model