import pandas as pd
import pytest
from src.data.cleaning import drop_non_feature_columns

def test_leakage_prevention():
    """Asserts that label and identifier columns can never slip through."""
    dummy_data = pd.DataFrame({
        'flow_id': ['123', '456'],
        'timestamp': ['10:00', '10:01'],
        'label': ['benign', 'malicious'],
        'label_encoded': [0, 1],
        'ttl_values_mean': [64, 128],
        'sending_bytes': [500, 1000]
    })
    
    cleaned_df = drop_non_feature_columns(dummy_data)
    
    # Assert targets and identifiers are gone
    assert 'label' not in cleaned_df.columns, "CRITICAL: 'label' leaked into features!"
    assert 'label_encoded' not in cleaned_df.columns, "CRITICAL: 'label_encoded' leaked into features!"
    assert 'flow_id' not in cleaned_df.columns, "'flow_id' leaked into features!"
    assert 'timestamp' not in cleaned_df.columns, "'timestamp' leaked into features!"
    
    # Assert actual features remain
    assert 'ttl_values_mean' in cleaned_df.columns
    assert 'sending_bytes' in cleaned_df.columns