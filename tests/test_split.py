import pandas as pd
import numpy as np
from src.data.split import stratified_split

def test_stratified_split_no_leakage():
    """Asserts 70/15/15 split ratio and ensures no overlap (leakage) between sets."""
    # Create dummy dataset of 1000 rows
    df = pd.DataFrame({
        'feature_1': np.random.rand(1000),
        'label_encoded': np.random.choice([0, 1], size=1000, p=[0.8, 0.2])
    })
    
    train_df, val_df, test_df = stratified_split(df, target_col='label_encoded')
    
    # Check approximate proportions (70%, 15%, 15%)
    assert 690 <= len(train_df) <= 710, f"Train set size unexpected: {len(train_df)}"
    assert 140 <= len(val_df) <= 160, f"Val set size unexpected: {len(val_df)}"
    assert 140 <= len(test_df) <= 160, f"Test set size unexpected: {len(test_df)}"
    
    # Assert NO leakage (indices must be mutually exclusive)
    train_idx = set(train_df.index)
    val_idx = set(val_df.index)
    test_idx = set(test_df.index)
    
    assert len(train_idx.intersection(val_idx)) == 0, "Leakage detected between train and val!"
    assert len(train_idx.intersection(test_idx)) == 0, "Leakage detected between train and test!"
    assert len(val_idx.intersection(test_idx)) == 0, "Leakage detected between val and test!"