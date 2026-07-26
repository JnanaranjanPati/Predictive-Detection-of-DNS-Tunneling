import pandas as pd
from sklearn.model_selection import train_test_split

def stratified_split(df: pd.DataFrame, target_col: str = 'label_encoded'):
    """
    Splits data into 70% train, 15% val, 15% test.
    Crucially, this happens BEFORE any scaling or outlier detection.
    """
    # First split: 70% train, 30% temp (val + test)
    train_df, temp_df = train_test_split(
        df, test_size=0.30, stratify=df[target_col], random_state=42
    )
    
    # Second split: split the 30% temp into 15% val and 15% test
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, stratify=temp_df[target_col], random_state=42
    )
    
    return train_df, val_df, test_df