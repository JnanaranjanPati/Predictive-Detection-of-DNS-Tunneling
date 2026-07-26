import pandas as pd
from pathlib import Path

def merge_csv_files(file_paths: list[Path]) -> pd.DataFrame:
    """Combines a list of CSV paths into a single DataFrame."""
    dfs = []
    for file in file_paths:
        if file.exists():
            dfs.append(pd.read_csv(file))
            
    if not dfs:
        raise ValueError("No valid CSV files provided for merging.")
        
    return pd.concat(dfs, ignore_index=True)