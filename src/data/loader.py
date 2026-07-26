import pandas as pd
from pathlib import Path
from src.utils.paths import get_path

def load_and_merge_data() -> pd.DataFrame:
    """Loads benign and attack CSVs, assuming 'label' column already exists."""
    raw_dir = get_path("data", "raw")
    benign_path = raw_dir / "benign.csv"
    attacks_dir = raw_dir / "attacks"
    
    dfs = []
    if benign_path.exists():
        print(f"Loading {benign_path.name}...")
        dfs.append(pd.read_csv(benign_path))
    else:
        print(f"WARNING: {benign_path.name} not found.")
        
    if attacks_dir.exists():
        attack_files = list(attacks_dir.glob("*.csv"))
        print(f"Found {len(attack_files)} files in attacks directory.")
        for file in attack_files:
            dfs.append(pd.read_csv(file))
    else:
        print(f"WARNING: attacks directory not found at {attacks_dir}")
            
    if not dfs:
        raise FileNotFoundError("No CSV files found in data/raw/")
        
    combined_df = pd.concat(dfs, ignore_index=True)
    
    # Handle string lowercasing just in case your labels are "Benign" or "BENIGN"
    if 'label' in combined_df.columns:
        combined_df['label'] = combined_df['label'].astype(str).str.lower()
    
    # Ensure label_encoded exists for modeling (0 = benign, 1 = malicious)
    if 'label_encoded' not in combined_df.columns:
        combined_df['label_encoded'] = (combined_df['label'] != 'benign').astype(int)
        
    # Validation Check to prevent the SMOTE 1-class error
    class_counts = combined_df['label_encoded'].value_counts()
    print("\n--- Dataset Class Distribution ---")
    print(f"0 (Benign):    {class_counts.get(0, 0)}")
    print(f"1 (Malicious): {class_counts.get(1, 0)}")
    print("----------------------------------\n")
    
    if len(class_counts) < 2:
        raise ValueError("CRITICAL: Dataset contains only 1 class. Check that both benign and attack CSVs are present and loaded correctly.")
        
    return combined_df