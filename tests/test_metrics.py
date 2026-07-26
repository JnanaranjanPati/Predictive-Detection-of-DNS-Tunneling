import pandas as pd
import numpy as np
from src.features.feature_selection import select_and_save_features, load_selected_features

def test_feature_selection_output(tmp_path, monkeypatch):
    """Asserts feature selection produces the correct output format and saves to JSON."""
    
    # Mock get_path to point configs/selected_features to a temp directory for the test
    def mock_get_path(category, key):
        return tmp_path / "selected_features.json"
    
    import src.features.feature_selection
    monkeypatch.setattr(src.features.feature_selection, "get_path", mock_get_path)
    
    # Dummy data with 30 features
    X_train = pd.DataFrame(np.random.rand(100, 30), columns=[f'feat_{i}' for i in range(30)])
    y_train = pd.Series(np.random.choice([0, 1], size=100))
    
    # Run selection, asking for top 5 (union of MI and RF might be between 5 and 10 features total)
    selected = select_and_save_features(X_train, y_train, top_n=5)
    
    # Assertions
    assert isinstance(selected, list)
    assert 5 <= len(selected) <= 10
    
    # Assert file was created and can be loaded identically
    json_path = tmp_path / "selected_features.json"
    assert json_path.exists()
    
    loaded_features = load_selected_features()
    assert sorted(selected) == sorted(loaded_features)