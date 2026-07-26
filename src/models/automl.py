from tpot import TPOTClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV

def get_tpot_classifier() -> TPOTClassifier:
    """
    Initializes TPOT with reasonable bounds for a standard run.
    Note: For a full production sweep, generations and population_size can be increased.
    """
    return TPOTClassifier(
        generations=5,
        population_size=20,
        cv=5,
        random_state=42,
        verbosity=2,
        n_jobs=-1,
        scoring='f1_macro'  # Aligning with our metric choice for imbalanced data
    )

def get_randomized_search_cv() -> RandomizedSearchCV:
    """
    A manual hyperparameter sweep to compare against TPOT's automated pipeline.
    """
    rf = RandomForestClassifier(random_state=42)
    
    param_distributions = {
        'n_estimators': [100, 200, 300],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'bootstrap': [True, False]
    }
    
    return RandomizedSearchCV(
        estimator=rf,
        param_distributions=param_distributions,
        n_iter=15,
        cv=5,
        scoring='f1_macro',
        n_jobs=-1,
        random_state=42,
        verbose=3
    )