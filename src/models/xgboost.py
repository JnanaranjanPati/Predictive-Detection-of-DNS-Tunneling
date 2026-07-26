from xgboost import XGBClassifier

def get_model(): 
    return XGBClassifier(
        use_label_encoder=False, 
        eval_metric='logloss', 
        random_state=42, 
        verbosity=2  # Prints boosting iterations
    )