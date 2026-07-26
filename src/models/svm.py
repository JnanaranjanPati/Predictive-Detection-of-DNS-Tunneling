from sklearn.svm import SVC

def get_model(): 
    return SVC(
        probability=True, 
        random_state=42, 
        verbose=True,  # Prints libsvm solver output
        max_iter=2000  # Hard limit to prevent endless training
    )