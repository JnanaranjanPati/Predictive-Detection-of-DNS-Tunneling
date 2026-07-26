# src/utils/compat.py
import sklearn
from packaging import version

def get_ohe_sparse_param():
    """
    Handles OneHotEncoder parameter changes across scikit-learn versions.
    Avoids the sparse vs sparse_output drift seen in the original notebooks.
    """
    if version.parse(sklearn.__version__) >= version.parse("1.2.0"):
        return {"sparse_output": False}
    return {"sparse": False}