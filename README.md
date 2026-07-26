# 🛡️ Predictive DNS Tunneling Detection

An end-to-end machine learning and deep learning pipeline designed to detect malicious DNS tunneling activities in network traffic. This project processes raw network packets, engineers highly selective features, and evaluates Traditional, Deep Learning, and AutoML models to identify advanced attack vectors like CobaltStrike, Iodine, and dnscat2.

## 📌 Project Overview
DNS Tunneling is a sophisticated cyberattack method that encodes data of other programs or protocols in DNS queries and responses. This project builds a robust detection system capable of distinguishing between legitimate (benign) DNS queries and malicious exfiltration attempts with high accuracy and low latency.

### Key Highlights:
* **Data Processing Pipeline:** Handles over 1.4 million rows of network traffic, utilizing **Isolation Forests** for strict outlier removal to prevent model degradation.
* **Canonical Feature Selection:** Reduces dimensionality by selecting the top **23 critical features** using the union of Mutual Information (MI) scores and Random Forest Feature Importances.
* **Diverse Model Architectures:** 
  * *Traditional ML:* Random Forest, Decision Tree, Support Vector Machines (SVM), and XGBoost.
  * *Deep Learning:* Dense Neural Networks (DNN), LSTMs, and GRUs (built with TensorFlow/Keras).
  * *AutoML:* Automated pipeline optimization using TPOT and RandomizedSearchCV.
* **Robust Evaluation:** Comprehensive logging of Macro F1-Scores, Inference Latency (QPS), ROC-AUC curves, and Confusion Matrices.

---

## 📂 Repository Structure

```text
Predictive-DNS-Tunneling-Detection/
├── assets/                 # Architecture diagrams and flowchart visuals
├── configs/                # YAML and JSON configurations (e.g., paths.yaml, selected_features.json)
├── data/
│   ├── interim/            # Intermediate data states (ignored in git)
│   ├── processed/          # Final scaled datasets: X_test_scaled, y_test (ignored in git)
│   ├── raw/                # Massive raw CSV files (benign.csv, attacks/) (ignored in git)
│   └── sample/             # 100-row sample datasets for quick review
├── docs/                   # Documentation and environment setup guides
├── models/
│   ├── automl/             # TPOT exported pipelines and RandomizedSearchCV best models
│   ├── deep_learning/      # .keras artifacts for DNN, LSTM, GRU
│   └── traditional/        # .pkl artifacts and fitted StandardScaler
├── notebooks/              # Jupyter notebooks for EDA, Feature Engineering, and Evaluation
├── results/                
│   ├── confusion_matrices/ # Generated model performance heatmaps
│   ├── metrics/            # Experiment logs (experiment_log.csv) and throughput charts
│   └── roc_curves/         # Combined ROC-AUC plots
├── scripts/                # Execution scripts for model training
├── src/                    # Source code for data loading, preprocessing, and model architectures
├── .gitignore              # Protects GitHub 100MB limit by ignoring data/ files
└── README.md