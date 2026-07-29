# Predictive Detection of DNS Tunneling: A Comparative Machine Learning Framework

A comprehensive machine learning framework for predictive DNS tunneling detection using advanced feature engineering, outlier detection, intelligent feature selection, traditional machine learning, deep learning, and AutoML. The project provides a reproducible end-to-end experimental pipeline for identifying malicious DNS tunneling traffic by comparing multiple learning paradigms under a unified preprocessing and evaluation framework.

The framework implements a modular architecture that includes data preprocessing, statistical feature engineering, feature selection, model training, experiment tracking, performance evaluation, and inference. Multiple models—including Decision Tree, Random Forest, Support Vector Machine (SVM), XGBoost, Dense Neural Network, LSTM, GRU, and TPOT AutoML—are evaluated using identical datasets and evaluation metrics to provide a comprehensive comparison of their effectiveness for DNS tunneling detection.


## Key Features

* **End-to-End Machine Learning Pipeline**
  Implements a complete workflow from raw DNS traffic preprocessing to model training, evaluation, and inference within a modular and reproducible framework.

* **Advanced Data Preprocessing**
  Performs data cleaning, identifier removal, missing value handling, and Isolation Forest-based outlier detection to improve data quality before training.

* **DNS-Specific Feature Engineering**
  Extracts statistical, lexical, and network behavioural features—including packet statistics, TTL characteristics, domain entropy, and naming patterns—to effectively distinguish malicious DNS tunneling traffic from legitimate traffic.

* **Intelligent Feature Selection**
  Combines Mutual Information and Random Forest feature importance to identify the most informative features, reducing dimensionality while preserving predictive performance.

* **Comprehensive Model Benchmarking**
  Evaluates multiple learning paradigms including Decision Tree, Random Forest, Support Vector Machine (SVM), XGBoost, Dense Neural Network (DNN), LSTM, GRU, and TPOT AutoML using a unified experimental setup.

* **Configuration-Driven Architecture**
  Organizes preprocessing parameters, model settings, and training configurations through dedicated configuration files, making experiments easy to reproduce and extend.

* **Comprehensive Performance Evaluation**
  Assesses model performance using Accuracy, Precision, Recall, F1-Score, ROC-AUC, PR-AUC, Confusion Matrix, and training time for a balanced comparison across models.

* **Experiment Tracking and Reproducibility**
  Maintains detailed experiment logs, trained models, evaluation results, and configuration settings to ensure reproducible research and systematic performance analysis.

* **Modular and Scalable Codebase**
  Follows a well-structured software architecture with separate modules for data processing, feature engineering, model development, evaluation, inference, and utilities, simplifying maintenance and future development.

* **Research-Oriented Framework**
  Designed as a comparative experimental platform that enables researchers and practitioners to evaluate, extend, and benchmark different machine learning approaches for DNS tunneling detection.


## Problem Statement

The Domain Name System (DNS) is a fundamental component of modern network communication, responsible for translating human-readable domain names into IP addresses. Due to its essential role and the fact that DNS traffic is commonly permitted through enterprise firewalls, attackers increasingly exploit the DNS protocol as a covert communication channel to perform **DNS tunneling**. This technique enables malicious actors to encapsulate data within DNS queries and responses, allowing unauthorized data exfiltration, remote command-and-control (C2) communication, and malware persistence while bypassing conventional network security mechanisms.

Traditional rule-based and signature-based intrusion detection systems often struggle to detect DNS tunneling because attackers continuously modify domain structures, encryption methods, and communication patterns to evade predefined detection rules. These approaches are generally ineffective against previously unseen or evolving attack behaviours, resulting in reduced detection capability and increased false positives.

Machine learning provides a promising alternative by learning behavioural patterns directly from network traffic instead of relying on handcrafted signatures. By analysing statistical, lexical, and network-level characteristics of DNS traffic, machine learning models can identify subtle anomalies that distinguish malicious DNS tunneling activity from legitimate DNS communication.

This project addresses these challenges by developing a comprehensive, modular, and reproducible machine learning framework for predictive DNS tunneling detection. The framework integrates advanced data preprocessing, feature engineering, intelligent feature selection, traditional machine learning algorithms, deep learning models, and AutoML techniques within a unified experimental pipeline. By systematically comparing multiple learning approaches under identical preprocessing and evaluation conditions, the project aims to identify the most effective and reliable models for detecting DNS tunneling attacks while providing a scalable foundation for future cybersecurity research and real-world deployment.


## Project Objectives

The primary objective of this project is to develop a comprehensive and reproducible machine learning framework for the predictive detection of DNS tunneling attacks by leveraging advanced data preprocessing, feature engineering, and comparative model evaluation. The framework is designed to provide accurate, scalable, and extensible solutions for identifying malicious DNS traffic while serving as a benchmark for multiple learning paradigms.

The specific objectives of this project are:

* Develop a modular end-to-end pipeline for DNS tunneling detection, covering data preprocessing, feature engineering, model training, evaluation, and inference.

* Improve the quality of network traffic data through data cleaning, identifier removal, and Isolation Forest-based outlier detection.

* Engineer meaningful statistical, lexical, and network behavioural features that effectively capture the characteristics of malicious DNS tunneling traffic.

* Identify the most informative features using a hybrid feature selection strategy combining Mutual Information and Random Forest feature importance.

* Evaluate and compare the performance of traditional machine learning algorithms, deep learning models, and AutoML techniques under identical preprocessing and evaluation conditions.

* Measure model performance using comprehensive evaluation metrics, including Accuracy, Precision, Recall, F1-Score, ROC-AUC, PR-AUC, Confusion Matrix, and training time.

* Maintain reproducibility through configuration-driven experiments, experiment logging, and modular project architecture.

* Provide a scalable framework that can be extended with additional datasets, feature extraction techniques, and machine learning models for future cybersecurity research.
