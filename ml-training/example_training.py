"""
Example Model Training Script
Demonstrates how to train a malware detection model
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from typing import Tuple, List, Dict, Any


# Feature names for PE files
FEATURE_NAMES = [
    'file_size', 'file_size_kb', 'days_since_creation',
    'days_since_modified', 'location_risk', 'is_pe_file',
    'is_x86', 'is_x64', 'is_dll', 'is_executable',
    'is_pe32', 'is_pe32plus', 'is_console', 'is_gui',
    'optional_header_size', 'number_of_sections',
    'section_with_code', 'section_with_data',
    'section_with_resources', 'total_raw_size',
    'total_virtual_size', 'size_ratio',
    'suspicious_api_count', 'known_dll_count',
    'has_process_injection', 'has_registry_manipulation',
    'has_network_apis', 'has_cryptography',
    'overall_entropy', 'header_entropy', 'middle_entropy',
    'is_high_entropy', 'is_very_high_entropy',
    'string_count', 'url_count', 'ip_address_count',
    'path_count', 'is_packed', 'is_signed',
    'is_recently_created', 'is_recently_modified'
]


def generate_sample_data(
    num_samples: int = 1000,
    malware_ratio: float = 0.5
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data for demonstration

    Args:
        num_samples: Total number of samples to generate
        malware_ratio: Ratio of malware samples (0.0 to 1.0)

    Returns:
        Tuple of (features, labels)
    """
    num_malware = int(num_samples * malware_ratio)
    num_benign = num_samples - num_malware

    # Generate malware samples (label=1)
    malware_features = np.random.rand(num_malware, len(FEATURE_NAMES))
    malware_features[:, FEATURE_NAMES.index('overall_entropy')] = \
        np.random.uniform(6.0, 8.0, num_malware)
    malware_features[:, FEATURE_NAMES.index('is_high_entropy')] = 1
    malware_features[:, FEATURE_NAMES.index('suspicious_api_count')] = \
        np.random.randint(3, 15, num_malware)
    malware_features[:, FEATURE_NAMES.index('is_packed')] = \
        np.random.randint(0, 2, num_malware)
    malware_features[:, FEATURE_NAMES.index('is_signed')] = 0

    # Generate benign samples (label=0)
    benign_features = np.random.rand(num_benign, len(FEATURE_NAMES))
    benign_features[:, FEATURE_NAMES.index('overall_entropy')] = \
        np.random.uniform(3.0, 6.5, num_benign)
    benign_features[:, FEATURE_NAMES.index('is_high_entropy')] = 0
    benign_features[:, FEATURE_NAMES.index('suspicious_api_count')] = \
        np.random.randint(0, 3, num_benign)
    benign_features[:, FEATURE_NAMES.index('is_packed')] = 0
    benign_features[:, FEATURE_NAMES.index('is_signed')] = 1

    # Combine
    X = np.vstack([malware_features, benign_features])
    y = np.hstack([np.ones(num_malware), np.zeros(num_benign)])

    # Shuffle
    indices = np.random.permutation(len(y))
    return X[indices], y[indices]


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray
) -> Tuple[RandomForestClassifier, StandardScaler]:
    """
    Train a Random Forest model

    Args:
        X_train: Training features
        y_train: Training labels

    Returns:
        Tuple of (trained_model, scaler)
    """
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # Train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    model.fit(X_train_scaled, y_train)

    return model, scaler


def evaluate_model(
    model: RandomForestClassifier,
    scaler: StandardScaler,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> Dict[str, Any]:
    """
    Evaluate model performance

    Args:
        model: Trained model
        scaler: Fitted scaler
        X_test: Test features
        y_test: Test labels

    Returns:
        Dictionary of evaluation metrics
    """
    X_test_scaled = scaler.transform(X_test)

    # Get predictions
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    # Calculate metrics
    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
        'roc_auc': float(roc_auc_score(y_test, y_proba)),
    }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics['confusion_matrix'] = cm.tolist()

    return metrics


def main() -> None:
    """Main training function"""
    print("=" * 60)
    print("Malware Detection Model Training Example")
    print("=" * 60)

    # Generate sample data
    print("\n1. Generating training data...")
    X, y = generate_sample_data(num_samples=1000, malware_ratio=0.5)
    print(f"   Total samples: {len(X)}")
    print(f"   Malware: {int(sum(y))}")
    print(f"   Benign: {int(len(y) - sum(y))}")

    # Split data
    print("\n2. Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")

    # Train model
    print("\n3. Training model...")
    model, scaler = train_model(X_train, y_train)
    print("   Model trained successfully!")

    # Evaluate model
    print("\n4. Evaluating model...")
    metrics = evaluate_model(model, scaler, X_test, y_test)

    print("\n   Results:")
    print(f"   - Accuracy:  {metrics['accuracy']:.4f}")
    print(f"   - Precision: {metrics['precision']:.4f}")
    print(f"   - Recall:    {metrics['recall']:.4f}")
    print(f"   - F1 Score:  {metrics['f1_score']:.4f}")
    print(f"   - ROC AUC:    {metrics['roc_auc']:.4f}")

    print("\n   Confusion Matrix:")
    cm = metrics['confusion_matrix']
    print(f"   TN: {cm[0][0]}, FP: {cm[0][1]}")
    print(f"   FN: {cm[1][0]}, TP: {cm[1][1]}")

    # Feature importance
    print("\n5. Top 10 Important Features:")
    importance = model.feature_importances_
    feature_imp = sorted(
        zip(FEATURE_NAMES, importance),
        key=lambda x: x[1],
        reverse=True
    )
    for i, (name, imp) in enumerate(feature_imp[:10], 1):
        print(f"   {i:2d}. {name}: {imp:.4f}")

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
