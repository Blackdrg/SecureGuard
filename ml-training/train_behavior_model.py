"""
Behavior Anomaly Detection Model Training
Trains a model to detect anomalous process behavior based on dynamic features
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

# Try to import lightgbm
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("Warning: LightGBM not available, using RandomForest")

# Behavior feature names
BEHAVIOR_FEATURES = [
    # Process features
    'process_count', 'child_process_count', 'thread_count',
    'handle_count', 'working_set', 'cpu_usage', 'memory_usage',

    # File operations
    'file_read_count', 'file_write_count', 'file_delete_count',
    'file_create_count', 'total_bytes_read', 'total_bytes_written',

    # Registry operations
    'registry_read_count', 'registry_write_count',
    'registry_delete_count', 'registry_key_enumerate', 'registry_value_set',

    # Network features
    'network_connections', 'tcp_connections', 'udp_connections',
    'listening_ports', 'outbound_connections', 'dns_queries',

    # API call patterns
    'suspicious_api_count', 'dangerous_api_count',
    'process_injection_attempt', 'privilege_escalation_attempt',

    # Timing features
    'execution_time', 'sleep_calls', 'timed_delays',

    # Code injection indicators
    'dll_injection', 'process_hollowing', 'APC_injection',

    # Persistence indicators
    'registry_run_keys', 'scheduled_task', 'service_created',

    # Crypto operations
    'crypto_operations', 'encryption_api', 'key_generation'
]


def generate_behavior_data(num_samples=2000, anomaly_ratio=0.3):
    """Generate synthetic behavior training data"""
    print(f"Generating {num_samples} behavior samples...")

    np.random.seed(42)
    num_anomalies = int(num_samples * anomaly_ratio)
    num_normal = num_samples - num_anomalies

    # Normal behavior samples
    normal_data = {
        'process_count': np.random.uniform(20, 80, num_normal),
        'child_process_count': np.random.uniform(0, 5, num_normal),
        'thread_count': np.random.uniform(100, 500, num_normal),
        'handle_count': np.random.uniform(500, 2000, num_normal),
        'working_set': np.random.uniform(50000000, 200000000, num_normal),
        'cpu_usage': np.random.uniform(1, 30, num_normal),
        'memory_usage': np.random.uniform(100000000, 500000000, num_normal),
        'file_read_count': np.random.uniform(10, 100, num_normal),
        'file_write_count': np.random.uniform(1, 20, num_normal),
        'file_delete_count': np.zeros(num_normal),
        'file_create_count': np.random.uniform(0, 10, num_normal),
        'total_bytes_read': np.random.uniform(1000000, 10000000, num_normal),
        'total_bytes_written': np.random.uniform(100000, 1000000, num_normal),
        'registry_read_count': np.random.uniform(10, 50, num_normal),
        'registry_write_count': np.random.uniform(0, 10, num_normal),
        'registry_delete_count': np.zeros(num_normal),
        'registry_key_enumerate': np.random.uniform(0, 5, num_normal),
        'registry_value_set': np.random.uniform(0, 5, num_normal),
        'network_connections': np.random.uniform(0, 10, num_normal),
        'tcp_connections': np.random.uniform(0, 5, num_normal),
        'udp_connections': np.random.uniform(0, 3, num_normal),
        'listening_ports': np.random.uniform(0, 2, num_normal),
        'outbound_connections': np.random.uniform(0, 5, num_normal),
        'dns_queries': np.random.uniform(0, 10, num_normal),
        'suspicious_api_count': np.random.uniform(0, 2, num_normal),
        'dangerous_api_count': np.zeros(num_normal),
        'process_injection_attempt': np.zeros(num_normal),
        'privilege_escalation_attempt': np.zeros(num_normal),
        'execution_time': np.random.uniform(1, 60, num_normal),
        'sleep_calls': np.random.uniform(0, 5, num_normal),
        'timed_delays': np.random.uniform(0, 3, num_normal),
        'dll_injection': np.zeros(num_normal),
        'process_hollowing': np.zeros(num_normal),
        'APC_injection': np.zeros(num_normal),
        'registry_run_keys': np.zeros(num_normal),
        'scheduled_task': np.zeros(num_normal),
        'service_created': np.zeros(num_normal),
        'crypto_operations': np.random.uniform(0, 2, num_normal),
        'encryption_api': np.zeros(num_normal),
        'key_generation': np.zeros(num_normal)
    }

    # Anomalous/malicious behavior samples
    anomaly_data = {
        'process_count': np.random.uniform(5, 30, num_anomalies),
        'child_process_count': np.random.uniform(1, 20, num_anomalies),
        'thread_count': np.random.uniform(50, 300, num_anomalies),
        'handle_count': np.random.uniform(1000, 5000, num_anomalies),
        'working_set': np.random.uniform(10000000, 100000000, num_anomalies),
        'cpu_usage': np.random.uniform(10, 90, num_anomalies),
        'memory_usage': np.random.uniform(20000000, 200000000, num_anomalies),
        'file_read_count': np.random.uniform(50, 500, num_anomalies),
        'file_write_count': np.random.uniform(10, 200, num_anomalies),
        'file_delete_count': np.random.uniform(0, 50, num_anomalies),
        'file_create_count': np.random.uniform(5, 50, num_anomalies),
        'total_bytes_read': np.random.uniform(1e7, 1e8, num_anomalies),
        'total_bytes_written': np.random.uniform(1e6, 5e7, num_anomalies),
        'registry_read_count': np.random.uniform(50, 500, num_anomalies),
        'registry_write_count': np.random.uniform(10, 100, num_anomalies),
        'registry_delete_count': np.random.uniform(0, 20, num_anomalies),
        'registry_key_enumerate': np.random.uniform(5, 50, num_anomalies),
        'registry_value_set': np.random.uniform(5, 30, num_anomalies),
        'network_connections': np.random.uniform(5, 50, num_anomalies),
        'tcp_connections': np.random.uniform(3, 30, num_anomalies),
        'udp_connections': np.random.uniform(0, 20, num_anomalies),
        'listening_ports': np.random.uniform(0, 5, num_anomalies),
        'outbound_conn': np.random.uniform(5, 30, num_anomalies),
        'dns_queries': np.random.uniform(10, 100, num_anomalies),
        'suspicious_api_count': np.random.uniform(5, 30, num_anomalies),
        'dangerous_api_count': np.random.uniform(1, 10, num_anomalies),
        'process_injection_attempt': np.random.choice(
            [0, 1], num_anomalies, p=[0.3, 0.7]
        ),
        'privilege_escalation_attempt': np.random.choice(
            [0, 1], num_anomalies, p=[0.5, 0.5]
        ),
        'execution_time': np.random.uniform(10, 300, num_anomalies),
        'sleep_calls': np.random.uniform(10, 100, num_anomalies),
        'timed_delays': np.random.uniform(5, 50, num_anomalies),
        'dll_injection': np.random.choice([0, 1], num_anomalies, p=[0.5, 0.5]),
        'process_hollowing': np.random.choice([0, 1], num_anomalies, p=[0.7, 0.3]),
        'APC_injection': np.random.choice([0, 1], num_anomalies, p=[0.6, 0.4]),
        'registry_run_keys': np.random.choice([0, 1], num_anomalies, p=[0.5, 0.5]),
        'scheduled_task': np.random.choice([0, 1], num_anomalies, p=[0.7, 0.3]),
        'service_created': np.random.choice([0, 1], num_anomalies, p=[0.7, 0.3]),
        'crypto_operations': np.random.uniform(5, 30, num_anomalies),
        'encryption_api': np.random.choice([0, 1], num_anomalies, p=[0.5, 0.5]),
        'key_generation': np.random.choice([0, 1], num_anomalies, p=[0.6, 0.4])
    }

    # Create DataFrames
    normal_df = pd.DataFrame(normal_data)
    normal_df['label'] = 0  # Normal

    anomaly_df = pd.DataFrame(anomaly_data)
    anomaly_df['label'] = 1  # Anomaly

    # Combine and shuffle
    df = pd.concat([normal_df, anomaly_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    return df


class BehaviorDetector:
    """Behavior anomaly detection model"""

    def __init__(self, model_type='random_forest'):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = BEHAVIOR_FEATURES
        self.is_trained = False

    def create_model(self):
        if self.model_type == 'lightgbm' and HAS_LIGHTGBM:
            return lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1,
                verbose=-1
            )
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )

    def train(self, X_train, y_train):
        print(f"Training {self.model_type} behavior model...")

        X_scaled = self.scaler.fit_transform(X_train)
        self.model = self.create_model()
        self.model.fit(X_scaled, y_train)
        self.is_trained = True
        print("Training complete!")

    def predict(self, X):
        if not self.is_trained:
            raise ValueError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(self, X):
        if not self.is_trained:
            raise ValueError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def evaluate(self, X_test, y_test):
        y_pred = self.predict(X_test)
        y_proba = self.predict_proba(X_test)[:, 1]

        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba)
        }

    def get_feature_importance(self):
        if not self.is_trained or not hasattr(self.model, 'feature_importances_'):
            return None

        importance = self.model.feature_importances_
        return pd.DataFrame({
            'feature': self.feature_names,
            'importance': importance
        }).sort_values('importance', ascending=False)


def main():
    parser = argparse.ArgumentParser(
        description='Train Behavior Anomaly Detection Model'
    )
    parser.add_argument(
        '--samples', type=int, default=2000, help='Number of samples'
    )
    parser.add_argument(
        '--output', type=str, default='../models', help='Output directory'
    )
    parser.add_argument(
        '--model', type=str, default='random_forest', help='Model type'
    )
    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Generate training data
    print("\n=== Generating Training Data ===")
    df = generate_behavior_data(num_samples=args.samples, anomaly_ratio=0.3)

    # Prepare features
    X = df[BEHAVIOR_FEATURES].values
    y = df['label'].values

    print(f"Total samples: {len(X)}")
    print(f"Normal: {sum(y == 0)}, Anomalies: {sum(y == 1)}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    print("\n=== Training Model ===")
    model = BehaviorDetector(model_type=args.model)
    model.train(X_train, y_train)

    # Evaluate
    print("\n=== Evaluating Model ===")
    results = model.evaluate(X_test, y_test)

    print(f"\nModel Performance:")
    print(f"  Accuracy:  {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall:    {results['recall']:.4f}")
    print(f"  F1 Score:  {results['f1']:.4f}")
    print(f"  ROC AUC:   {results['roc_auc']:.4f}")

    # Feature importance
    print("\n=== Top 10 Important Features ===")
    importance = model.get_feature_importance()
    if importance is not None:
        print(importance.head(10).to_string(index=False))

    # Save model metadata
    metadata = {
        'name': 'SecureGuard Behavior Anomaly Detector',
        'version': '1.0.0',
        'created_at': datetime.now().isoformat(),
        'model_type': model.model_type,
        'accuracy': results['accuracy'],
        'precision': results['precision'],
        'recall': results['recall'],
        'f1_score': results['f1'],
        'roc_auc': results['roc_auc'],
        'features': BEHAVIOR_FEATURES,
        'training_samples': len(X_train),
        'dataset': 'Generated Synthetic Data'
    }

    meta_path = os.path.join(args.output, 'behavior_anomaly.meta.json')
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"\nMetadata saved: {meta_path}")

    # Save scaler parameters
    scaler_data = {
        'mean': model.scaler.mean_.tolist(),
        'scale': model.scaler.scale_.tolist(),
        'feature_names': BEHAVIOR_FEATURES
    }

    scaler_path = os.path.join(args.output, 'behavior_anomaly.scaler.json')
    with open(scaler_path, 'w') as f:
        json.dump(scaler_data, f, indent=2)
    print(f"Scaler saved: {scaler_path}")

    # Save feature importances
    if importance is not None:
        weights = dict(zip(importance['feature'], importance['importance']))
        weights_path = os.path.join(args.output, 'behavior_anomaly.weights.json')
        with open(weights_path, 'w') as f:
            json.dump(weights, f, indent=2)
        print(f"Weights saved: {weights_path}")

    print("\n=== Training Complete ===")


if __name__ == '__main__':
    main()

