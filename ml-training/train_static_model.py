"""
Static Malware Detection Model Training
Trains a model to detect malware based on PE file features
Compatible with EMBER dataset format
"""

import os
import json
import argparse
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
import warnings

from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from sklearn.base import BaseEstimator
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    matthews_corrcoef,
    balanced_accuracy_score,
)

warnings.filterwarnings('ignore')

# Try to import lightgbm (recommended for malware detection)
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("Warning: LightGBM not available, using RandomForest")

# Try to import torch for neural network
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    print("Warning: PyTorch not available")

# Feature names matching C# FeatureExtractor
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


class MalwareDetector:
    """Static malware detection model"""

    def __init__(self, model_type='random_forest', use_scaling=True):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler() if use_scaling else None
        self.minmax_scaler = MinMaxScaler() if use_scaling else None
        self.feature_names = FEATURE_NAMES
        self.is_trained = False
        self.use_scaling = use_scaling
        self.cv_scores = {}

    def create_model(self):
        """Create the ML model based on type"""
        if self.model_type == 'lightgbm' and HAS_LIGHTGBM:
            return lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=10,
                learning_rate=0.1,
                num_leaves=31,
                random_state=42,
                n_jobs=-1,
                verbose=-1,
                force_col_wise=True,
                class_weight='balanced'
            )
        elif self.model_type == 'gradient_boosting':
            return GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
                validation_fraction=0.1,
                n_iter_no_change=10
            )
        else:
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )

    def preprocess(self, X, fit=True):
        """Preprocess features"""
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, negin=-1e6)

        if self.use_scaling:
            if fit:
                X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = self.scaler.transform(X)
            return X_scaled
        return X

    def train(self, X_train, y_train, perform_cv=True, cv_folds=5):
        """Train the model with optional cross-validation"""
        print(f"Training {self.model_type} model...")

        # Preprocess training data (fit scaler)
        X_train_processed = self.preprocess(X_train, fit=True)

        # Create and train model
        self.model = self.create_model()

        # Perform cross-validation if requested
        if perform_cv:
            print(f"Performing {cv_folds}-fold cross-validation...")
            cv = StratifiedKFold(
                n_splits=cv_folds, shuffle=True, random_state=42
            )

            # Cross-validation for different metrics
            self.cv_scores['accuracy'] = cross_val_score(
                self.model, X_train_processed, y_train,
                cv=cv, scoring='accuracy'
            )
            self.cv_scores['f1'] = cross_val_score(
                self.model, X_train_processed, y_train,
                cv=cv, scoring='f1'
            )
            self.cv_scores['roc_auc'] = cross_val_score(
                self.model, X_train_processed, y_train,
                cv=cv, scoring='roc_auc'
            )
            self.cv_scores['precision'] = cross_val_score(
                self.model, X_train_processed, y_train,
                cv=cv, scoring='precision'
            )
            self.cv_scores['recall'] = cross_val_score(
                self.model, X_train_processed, y_train,
                cv=cv, scoring='recall'
            )

            print("Cross-validation results:")
            for metric, scores in self.cv_scores.items():
                mean_val = scores.mean()
                std_val = scores.std() * 2
                print(f"  {metric}: {mean_val:.4f} (+/- {std_val:.4f})")

        # Train on full training set
        self.model.fit(X_train_processed, y_train)

        self.is_trained = True
        print("Training complete!")

    def predict(self, X):
        """Make predictions"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        X_scaled = self.preprocess(X, fit=False)
        return self.model.predict(X_scaled)

    def predict_proba(self, X):
        """Get prediction probabilities"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        X_scaled = self.preprocess(X, fit=False)
        return self.model.predict_proba(X_scaled)

    def evaluate(self, X_test, y_test):
        """Evaluate model performance with comprehensive metrics"""
        y_pred = self.predict(X_test)
        y_proba = self.predict_proba(X_test)[:, 1]

        results = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(
                y_test, y_pred, average='binary', zero_division=0
            ),
            'recall': recall_score(
                y_test, y_pred, average='binary', zero_division=0
            ),
            'f1': f1_score(
                y_test, y_pred, average='binary', zero_division=0
            ),
            'roc_auc': roc_auc_score(y_test, y_proba),
            'balanced_accuracy': balanced_accuracy_score(y_test, y_pred),
            'mcc': matthews_corrcoef(y_test, y_pred)
        }

        # Get confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        results['confusion_matrix'] = cm.tolist()

        # Calculate additional metrics from confusion matrix
        tn, fp, fn, tp = cm.ravel()
        results['true_negatives'] = int(tn)
        results['false_positives'] = int(fp)
        results['false_negatives'] = int(fn)
        results['true_positives'] = int(tp)

        # Calculate per-class metrics
        denom = tn + fp
        results['specificity'] = tn / denom if denom > 0 else 0
        denom = tn + fn
        results['npv'] = tn / denom if denom > 0 else 0

        return results, y_pred, y_proba

    def get_feature_importance(self):
        """Get feature importance scores"""
        if not self.is_trained:
            return None

        if hasattr(self.model, 'feature_importances_'):
            importance = self.model.feature_importances_
            feature_imp = pd.DataFrame({
                'feature': self.feature_names[:len(importance)],
                'importance': importance
            }).sort_values('importance', ascending=False)
            return feature_imp
        return None


class NeuralNetworkClassifier(nn.Module):
    """PyTorch Neural Network for malware detection"""

    def __init__(self, input_size, hidden_sizes=(256, 128, 64), dropout=0.3):
        super(NeuralNetworkClassifier, self).__init__()

        layers = []
        prev_size = input_size

        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.BatchNorm1d(hidden_size),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_size = hidden_size

        layers.append(nn.Linear(prev_size, 1))

        self.network = nn.Sequential(*layers)

    def forward(self, x):
        return self.network(x).squeeze()


def train_neural_network(
    X_train, y_train, X_test, y_test,
    hidden_sizes=(256, 128, 64),
    epochs=50, batch_size=64, lr=0.001
):
    """Train a neural network model"""
    if not HAS_TORCH:
        print("PyTorch not available")
        return None

    # Scale data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Convert to tensors
    X_train_tensor = torch.FloatTensor(X_train_scaled)
    y_train_tensor = torch.FloatTensor(y_train)

    # Create DataLoader
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True
    )

    # Initialize model
    input_size = X_train.shape[1]
    model = NeuralNetworkClassifier(input_size, hidden_sizes)

    # Loss and optimizer
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', patience=5, factor=0.5
    )

    # Training loop
    model.train()

    for epoch in range(epochs):
        epoch_loss = 0
        for batch_X, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / len(train_loader)
        scheduler.step(avg_loss)

        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

    # Evaluation
    model.eval()
    with torch.no_grad():
        X_test_tensor = torch.FloatTensor(X_test_scaled)
        outputs = model(X_test_tensor)
        predictions = (torch.sigmoid(outputs) > 0.5).numpy().astype(int)
        probabilities = torch.sigmoid(outputs).numpy()

    results = {
        'accuracy': accuracy_score(y_test, predictions),
        'precision': precision_score(
            y_test, predictions, zero_division=0
        ),
        'recall': recall_score(y_test, predictions, zero_division=0),
        'f1': f1_score(y_test, predictions, zero_division=0),
        'roc_auc': roc_auc_score(y_test, probabilities)
    }

    return model, results, predictions, probabilities


def generate_sample_data(num_samples=1000, malware_ratio=0.5):
    """Generate sample training data"""
    print(f"Generating {num_samples} sample training data...")

    np.random.seed(42)

    num_malware = int(num_samples * malware_ratio)
    num_benign = num_samples - num_malware

    # Generate malware samples
    malware_data = {
        'file_size': np.random.exponential(500000, num_malware),
        'file_size_kb': np.random.exponential(500, num_malware),
        'days_since_creation': np.random.uniform(0, 30, num_malware),
        'days_since_modified': np.random.uniform(0, 30, num_malware),
        'location_risk': np.random.uniform(0.5, 0.8, num_malware),
        'is_pe_file': np.ones(num_malware),
        'is_x86': np.random.choice([0, 1], num_malware, p=[0.3, 0.7]),
        'is_x64': np.random.choice([0, 1], num_malware, p=[0.7, 0.3]),
        'is_dll': np.random.choice([0, 1], num_malware, p=[0.8, 0.2]),
        'is_executable': np.ones(num_malware),
        'is_pe32': np.random.choice([0, 1], num_malware, p=[0.4, 0.6]),
        'is_pe32plus': np.random.choice([0, 1], num_malware, p=[0.6, 0.4]),
        'is_console': np.random.choice([0, 1], num_malware, p=[0.6, 0.4]),
        'is_gui': np.random.choice([0, 1], num_malware, p=[0.5, 0.5]),
        'optional_header_size': np.random.uniform(224, 240, num_malware),
        'number_of_sections': np.random.randint(2, 8, num_malware),
        'section_with_code': np.random.randint(1, 4, num_malware),
        'section_with_data': np.random.randint(0, 3, num_malware),
        'section_with_resources': np.random.randint(0, 2, num_malware),
        'total_raw_size': np.random.exponential(100000, num_malware),
        'total_virtual_size': np.random.exponential(100000, num_malware),
        'size_ratio': np.random.uniform(0.8, 1.5, num_malware),
        'suspicious_api_count': np.random.randint(3, 15, num_malware),
        'known_dll_count': np.random.randint(1, 5, num_malware),
        'has_process_injection': np.random.choice(
            [0, 1], num_malware, p=[0.3, 0.7]
        ),
        'has_registry_manipulation': np.random.choice(
            [0, 1], num_malware, p=[0.4, 0.6]
        ),
        'has_network_apis': np.random.choice(
            [0, 1], num_malware, p=[0.3, 0.7]
        ),
        'has_cryptography': np.random.choice(
            [0, 1], num_malware, p=[0.5, 0.5]
        ),
        'overall_entropy': np.random.uniform(6.0, 8.0, num_malware),
        'header_entropy': np.random.uniform(4.0, 7.0, num_malware),
        'middle_entropy': np.random.uniform(5.0, 8.0, num_malware),
        'is_high_entropy': np.ones(num_malware),
        'is_very_high_entropy': np.random.choice(
            [0, 1], num_malware, p=[0.5, 0.5]
        ),
        'string_count': np.random.randint(100, 1000, num_malware),
        'url_count': np.random.randint(0, 20, num_malware),
        'ip_address_count': np.random.randint(0, 5, num_malware),
        'path_count': np.random.randint(0, 10, num_malware),
        'is_packed': np.random.choice([0, 1], num_malware, p=[0.4, 0.6]),
        'is_signed': np.zeros(num_malware),
        'is_recently_created': np.random.choice(
            [0, 1], num_malware, p=[0.3, 0.7]
        ),
        'is_recently_modified': np.random.choice(
            [0, 1], num_malware, p=[0.3, 0.7]
        )
    }

    # Generate benign samples
    benign_data = {
        'file_size': np.random.exponential(2000000, num_benign),
        'file_size_kb': np.random.exponential(2000, num_benign),
        'days_since_creation': np.random.uniform(30, 365, num_benign),
        'days_since_modified': np.random.uniform(30, 365, num_benign),
        'location_risk': np.random.uniform(0.1, 0.3, num_benign),
        'is_pe_file': np.ones(num_benign),
        'is_x86': np.random.choice([0, 1], num_benign, p=[0.4, 0.6]),
        'is_x64': np.random.choice([0, 1], num_benign, p=[0.5, 0.5]),
        'is_dll': np.random.choice([0, 1], num_benign, p=[0.85, 0.15]),
        'is_executable': np.ones(num_benign),
        'is_pe32': np.random.choice([0, 1], num_benign, p=[0.5, 0.5]),
        'is_pe32plus': np.random.choice([0, 1], num_benign, p=[0.5, 0.5]),
        'is_console': np.random.choice([0, 1], num_benign, p=[0.4, 0.6]),
        'is_gui': np.random.choice([0, 1], num_benign, p=[0.5, 0.5]),
        'optional_header_size': np.random.uniform(224, 240, num_benign),
        'number_of_sections': np.random.randint(3, 6, num_benign),
        'section_with_code': np.random.randint(1, 3, num_benign),
        'section_with_data': np.random.randint(1, 3, num_benign),
        'section_with_resources': np.random.randint(0, 2, num_benign),
        'total_raw_size': np.random.exponential(500000, num_benign),
        'total_virtual_size': np.random.exponential(500000, num_benign),
        'size_ratio': np.random.uniform(0.9, 1.1, num_benign),
        'suspicious_api_count': np.random.randint(0, 3, num_benign),
        'known_dll_count': np.random.randint(3, 10, num_benign),
        'has_process_injection': np.zeros(num_benign),
        'has_registry_manipulation': np.random.choice(
            [0, 1], num_benign, p=[0.9, 0.1]
        ),
        'has_network_apis': np.random.choice(
            [0, 1], num_benign, p=[0.7, 0.3]
        ),
        'has_cryptography': np.random.choice(
            [0, 1], num_benign, p=[0.8, 0.2]
        ),
        'overall_entropy': np.random.uniform(3.0, 6.5, num_benign),
        'header_entropy': np.random.uniform(3.0, 5.5, num_benign),
        'middle_entropy': np.random.uniform(3.0, 6.0, num_benign),
        'is_high_entropy': np.zeros(num_benign),
        'is_very_high_entropy': np.zeros(num_benign),
        'string_count': np.random.randint(50, 500, num_benign),
        'url_count': np.random.randint(0, 5, num_benign),
        'ip_address_count': np.zeros(num_benign),
        'path_count': np.random.randint(0, 5, num_benign),
        'is_packed': np.zeros(num_benign),
        'is_signed': np.random.choice([0, 1], num_benign, p=[0.2, 0.8]),
        'is_recently_created': np.zeros(num_benign),
        'is_recently_modified': np.zeros(num_benign)
    }

    # Combine data
    malware_df = pd.DataFrame(malware_data)
    malware_df['label'] = 1

    benign_df = pd.DataFrame(benign_data)
    benign_df['label'] = 0

    # Combine and shuffle
    df = pd.concat([malware_df, benign_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    return df


def load_ember_dataset(data_dir):
    """Load EMBER dataset placeholder"""
    ember_features = [
        'byte_histogram', 'byte_entropy_histogram', 'section_info',
        'imports', 'exports', 'header_info', 'strings'
    ]

    print("EMBER dataset loader - place files in data directory")
    print("Expected features: {}".format(ember_features))

    return None


def export_to_onnx(model, output_path, feature_names):
    """Export trained model to ONNX format"""
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        initial_type = [
            ('float_input', FloatTensorType([None, len(feature_names)]))
        ]

        onnx_model = convert_sklearn(model, initial_type=initial_type)

        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())

        print("Model exported to ONNX: {}".format(output_path))
        return True
    except ImportError:
        print("skl2onnx not available, skipping ONNX export")
        return False
    except Exception as e:
        print("ONNX export failed: {}".format(e))
        return False


def save_model_metadata(model, results, output_dir, num_samples, cv_scores=None):
    """Save model metadata"""
    metadata = {
        'name': 'SecureGuard Static Malware Detector',
        'version': '1.0.0',
        'created_at': datetime.now().isoformat(),
        'model_type': model.model_type,
        'accuracy': results.get('accuracy', 0),
        'precision': results.get('precision', 0),
        'recall': results.get('recall', 0),
        'f1_score': results.get('f1', 0),
        'roc_auc': results.get('roc_auc', 0),
        'balanced_accuracy': results.get('balanced_accuracy', 0),
        'mcc': results.get('mcc', 0),
        'specificity': results.get('specificity', 0),
        'features': model.feature_names,
        'training_samples': num_samples,
        'dataset': 'Generated Sample Data',
        'note': 'Replace with EMBER/VirusShare for production'
    }

    # Add cross-validation scores if available
    if cv_scores:
        metadata['cross_validation'] = {}
        for metric, scores in cv_scores.items():
            metadata['cross_validation'][metric] = {
                'mean': float(scores.mean()),
                'std': float(scores.std())
            }

    # Add confusion matrix details
    metadata['confusion_matrix'] = {
        'true_negatives': results.get('true_negatives', 0),
        'false_positives': results.get('false_positives', 0),
        'false_negatives': results.get('false_negatives', 0),
        'true_positives': results.get('true_positives', 0)
    }

    metadata_path = os.path.join(output_dir, 'static_pe_malware.meta.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print("Metadata saved: {}".format(metadata_path))


def print_classification_report(y_test, y_pred):
    """Print detailed classification report"""
    print("\nClassification Report:")
    print("=" * 60)
    print(classification_report(
        y_test, y_pred, target_names=['Benign', 'Malware']
    ))
    print("=" * 60)


def print_confusion_matrix(results):
    """Print confusion matrix in readable format"""
    print("\nConfusion Matrix:")
    print("=" * 40)
    print("                  Predicted")
    print("                Benign  Malware")
    tn = results['true_negatives']
    fp = results['false_positives']
    fn = results['false_negatives']
    tp = results['true_positives']
    print("Actual Benign    {:5d}   {:5d}".format(tn, fp))
    print("       Malware   {:5d}   {:5d}".format(fn, tp))
    print("=" * 40)


def main():
    parser = argparse.ArgumentParser(
        description='Train Static Malware Detection Model'
    )
    parser.add_argument(
        '--model', type=str, default='random_forest',
        choices=['random_forest', 'lightgbm', 'gradient_boosting',
                 'neural_network'],
        help='Model type to train'
    )
    parser.add_argument(
        '--samples', type=int, default=2000,
        help='Number of training samples'
    )
    parser.add_argument(
        '--output', type=str, default='../models',
        help='Output directory for model'
    )
    parser.add_argument(
        '--test-size', type=float, default=0.2,
        help='Test set ratio'
    )
    parser.add_argument(
        '--no-cv', action='store_true',
        help='Disable cross-validation'
    )
    parser.add_argument(
        '--cv-folds', type=int, default=5,
        help='Number of cross-validation folds'
    )
    parser.add_argument(
        '--no-scaling', action='store_true',
        help='Disable feature scaling'
    )
    parser.add_argument(
        '--data-file', type=str, default=None,
        help='Path to custom training data CSV'
    )

    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Generate or load training data
    print("\n=== Loading Training Data ===")

    if args.data_file and os.path.exists(args.data_file):
        print("Loading training data from {}".format(args.data_file))
        df = pd.read_csv(args.data_file)
        print("Loaded {} samples from file".format(len(df)))
    else:
        df = generate_sample_data(num_samples=args.samples, malware_ratio=0.5)

    # Ensure columns match expected feature names
    available_features = [
        col for col in FEATURE_NAMES if col in df.columns
    ]
    missing_features = [
        col for col in FEATURE_NAMES if col not in df.columns
    ]

    if missing_features:
        print("Warning: Missing features: {}".format(missing_features))
        for feat in missing_features:
            df[feat] = 0

    # Use only available features + label
    feature_cols = available_features + missing_features
    X = df[feature_cols].values
    y = df['label'].values

    print("\nDataset Summary:")
    print("  Total samples: {}".format(len(X)))
    print("  Features: {}".format(X.shape[1]))
    print("  Malware samples: {}".format(sum(y == 1)))
    print("  Benign samples: {}".format(sum(y == 0)))

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    print("\nTraining samples: {}".format(len(X_train)))
    print("Test samples: {}".format(len(X_test)))

    # Train model
    print("\n=== Training Model ===")

    if args.model == 'neural_network':
        if not HAS_TORCH:
            print("PyTorch not available, falling back to RandomForest")
            args.model = 'random_forest'
        else:
            nn_model = None
            nn_results = None

    if args.model != 'neural_network':
        model = MalwareDetector(
            model_type=args.model,
            use_scaling=not args.no_scaling
        )
        model.train(
            X_train, y_train,
            perform_cv=not args.no_cv,
            cv_folds=args.cv_folds
        )

        # Evaluate
        print("\n=== Evaluating Model ===")
        results, predictions, probabilities = model.evaluate(X_test, y_test)

        print("\nModel Performance:")
        print("  Accuracy:          {:.4f}".format(results['accuracy']))
        print("  Precision:         {:.4f}".format(results['precision']))
        print("  Recall:            {:.4f}".format(results['recall']))
        print("  F1 Score:          {:.4f}".format(results['f1']))
        print("  ROC AUC:           {:.4f}".format(results['roc_auc']))
        print("  Balanced Accuracy: {:.4f}".format(results['balanced_accuracy']))
        print("  MCC:               {:.4f}".format(results['mcc']))
        print("  Specificity:       {:.4f}".format(results['specificity']))

        print_confusion_matrix(results)
        print_classification_report(y_test, predictions)

        # Feature importance
        print("\n=== Top 10 Important Features ===")
        importance = model.get_feature_importance()
        if importance is not None:
            print(importance.head(10).to_string(index=False))

        # Save model
        model_path = os.path.join(args.output, 'static_pe_malware.joblib')
        try:
            import joblib
            joblib.dump(model, model_path)
            print("\nModel saved: {}".format(model_path))
        except ImportError:
            model_path = model_path.replace('.joblib', '.pkl')
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            print("\nModel saved: {}".format(model_path))

        # Export to ONNX
        onnx_path = os.path.join(args.output, 'static_pe_malware.onnx')
        export_to_onnx(model.model, onnx_path, FEATURE_NAMES)

        # Save metadata
        save_model_metadata(
            model, results, args.output, len(X_train), model.cv_scores
        )

    else:
        # Neural network training
        print("\nTraining Neural Network...")
        nn_model, nn_results, nn_preds, nn_proba = train_neural_network(
            X_train, y_train, X_test, y_test,
            hidden_sizes=(256, 128, 64),
            epochs=50,
            batch_size=64
        )

        print("\nNeural Network Performance:")
        print("  Accuracy:  {:.4f}".format(nn_results['accuracy']))
        print("  Precision: {:.4f}".format(nn_results['precision']))
        print("  Recall:    {:.4f}".format(nn_results['recall']))
        print("  F1 Score:  {:.4f}".format(nn_results['f1']))
        print("  ROC AUC:   {:.4f}".format(nn_results['roc_auc']))

        # Save neural network model
        if nn_model:
            torch_path = os.path.join(
                args.output, 'static_pe_malware_nn.pt'
            )
            torch.save(nn_model.state_dict(), torch_path)
            print("\nNeural network saved: {}".format(torch_path))

            # Save metadata for neural network
            metadata = {
                'name': 'SecureGuard Malware Detector (Neural Network)',
                'version': '1.0.0',
                'created_at': datetime.now().isoformat(),
                'model_type': 'neural_network',
                'accuracy': nn_results['accuracy'],
                'precision': nn_results['precision'],
                'recall': nn_results['recall'],
                'f1_score': nn_results['f1'],
                'roc_auc': nn_results['roc_auc'],
                'features': FEATURE_NAMES,
                'training_samples': len(X_train),
                'hidden_layers': [256, 128, 64],
                'dataset': 'Generated Sample Data'
            }

            metadata_path = os.path.join(
                args.output, 'static_pe_malware_nn.meta.json'
            )
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            print("Metadata saved: {}".format(metadata_path))

    # Save sample training data
    csv_path = os.path.join(args.output, 'training_data.csv')
    df.to_csv(csv_path, index=False)
    print("Training data saved: {}".format(csv_path))

    print("\n=== Training Complete ===")


if __name__ == '__main__':
    main()
