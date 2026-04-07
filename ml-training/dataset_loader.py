"""
Dataset Loader for ML Training
Supports EMBER, VirusShare, and custom datasets
"""

import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


class MalwareDatasetLoader:
    """Load and preprocess malware datasets"""

    # Feature names for PE files (EMBER-compatible)
    PE_FEATURES = [
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

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def load_ember_dataset(
        self, version: str = "2018"
    ) -> Optional[pd.DataFrame]:
        """
        Load EMBER (Empirical Malware Benchmark) dataset
        Download from: https://github.com/elastic/ember
        """
        ember_dir = self.data_dir / "ember"

        if not ember_dir.exists():
            msg = f"EMBER dataset not found at {ember_dir}"
            print(msg)
            msg2 = "Download from: https://github.com/elastic/ember"
            print(msg2)

        # Look for ember_2018_1.csv or similar
        ember_files = list(ember_dir.glob("ember*.csv"))

        if not ember_files:
            print("No EMBER CSV files found")
            return None

        # Load the largest CSV (typically the full dataset)
        ember_file = max(ember_files, key=lambda x: x.stat().st_size)
        print(f"Loading EMBER dataset from {ember_file}")

        df = pd.read_csv(ember_file)

        # EMBER has 'label' column: 0=benign, 1=malware, -1=unlabeled
        # Filter to only labeled samples
        df = df[df['label'] != -1]

        print(f"Loaded {len(df)} labeled samples")
        print(f"Malware: {sum(df['label'] == 1)}, "
              f"Benign: {sum(df['label'] == 0)}")

        return df

    def load_virusshare(
        self, limit: Optional[int] = None
    ) -> List[bytes]:
        """
        Load malware samples from VirusShare
        Note: Requires access to VirusShare dataset

        Returns list of file bytes
        """
        virusshare_dir = self.data_dir / "virusshare"

        if not virusshare_dir.exists():
            print(f"VirusShare directory not found at {virusshare_dir}")
            return []

        malware_files = []

        # VirusShare files are named with hash
        for i, filepath in enumerate(virusshare_dir.glob("*.bin")):
            if limit and i >= limit:
                break

            try:
                with open(filepath, 'rb') as f:
                    malware_files.append(f.read())
            except Exception as e:
                print(f"Error loading {filepath}: {e}")

        print(f"Loaded {len(malware_files)} VirusShare samples")
        return malware_files

    def load_microsoft_kaggle(self) -> Optional[pd.DataFrame]:
        """
        Load Microsoft Malware dataset from Kaggle
        Download from: https://www.kaggle.com/c/malware-classification
        """
        ms_dir = self.data_dir / "microsoft"

        if not ms_dir.exists():
            print(f"Microsoft dataset not found at {ms_dir}")
            return None

        # Microsoft dataset typically has trainLabels.csv and asm files
        labels_file = ms_dir / "trainLabels.csv"

        if not labels_file.exists():
            print("trainLabels.csv not found")
            return None

        df = pd.read_csv(labels_file)
        print(f"Loaded {len(df)} Microsoft samples")

        return df

    def load_custom_csv(self, filepath: str) -> pd.DataFrame:
        """Load custom dataset from CSV"""
        print(f"Loading custom dataset from {filepath}")

        df = pd.read_csv(filepath)
        print(f"Loaded {len(df)} samples")

        return df

    def extract_pe_features_from_file(self, filepath: str) -> Dict:
        """
        Extract features from a PE file
        This mirrors the C# FeatureExtractor
        """
        features: Dict = {}

        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            # Basic features
            features['file_size'] = len(data)
            features['file_size_kb'] = len(data) / 1024

            # MZ header check
            if len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A:
                features['is_pe_file'] = 1

                # Get PE offset
                if len(data) >= 64:
                    pe_offset = struct.unpack('<I', data[60:64])[0]

                    if pe_offset < len(data) - 24:
                        # PE signature
                        if data[pe_offset:pe_offset + 2] == b'PE\x00\x00':
                            # Machine type
                            machine = struct.unpack(
                                '<H', data[pe_offset + 4:pe_offset + 6]
                            )[0]
                            features['is_x86'] = 1 if machine == 0x014C else 0
                            features['is_x64'] = 1 if machine == 0x8664 else 0

                            # Number of sections
                            num_sections = struct.unpack(
                                '<H', data[pe_offset + 6:pe_offset + 8]
                            )[0]
                            features['number_of_sections'] = num_sections

                            # Characteristics
                            characteristics = struct.unpack(
                                '<H', data[pe_offset + 20:pe_offset + 22]
                            )[0]
                            features['is_dll'] = \
                                1 if (characteristics & 0x2000) else 0
                            features['is_executable'] = \
                                1 if (characteristics & 0x0002) else 0
            else:
                features['is_pe_file'] = 0

            # Entropy calculation
            chunk = data[:min(len(data), 1024 * 1024)]
            features['overall_entropy'] = self._calculate_entropy(chunk)
            features['is_high_entropy'] = \
                1 if features['overall_entropy'] > 6.5 else 0
            features['is_very_high_entropy'] = \
                1 if features['overall_entropy'] > 7.5 else 0

            # String count
            strings = [
                s for s in data.decode('latin-1', errors='ignore').split()
                if len(s) >= 4 and s.isprintable()
            ]
            features['string_count'] = len(strings)

            # URL count
            urls = re.findall(
                r'https?://[^\s]+',
                data.decode('latin-1', errors='ignore')
            )
            features['url_count'] = len(urls)

            # Suspicious API detection
            suspicious_apis = [
                b'VirtualAlloc', b'CreateRemoteThread', b'WriteProcessMemory',
                b'LoadLibrary', b'GetProcAddress', b'CreateProcess'
            ]

            suspicious_count = 0
            for api in suspicious_apis:
                if api in data:
                    suspicious_count += 1

            features['suspicious_api_count'] = suspicious_count

            # Packer detection
            packers = [b'UPX', b'ASPack', b'Petite', b'Themida',
                       b'VMProtect']
            features['is_packed'] = 1 if any(p in data for p in packers) else 0

        except Exception as e:
            print(f"Error extracting features from {filepath}: {e}")

        # Fill missing features with 0
        for feat in self.PE_FEATURES:
            if feat not in features:
                features[feat] = 0

        return features

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * np.log2(probability)

        return entropy

    def create_dataset_from_directory(
        self,
        malware_dir: str,
        benign_dir: str,
        max_samples: int = 1000
    ) -> pd.DataFrame:
        """Create dataset from directories of malware and benign files"""

        samples = []

        # Load malware samples
        malware_path = Path(malware_dir)
        if malware_path.exists():
            malware_files = list(malware_path.glob("*"))[:max_samples]
            print(f"Processing {len(malware_files)} malware files...")

            for i, filepath in enumerate(malware_files):
                if filepath.is_file():
                    try:
                        features = self.extract_pe_features_from_file(
                            str(filepath)
                        )
                        features['label'] = 1
                        samples.append(features)

                        if (i + 1) % 100 == 0:
                            print(f"  Processed {i + 1} malware samples")
                    except Exception as e:
                        print(f"Error: {e}")

        # Load benign samples
        benign_path = Path(benign_dir)
        if benign_path.exists():
            benign_files = list(benign_path.glob("*"))[:max_samples]
            print(f"Processing {len(benign_files)} benign files...")

            for i, filepath in enumerate(benign_files):
                if filepath.is_file():
                    try:
                        features = self.extract_pe_features_from_file(
                            str(filepath)
                        )
                        features['label'] = 0
                        samples.append(features)

                        if (i + 1) % 100 == 0:
                            print(f"  Processed {i + 1} benign samples")
                    except Exception as e:
                        print(f"Error: {e}")

        # Create DataFrame
        df = pd.DataFrame(samples)

        # Ensure all feature columns exist
        for feat in self.PE_FEATURES:
            if feat not in df.columns:
                df[feat] = 0

        print(f"Created dataset with {len(df)} samples")
        print(f"  Malware: {sum(df['label'] == 1)}")
        print(f"  Benign: {sum(df['label'] == 0)}")

        return df

    def save_dataset(self, df: pd.DataFrame, filename: str) -> None:
        """Save dataset to CSV"""
        output_path = self.data_dir / filename
        df.to_csv(output_path, index=False)
        print(f"Dataset saved to {output_path}")

    def split_dataset(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        stratify: bool = True
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Split dataset into train and test sets"""

        # Convert to numpy array for stratify parameter
        stratify_labels: Optional[np.ndarray] = None
        if stratify and 'label' in df.columns:
            stratify_labels = df['label'].to_numpy()

        if stratify:
            train_df, test_df = train_test_split(
                df,
                test_size=test_size,
                random_state=42,
                stratify=stratify_labels
            )
        else:
            train_df, test_df = train_test_split(
                df,
                test_size=test_size,
                random_state=42
            )

        return train_df, test_df


def download_ember() -> None:
    """Instructions for downloading EMBER dataset"""
    print("""
=== EMBER Dataset Download Instructions ===

EMBER (Empirical Malware Benchmark) is a benchmark dataset for
malware detection.

1. Visit: https://github.com/elastic/ember
2. Download the ember_2018_1.tar.bz2 file
3. Extract to: ./data/ember/
4. The folder should contain:
   - ember_2018_1.csv (features)
   - train_labels.csv (labels)

Alternatively, use the raw features:
   python -m ember.readelf data_dir

For more information, visit:
https://www.kaggle.com/c/malware-classification
""")


def download_virusshare() -> None:
    """Instructions for downloading VirusShare dataset"""
    print("""
=== VirusShare Dataset Download Instructions ===

VirusShare is a repository of malware samples.

1. Request access at: https://virusshare.com/
2. Download the malware samples
3. Organize by hash in ./data/virusshare/
4. Each file should be the malware binary

Note: VirusShare requires registration and is for
research/educational purposes only.
""")


if __name__ == '__main__':
    # Example usage
    loader = MalwareDatasetLoader("./data")

    # Try to load EMBER
    df = loader.load_ember_dataset()

    if df is not None:
        # Split dataset
        train_df, test_df = loader.split_dataset(df)

        # Save splits
        loader.save_dataset(train_df, "train.csv")
        loader.save_dataset(test_df, "test.csv")
    else:
        print("EMBER dataset not available")
        print("Generating sample data instead...")

        # Generate sample data (for testing)
        n_samples = 1000
        data = {
            'file_size': np.random.exponential(500000, n_samples),
            'file_size_kb': np.random.exponential(500, n_samples),
            'overall_entropy': np.random.uniform(3.0, 8.0, n_samples),
            'string_count': np.random.randint(50, 1000, n_samples),
            'suspicious_api_count': np.random.randint(0, 15, n_samples),
            'is_packed': np.random.choice([0, 1], n_samples),
            'is_signed': np.random.choice([0, 1], n_samples),
            'number_of_sections': np.random.randint(1, 10, n_samples),
            'label': np.random.choice([0, 1], n_samples)
        }

        df = pd.DataFrame(data)
        loader.save_dataset(df, "sample_data.csv")
        print("Sample data saved!")

