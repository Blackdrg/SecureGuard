"""
Example ONNX Export Function
Demonstrates how to export trained models to ONNX format
"""

import os
import sys
from typing import Any, Optional, Tuple

import numpy as np

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try importing ONNX dependencies
try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    HAS_SKL2ONX = True
except ImportError:
    HAS_SKL2ONX = False
    print("Warning: skl2onnx not installed. ONNX export will be skipped.")

try:
    import onnx
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    print("Warning: onnx not installed. ONNX export will be skipped.")


def export_model_to_onnx(
    model: Any,
    feature_names: list,
    output_path: str,
    input_shape: Optional[Tuple[int, ...]] = None
) -> bool:
    """
    Export a trained scikit-learn model to ONNX format.

    Args:
        model: Trained scikit-learn model
        feature_names: List of feature names
        output_path: Path to save the ONNX model
        input_shape: Input shape (defaults to [None, len(feature_names)])

    Returns:
        True if export succeeded, False otherwise
    """
    if not HAS_SKL2ONX:
        print("Error: skl2onnx is required for ONNX export")
        print("Install with: pip install skl2onnx")
        return False

    if not HAS_ONNX:
        print("Error: onnx is required for ONNX export")
        print("Install with: pip install onnx")
        return False

    try:
        # Set input shape
        if input_shape is None:
            n_features = len(feature_names)
            initial_type = [('input', FloatTensorType([None, n_features]))]
        else:
            initial_type = [('input', FloatTensorType(list(input_shape)))]

        # Convert model to ONNX
        onnx_model = convert_sklearn(
            model,
            initial_types=initial_type,
            target_opset=12
        )

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Save ONNX model
        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())

        print(f"Model exported successfully to: {output_path}")

        # Print model info
        print("\nONNX Model Information:")
        print(f"  - Input name: input")
        n_feat = len(feature_names)
        print(f"  - Input shape: {input_shape or f'(batch_size, {n_feat})'}")
        print("  - Output name: output")
        print(f"  - Feature names: {feature_names[:5]}...")

        return True

    except Exception as e:
        print(f"Error exporting model to ONNX: {e}")
        return False


def verify_onnx_model(onnx_path: str) -> bool:
    """
    Verify an ONNX model can be loaded and inferred.

    Args:
        onnx_path: Path to the ONNX model file

    Returns:
        True if model is valid, False otherwise
    """
    if not HAS_ONNX:
        print("Error: onnx is required for model verification")
        return False

    try:
        onnx_model = onnx.load(onnx_path)
        onnx.checker.check_model(onnx_model)
        print("ONNX model verified successfully!")
        return True
    except Exception as e:
        print(f"Error verifying ONNX model: {e}")
        return False


def create_onnx_runtime_inference(
    onnx_path: str,
    input_data: np.ndarray
) -> Optional[np.ndarray]:
    """
    Run inference using ONNX Runtime.

    Args:
        onnx_path: Path to the ONNX model file
        input_data: Input data as numpy array

    Returns:
        Prediction results as numpy array, or None if failed
    """
    try:
        import onnxruntime as ort

        # Create inference session
        session = ort.InferenceSession(onnx_path)

        # Get input and output names
        input_name = session.get_inputs()[0].name
        output_name = session.get_outputs()[0].name

        # Run inference
        result = session.run(
            [output_name],
            {input_name: input_data.astype(np.float32)}
        )

        return result[0]

    except ImportError:
        print("Error: onnxruntime is required for inference")
        print("Install with: pip install onnxruntime")
        return None
    except Exception as e:
        print(f"Error running inference: {e}")
        return None


def main() -> None:
    """Demonstrate ONNX export with a simple model"""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.datasets import make_classification
    from sklearn.preprocessing import StandardScaler

    print("=" * 60)
    print("ONNX Export Example")
    print("=" * 60)

    if not HAS_SKL2ONX or not HAS_ONNX:
        print("\nPlease install ONNX dependencies:")
        print("  pip install skl2onnx onnx onnxruntime")
        return

    # Create simple model
    print("\n1. Creating sample model...")
    X, y = make_classification(
        n_samples=1000,
        n_features=10,
        random_state=42
    )

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_scaled, y)

    feature_names = [f"feature_{i}" for i in range(10)]

    # Export to ONNX
    print("\n2. Exporting model to ONNX...")
    output_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'models',
        'example_model.onnx'
    )

    success = export_model_to_onnx(
        model,
        feature_names,
        output_path,
        input_shape=(None, 10)
    )

    if success:
        # Verify model
        print("\n3. Verifying ONNX model...")
        verify_onnx_model(output_path)

        # Test inference
        print("\n4. Testing inference with ONNX Runtime...")
        test_input = X_scaled[:5]
        result = create_onnx_runtime_inference(output_path, test_input)

        if result is not None:
            print(f"   Inference result shape: {result.shape}")
            print(f"   Sample predictions: {result[:5]}")

    print("\n" + "=" * 60)
    print("ONNX export complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
