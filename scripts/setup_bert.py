# scripts/setup_bert.py — Automatic BERT setup for policy-gate
#
# This script checks the firewall.toml configuration and downloads the
# necessary BERT model and tokenizer files if BERT mode is enabled.

import os
import sys
import shutil
from pathlib import Path

try:
    # Use tomllib if available (Python 3.11+) or fallback to simple parsing
    import tomllib
except ImportError:
    tomllib = None

try:
    from huggingface_hub import hf_hub_download
except ImportError:
    print("Error: 'huggingface_hub' not found. Please run: pip install huggingface_hub")
    sys.exit(1)

# Configuration
DEFAULT_MODEL_REPO = "sentence-transformers/all-MiniLM-L6-v2"
MODELS_DIR = Path("models")

def parse_toml_config(file_path):
    """Simple TOML parser if tomllib is not available."""
    if not os.path.exists(file_path):
        return {}
    
    if tomllib:
        with open(file_path, "rb") as f:
            return tomllib.load(f)
    
    # Very basic fallback parser for simple TOML files
    config = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip().strip('"').strip("'")
    return config

def main():
    print("--- policy-gate BERT Setup ---")
    
    # 1. Determine which config to use
    config_file = "firewall.toml" if os.path.exists("firewall.toml") else "firewall.example.toml"
    print(f"Reading configuration from: {config_file}")
    
    config = parse_toml_config(config_file)
    
    # 2. Check if BERT mode is enabled
    engine_mode = config.get("semantic_engine_mode")
    if engine_mode != "bert":
        print(f"Note: semantic_engine_mode is set to '{engine_mode}'.")
        print("To enable BERT mode, set 'semantic_engine_mode = \"bert\"' in your firewall.toml.")
        # We can still download it if requested via CLI, but let's be safe
        response = input("Do you want to download the BERT model anyway? [y/N]: ").lower()
        if response != 'y':
            print("Setup skipped.")
            return

    # 3. Determine paths
    model_path = config.get("semantic_model_path", "models/all-MiniLM-L6-v2.safetensors")
    tokenizer_path = config.get("tokenizer_path", "models/tokenizer.json")
    
    # 4. Create models directory
    if not MODELS_DIR.exists():
        print(f"Creating {MODELS_DIR} directory...")
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 5. Download model (ONNX for ORT)
    model_filename = os.path.basename(model_path)
    # If the user specified .safetensors but we want to use ORT, we might need .onnx
    if model_filename.endswith(".safetensors"):
        print("Note: ORT engine prefers .onnx files. Downloading ONNX version instead.")
        model_filename = model_filename.replace(".safetensors", ".onnx")
    
    print(f"Downloading model '{model_filename}' from {DEFAULT_MODEL_REPO}...")
    try:
        # MiniLM ONNX is usually in the 'onnx' subfolder or named differently
        downloaded_model = hf_hub_download(
            repo_id=DEFAULT_MODEL_REPO,
            filename="onnx/model.onnx" # Common path for sentence-transformers ONNX
        )
        shutil.copy(downloaded_model, MODELS_DIR / model_filename)
        print(f"Model saved to: {MODELS_DIR / model_filename}")
    except Exception as e:
        print(f"Error downloading model: {e}")
        print("Attempting fallback to root model.onnx...")
        try:
            downloaded_model = hf_hub_download(
                repo_id=DEFAULT_MODEL_REPO,
                filename="model.onnx"
            )
            shutil.copy(downloaded_model, MODELS_DIR / model_filename)
            print(f"Model saved to: {MODELS_DIR / model_filename}")
        except Exception as e2:
            print(f"Fallback failed: {e2}")

    # 6. Download tokenizer
    tokenizer_filename = os.path.basename(tokenizer_path)
    print(f"Downloading tokenizer '{tokenizer_filename}' from {DEFAULT_MODEL_REPO}...")
    try:
        downloaded_tokenizer = hf_hub_download(
            repo_id=DEFAULT_MODEL_REPO,
            filename="tokenizer.json"
        )
        shutil.copy(downloaded_tokenizer, MODELS_DIR / tokenizer_filename)
        print(f"Tokenizer saved to: {MODELS_DIR / tokenizer_filename}")
    except Exception as e:
        print(f"Error downloading tokenizer: {e}")

    print("\n--- Setup Complete ---")
    print("You can now use Channel D with engine_mode = \"bert\".")

if __name__ == "__main__":
    main()
