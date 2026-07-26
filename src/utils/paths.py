# src/utils/paths.py
import yaml
from pathlib import Path

# Get the project root (assumes this file is in src/utils/)
PROJECT_ROOT = Path(__file__).resolve().parents[2]

def get_project_root() -> Path:
    return PROJECT_ROOT

def load_config(config_name: str) -> dict:
    """Loads a YAML configuration file from the configs directory."""
    config_path = PROJECT_ROOT / "configs" / f"{config_name}.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def get_path(category: str, key: str) -> Path:
    """Resolves a path from paths.yaml relative to the project root."""
    paths_config = load_config("paths")
    if category not in paths_config or key not in paths_config[category]:
        raise KeyError(f"Path configuration for '{category}.{key}' not found.")
    
    resolved_path = PROJECT_ROOT / paths_config[category][key]
    # Ensure directories exist
    if not resolved_path.suffix:  # It's a directory
        resolved_path.mkdir(parents=True, exist_ok=True)
    elif not resolved_path.parent.exists():
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        
    return resolved_path