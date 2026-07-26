import subprocess
import sys
from pathlib import Path

def run_script(script_name: str):
    """Executes a python script as a subprocess and monitors its exit code."""
    script_path = Path(__file__).parent / script_name
    print(f"\n{'='*60}\nExecuting {script_name}...\n{'='*60}")
    
    try:
        # sys.executable ensures we use the exact same python environment
        subprocess.run([sys.executable, str(script_path)], check=True)
        print(f"✅ {script_name} completed successfully.")
    except subprocess.CalledProcessError:
        print(f"❌ Error executing {script_name}. Halting pipeline.")
        sys.exit(1)

def main():
    # Order is critical: train_traditional sets up the scaler and feature selection
    scripts = [
        "train_traditional.py",
        "train_deep_learning.py",
        "train_automl.py"
    ]
    
    for script in scripts:
        run_script(script)
        
    print("\n🎉 All training pipelines completed successfully!")
    print("Check 'results/metrics/experiment_log.csv' for the comprehensive model comparison.")

if __name__ == "__main__":
    main()