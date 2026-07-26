import matplotlib.pyplot as plt
from pathlib import Path
import sys

sys.path.append(str(Path.cwd().parent) if Path.cwd().name == 'scripts' else str(Path.cwd()))
from src.utils.paths import get_path

def generate_pipeline_diagram():
    """Generates a high-level block diagram of the ML pipeline."""
    fig, ax = plt.subplots(figsize=(10, 4))
    
    boxes = [
        "Raw Data", "Split\n(70/15/15)", "Drop\nTargets", 
        "Isolation\nForest (Train)", "Feature\nSelection", 
        "Scaler", "SMOTE\n(Train)", "Model\nTraining"
    ]
    
    for i, box in enumerate(boxes):
        ax.text(i, 0.5, box, ha='center', va='center', 
                bbox=dict(facecolor='lightblue', edgecolor='black', boxstyle='round,pad=0.5'))
        if i < len(boxes) - 1:
            ax.arrow(i + 0.4, 0.5, 0.2, 0, head_width=0.05, head_length=0.1, fc='black', ec='black')
            
    ax.set_xlim(-0.5, len(boxes) - 0.5)
    ax.set_ylim(0, 1)
    ax.axis('off')
    plt.title("v2 Rebuild: Leakage-Free Pipeline Architecture")
    
    save_dir = get_path("data", "raw").parent.parent / "assets" / "architecture"
    save_dir.mkdir(parents=True, exist_ok=True)
    
    plt.tight_layout()
    plt.savefig(save_dir / "pipeline_workflow.png")
    plt.close()
    print(f"Pipeline diagram saved to {save_dir}/pipeline_workflow.png")

if __name__ == "__main__":
    generate_pipeline_diagram()