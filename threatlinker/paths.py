from pathlib import Path

# Percorso della radice del progetto
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Percorso della directory 'reports'
REPORTS = PROJECT_ROOT / "reports"

def get_project_root():
    """
    Restituisce il percorso assoluto della radice del progetto.
    """
    return PROJECT_ROOT