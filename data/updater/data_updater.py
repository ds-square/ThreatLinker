# data/updater/data_updater.py

from data.updater.cwe_update import download_cwe_data, import_cwe_data, create_cwe_relationships
from data.updater.capec_update import download_capec_data, import_capec_data
from data.updater.cve_update import download_cve_data, import_cve_data, create_cve_relationships

def download_all():
    """
    Scarica i dati per tutte le entità richieste (CWE, CAPEC e CVE).
    Gestisce errori specifici per ciascuna entità e restituisce uno stato finale.
    
    Returns:
        dict: Un dizionario contenente lo stato di ciascun download e eventuali messaggi di errore.
    """
    status = {
        "cwe": {"success": False, "file_path": None, "error": None},
        "capec": {"success": False, "file_path": None, "error": None},
        "cve": {"success": False, "file_paths": [], "error": None},  # CVE può avere più file
    }
    
    # Download di CWE
    try:
        cwe_file_path = download_cwe_data()
        status["cwe"]["success"] = True
        status["cwe"]["file_path"] = cwe_file_path
    except Exception as e:
        status["cwe"]["error"] = str(e)
    
    # Download di CAPEC
    try:
        capec_file_path = download_capec_data()
        status["capec"]["success"] = True
        status["capec"]["file_path"] = capec_file_path
    except Exception as e:
        status["capec"]["error"] = str(e)
    
    # Download di CVE
    try:
        cve_file_paths = download_cve_data()  # Restituisce una lista di percorsi file
        status["cve"]["success"] = True
        status["cve"]["file_paths"] = cve_file_paths
    except Exception as e:
        status["cve"]["error"] = str(e)
    
    # Determina lo stato complessivo
    all_success = all(entity["success"] for entity in status.values())
    status["overall_success"] = all_success

    return status

def import_all():
    """
    Importa i dati per tutte le entità richieste (CWE, CAPEC e CVE).
    Gestisce errori specifici per ciascuna entità e restituisce uno stato finale.
    
    Returns:
        dict: Un dizionario contenente lo stato di ciascun import e eventuali messaggi di errore.
    """
    status = {
        "cwe": {"success": False, "error": None},
        "capec": {"success": False, "error": None},
        "cve": {"success": False, "error": None},
    }
    
    # Import di CWE
    try:
        import_cwe_data()
        status["cwe"]["success"] = True
    except Exception as e:
        status["cwe"]["error"] = str(e)

    # Import di CAPEC
    try:
        import_capec_data()
        status["capec"]["success"] = True
    except Exception as e:
        status["capec"]["error"] = str(e)

    # Import di CVE
    try:
        import_cve_data()
        status["cve"]["success"] = True
    except Exception as e:
        status["cve"]["error"] = str(e)

    # Determina lo stato complessivo
    all_success = all(entity["success"] for entity in status.values())
    status["overall_success"] = all_success

    return status

def create_all_relationships():
    """
    Crea le relazioni tra le entità (CWE, CAPEC, CVE).
    Gestisce errori specifici per ciascuna entità e restituisce uno stato finale.
    
    Returns:
        dict: Un dizionario contenente lo stato di ciascuna relazione e eventuali messaggi di errore.
    """
    status = {
        "cwe_capec": {"success": False, "error": None},
        "cve_cwe": {"success": False, "error": None}
    }
    
    # Creazione delle relazioni tra CWE e CAPEC
    try:
        create_cwe_relationships()
        status["cwe_capec"]["success"] = True
    except Exception as e:
        status["cwe_capec"]["error"] = str(e)

    # Creazione delle relazioni tra CVE e CWE
    try:
        create_cve_relationships()
        status["cve_cwe"]["success"] = True
    except Exception as e:
        status["cve_cwe"]["error"] = str(e)

    # Determina lo stato complessivo
    all_success = all(entity["success"] for entity in status.values())
    status["overall_success"] = all_success

    return status
