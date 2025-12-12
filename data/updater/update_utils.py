# data/updater/update_utils.py

import json
import os
import zipfile
import requests
import shutil
from urllib.parse import urlparse
from django.http import JsonResponse
from data.models import DataUpdate
from debug.debug_utils import debug_print  # Importa debug_print per tracciare le operazioni

# Imposta BASE_DOWNLOAD_DIR per puntare a `data/downloads` nella radice del progetto
BASE_DOWNLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../downloads"))

# Path al file JSON con le URL di download
URLS_FILE_PATH = os.path.join(os.path.dirname(__file__), "update_urls.json")

# Progress Path File
PROGRESS_FILE_PATH = os.path.join(os.path.dirname(__file__), "generated_update_progress.json")

def get_download_url(entity_name):
    """
    Restituisce la URL di download per l'entità specificata leggendo dal file JSON.
    Se l'URL non è presente, restituisce None.
    """
    debug_print("DEBUG", f"Inizio recupero URL per l'entità {entity_name}")
    try:
        with open(URLS_FILE_PATH, "r") as f:
            urls = json.load(f)
        url = urls.get(entity_name)
        debug_print("DEBUG", f"URL trovato per {entity_name}: {url}")
        return url
    except FileNotFoundError:
        debug_print("ERROR", f"Il file {URLS_FILE_PATH} non esiste.")
        raise FileNotFoundError(f"Il file {URLS_FILE_PATH} non esiste.")
    except json.JSONDecodeError:
        debug_print("ERROR", f"Errore di lettura del file JSON {URLS_FILE_PATH}.")
        raise ValueError(f"Errore di lettura del file JSON {URLS_FILE_PATH}.")

def get_entity_download_dir(entity_name):
    """
    Restituisce il percorso della cartella di download per un'entità specifica.
    Crea la cartella se non esiste.
    """
    download_dir = os.path.join(BASE_DOWNLOAD_DIR, entity_name)
    os.makedirs(download_dir, exist_ok=True)
    debug_print("DEBUG", f"Cartella di download per {entity_name} verificata/creata: {download_dir}")
    return download_dir

def download_file(entity_name):
    """
    Scarica il file per l'entità specificata utilizzando l'URL dal file JSON
    e salva il contenuto nella cartella downloads/entity/.
    """
    debug_print("DEBUG", f"Inizio download per l'entità {entity_name}")
    
    # Ottieni l'URL dal file JSON
    url = get_download_url(entity_name)
    if not url:
        debug_print("ERROR", f"URL per {entity_name} non trovato in download_urls.json")
        raise ValueError(f"URL for {entity_name} data not found in download_urls.json")

    # Scarica il file
    response = requests.get(url)
    if response.status_code == 200:
        # Ottieni il nome del file dall'URL
        filename = os.path.basename(urlparse(url).path)
        
        # Salva il file nella cartella appropriata
        download_dir = get_entity_download_dir(entity_name)
        file_path = os.path.join(download_dir, filename)
        
        with open(file_path, "wb") as f:
            f.write(response.content)
        debug_print("DEBUG", f"File scaricato e salvato in: {file_path}")

        return file_path
    else:
        debug_print("ERROR", f"Errore nel download per {entity_name}. Status code: {response.status_code}")
        raise Exception(f"Failed to download {entity_name} data. Status code: {response.status_code}")

def extract_zip_file(zip_path, entity_name):
    """
    Estrae un file ZIP nella directory di destinazione per l'entità specificata
    e rimuove il file ZIP una volta completata l'estrazione.
    
    Parameters:
        zip_path (str): Il percorso del file ZIP da estrarre.
        entity_name (str): Il nome dell'entità (es. "cwe", "cve") per determinare la cartella di destinazione.
    
    Returns:
        str: La directory in cui i file sono stati estratti.
    """
    # Ottieni la directory di destinazione basata sull'entità
    extract_to = get_entity_download_dir(entity_name)
    
    # Estrai i contenuti del file ZIP
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    
    print(f"File estratto in: {extract_to}")
    
    # Rimuove il file ZIP dopo l'estrazione
    os.remove(zip_path)
    print(f"File ZIP eliminato: {zip_path}")
    
    return extract_to


### Funzione per progresso UPDATE

def initialize_progress_file():
    # Stato iniziale per tutte le entità e fasi, incluso un campo per errori
    initial_progress = {
        "download": {"CWE": 0, "CAPEC": 0, "CVE": 0, "overall": 0},
        "import": {"CWE": 0, "CAPEC": 0, "CVE": 0, "overall": 0},
        "relation": {"CWE": 0, "CAPEC": 0, "CVE": 0, "overall": 0},
        "error": {"message": ""},
        "is_updating": True
    }
    # Salva nel file JSON
    with open(PROGRESS_FILE_PATH, 'w') as f:
        json.dump(initial_progress, f)

def update_progress_file(phase, entity, percentage):
    # Aggiorna lo stato di una specifica fase e entità
    with open(PROGRESS_FILE_PATH, 'r+') as f:
        progress = json.load(f)
        
        # Controlla se la fase esiste, altrimenti aggiungila
        if phase not in progress:
            progress[phase] = {}
        
        # Se l'entità è 'message' (errore), gestiscila separatamente
        if phase == "error":
            progress[phase]["message"] = percentage
        else:
            # Aggiorna la specifica entità e la percentuale complessiva
            progress[phase][entity] = percentage
            progress[phase]["overall"] = (progress[phase]["CWE"] + progress[phase]["CAPEC"] + progress[phase]["CVE"]) // 3
        
        # Riscrivi il file
        f.seek(0)
        json.dump(progress, f)
        f.truncate()

def get_progress_status_dict():
    try:
        with open(PROGRESS_FILE_PATH, 'r') as f:
            progress = json.load(f)
        return progress  # Restituisce il dizionario direttamente
    except FileNotFoundError:
        return {"error": "Progress file not found"}
    except json.JSONDecodeError:
        return {"error": "Failed to decode JSON"}

def get_progress_status(request):
    try:
        with open(PROGRESS_FILE_PATH, 'r') as f:
            progress = json.load(f)
        return JsonResponse(progress)
    except FileNotFoundError:
        return JsonResponse({"error": "Progress file not found"}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Failed to decode JSON"}, status=500)

def clear_downloads_directory():
    """
    Rimuove tutti i file e le cartelle nella directory di downloads.
    """
    try:
        if os.path.exists(BASE_DOWNLOAD_DIR):
            # Cancella tutto il contenuto della cartella downloads
            shutil.rmtree(BASE_DOWNLOAD_DIR)
            # Ricrea la cartella downloads vuota
            os.makedirs(BASE_DOWNLOAD_DIR)
            print("Directory downloads pulita con successo.")
        else:
            print("La directory downloads non esiste.")
    except Exception as e:
        print(f"Errore durante la pulizia della directory downloads: {e}")

def finalize_progress_file():
    """
    Finalizza il file di progresso dell'aggiornamento, impostando is_updating su False.
    Elimina il file di progresso una volta completato.
    """
    if os.path.exists(PROGRESS_FILE_PATH):
        with open(PROGRESS_FILE_PATH, 'r+') as f:
            progress = json.load(f)
            progress["is_updating"] = False
            f.seek(0)
            json.dump(progress, f)
            f.truncate()
    else:
        print(f"File di progresso '{PROGRESS_FILE_PATH}' non trovato.")

def remove_progress_file():
    if os.path.exists(PROGRESS_FILE_PATH):
        os.remove(PROGRESS_FILE_PATH)
        print(f"File di progresso '{PROGRESS_FILE_PATH}' eliminato con successo.")
    else:
        print(f"File di progresso '{PROGRESS_FILE_PATH}' non trovato.")


