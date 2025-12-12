import requests
from datetime import datetime
import os
import json

from data.models import CVE, CVEReference, CWE
from data.updater.update_utils import get_entity_download_dir, extract_zip_file, get_download_url, debug_print, update_progress_file

def download_cve_data():
    """
    Scarica i file ZIP delle CVE per ogni anno dal 2002 ad oggi e li salva
    nella directory specifica per l'entità CVE.

    Returns:
        list: Una lista di percorsi ai file ZIP scaricati.
    """
    current_year = datetime.now().year
    download_dir = get_entity_download_dir("cve")
    downloaded_files = []

    # Ottieni l'URL di base per le CVE
    base_url = get_download_url("cve")
    if not base_url:
        debug_print("ERROR", "Download URL for CVE not found in configuration file.")
        raise ValueError("Download URL for CVE not found in configuration file.")

    total_years = current_year - 2002 + 1  # Numero totale di anni da scaricare
    for i, year in enumerate(range(2002, current_year + 1), start=1):
        # Formatta l'URL per l'anno specifico
        url = base_url.format(year=year)
        filename = f"nvdcve-1.1-{year}.json.zip"
        file_path = os.path.join(download_dir, filename)

        debug_print("DEBUG", f"Downloading {url}...")

        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(file_path, "wb") as file:
                file.write(response.content)
            downloaded_files.append(file_path)
            debug_print("INFO", f"Downloaded {filename} to {file_path}")

            # Estrai il file ZIP
            extract_zip_file(file_path, download_dir)
            debug_print("INFO", f"Extracted {filename} to {download_dir}")

            # Calcola e aggiorna il progresso
            progress_percentage = int((i / total_years) * 100)
            update_progress_file("download", "CVE", progress_percentage)

        except requests.exceptions.RequestException as e:
            debug_print("ERROR", f"Failed to download {filename}. Error: {e}")
        except Exception as e:
            debug_print("ERROR", f"Failed to extract {filename}. Error: {e}")

    return downloaded_files

def import_cve_data():
    folder_path = get_entity_download_dir("cve")
    json_files = sorted(
        [f for f in os.listdir(folder_path) if f.endswith(".json")],
        key=lambda x: int(x.split('-')[-1].split('.')[0])
    )

    most_recent_timestamp = None
    total_cve_count = 0
    processed_cve_count = 0

    # Calcola il numero totale di CVE in tutti i file
    for file_name in json_files:
        file_path = os.path.join(folder_path, file_name)
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            total_cve_count += len(data.get("CVE_Items", []))

    # Processo di importazione
    for file_name in json_files:
        file_path = os.path.join(folder_path, file_name)
        debug_print("INFO", f"Processing file: {file_name}")

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)

                # Estrazione del timestamp dal file
                file_timestamp = data.get("CVE_data_timestamp")
                if file_timestamp:
                    file_timestamp_date = datetime.fromisoformat(file_timestamp.replace("Z", "+00:00"))
                    if not most_recent_timestamp or file_timestamp_date > most_recent_timestamp:
                        most_recent_timestamp = file_timestamp_date

                # Estrazione dei metadati del file
                data_type = data.get("CVE_data_type")
                data_format = data.get("CVE_data_format")
                data_version = data.get("CVE_data_version")

                for item in data.get("CVE_Items", []):
                    processed_cve_count += 1  # Incrementa il conteggio dei CVE processati

                    # Calcola la percentuale di avanzamento e aggiorna il file di stato
                    progress_percentage = int((processed_cve_count / total_cve_count) * 100)
                    update_progress_file("import", "CVE", progress_percentage)

                    # Estrazione dei dati principali della CVE
                    cve_meta = item["cve"]["CVE_data_meta"]
                    cve_id = cve_meta["ID"]
                    assigner = cve_meta.get("ASSIGNER", None)

                    # Dettagli descrizione
                    description_data = item["cve"]["description"]["description_data"]
                    description = next((d["value"] for d in description_data if d["lang"] == "en"), None)

                    # Date di pubblicazione e ultima modifica
                    published_date = item.get("publishedDate")
                    last_modified_date = item.get("lastModifiedDate")
                    published_date = datetime.fromisoformat(published_date) if published_date else None
                    last_modified_date = datetime.fromisoformat(last_modified_date) if last_modified_date else None

                    # Dati CVSS V2 e V3
                    impact_v2 = item.get("impact", {}).get("baseMetricV2", None)
                    impact_v3 = item.get("impact", {}).get("baseMetricV3", None)

                    # Configurazioni CPE
                    vulnerable_cpe_uris = []
                    related_cpe_uris = []
                    for node in item.get("configurations", {}).get("nodes", []):
                        for cpe in node.get("cpe_match", []):
                            if cpe.get("vulnerable"):
                                vulnerable_cpe_uris.append(cpe["cpe23Uri"])
                            else:
                                related_cpe_uris.append(cpe["cpe23Uri"])

                    # Prepara i dati per l'inserimento
                    cve_data = {
                        "data_type": data_type,
                        "data_format": data_format,
                        "data_version": data_version,
                        "assigner": assigner,
                        "description": description,
                        "published_date": published_date,
                        "last_modified_date": last_modified_date,
                        "impact_v2": impact_v2,
                        "impact_v3": impact_v3,
                        "vulnerable_cpe_uris": vulnerable_cpe_uris,
                        "related_cpe_uris": related_cpe_uris,
                    }

                    # Inserisce o aggiorna i dati della CVE
                    cve_instance, created = CVE.objects.update_or_create(id=cve_id, defaults=cve_data)

                    # Creazione o aggiornamento dei riferimenti
                    references_data = item["cve"]["references"]["reference_data"]
                    for ref in references_data:
                        CVEReference.objects.update_or_create(
                            cve=cve_instance,
                            url=ref["url"],
                            defaults={
                                "name": ref.get("name"),
                                "refsource": ref.get("refsource"),
                                "tags": ref.get("tags", [])
                            }
                        )

            debug_print("INFO", f"Importazione delle CVE dal file {file_name} completata con successo.")

        except Exception as e:
            debug_print("ERROR", f"Errore durante l'importazione delle CVE dal file {file_name}: {e}")
    
    if most_recent_timestamp:
        debug_print("INFO", f"Most recent timestamp: {most_recent_timestamp.strftime('%Y-%m-%d')}")
    return most_recent_timestamp.strftime('%Y-%m-%d') if most_recent_timestamp else None


def create_cve_relationships():
    folder_path = get_entity_download_dir("cve")
    json_files = sorted([f for f in os.listdir(folder_path) if f.endswith(".json")],
                        key=lambda x: int(x.split('-')[-1].split('.')[0]))

    for file_name in json_files:
        file_path = os.path.join(folder_path, file_name)
        debug_print("INFO", f"Processing file: {file_name}")

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
                for item in data.get("CVE_Items", []):
                    # Identificatore CVE
                    cve_meta = item["cve"]["CVE_data_meta"]
                    cve_id = cve_meta["ID"]

                    # Ottieni o ignora la CVE se non esiste
                    try:
                        cve_instance = CVE.objects.get(id=cve_id)
                    except CVE.DoesNotExist:
                        debug_print("WARNING", f"{cve_id} non trovato nel database; saltato.")
                        continue

                    # Estrai e collega CWE
                    problemtype_data = item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
                    for entry in problemtype_data:
                        for desc in entry.get("description", []):
                            if desc["lang"] == "en":
                                cwe_value = desc["value"]
                                # Ignora valori non validi
                                if cwe_value in ["NVD-CWE-Other", "NVD-CWE-noinfo"]:
                                    continue
                                
                                try:
                                    # Collega la CWE se esiste
                                    cwe_instance = CWE.objects.get(id=cwe_value)
                                    cve_instance.related_cwes.add(cwe_instance)
                                    debug_print("INFO", f"Relazione creata: {cve_id} -> {cwe_value}")
                                except CWE.DoesNotExist:
                                    debug_print("WARNING", f"{cwe_value} non trovato nel database; relazione non creata.")
        except Exception as e:
            debug_print("ERROR", f"Errore durante l'elaborazione delle relazioni CVE dal file {file_name}: {e}")

    update_progress_file("relation", "CVE", 100)
    debug_print("INFO", "Creazione delle relazioni CVE-CWE completata.")