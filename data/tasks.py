# data/tasks.py
from celery import shared_task
from data.updater.cve_update import download_cve_data, import_cve_data, create_cve_relationships
from data.updater.cwe_update import download_cwe_data, import_cwe_data, create_cwe_relationships
from data.updater.capec_update import download_capec_data, import_capec_data, create_preprocessed_capecs
from django.utils import timezone
from datetime import datetime
from data.updater.update_utils import initialize_progress_file, finalize_progress_file, update_progress_file, clear_downloads_directory, remove_progress_file
from data.models import DataUpdate, CVE, CWE, CAPEC, PreprocessedCAPEC

@shared_task
def start_update_process():
    """
    Task per eseguire l'aggiornamento completo del database: download, import e creazione delle relazioni.
    """
    try:
        set_all_updates_in_progress()

        # Inizializza il file di progresso all'inizio
        initialize_progress_file()

        # Step 1: Download per tutte le entità
        download_cwe_data()
        download_capec_data()
        download_cve_data()

        # Step 2: Import per tutte le entità
        cwe_version, cwe_date = import_cwe_data()
        capec_version, capec_date = import_capec_data()
        cve_most_recent = import_cve_data()

        # Step 3: Creazione delle relazioni per CWE e CVE
        create_cwe_relationships()
        create_cve_relationships()
        create_preprocessed_capecs()

        # Aggiorna le istanze di DataUpdate
        update_data_update_record("CWE", cwe_version, cwe_date)
        update_data_update_record("CAPEC", capec_version, capec_date)
        update_data_update_record("CVE", version=None, last_update=cve_most_recent)

        # Concludi l'aggiornamento
        finalize_progress_file()

        # Setta gli stati
        set_update_status("CWE", "Complete")
        set_update_status("CAPEC", "Complete")
        set_update_status("CVE", "Complete")

        # Elimina i files dalla cartella downloads
        clear_downloads_directory()

        # Rimuove file di progresso
        remove_progress_file()

    except Exception as e:
        # Gestisci l'errore (ad esempio, log dell'errore)
        print(f"Errore durante l'aggiornamento: {e}")
        update_progress_file("error", "message", f"Error occurred: {str(e)}")
    finally:
        # Se la task è stata interrotta o completata, reimposta a "Pending"
        reset_all_updates_to_pending()
        
@shared_task
def reinitialize_entry_task(entity):
    """
    Task per reinizializzare un'entità specificata (CAPEC, CWE, CVE):
    1. Rimuove le versioni preprocessate e i dati esistenti.
    2. Esegue il download, l'importazione e la creazione delle relazioni.
    """

    # Inizializza il file di progresso all'inizio
    initialize_progress_file()

    if entity == "CAPEC":
        # Rimuove le versioni preprocessate esistenti per CAPEC
        PreprocessedCAPEC.objects.all().delete()
        CAPEC.objects.all().delete()

        
        # Esegui il download e l'importazione dei dati CAPEC
        download_capec_data()
        capec_version, capec_date = import_capec_data()
        create_preprocessed_capecs()

        # Aggiorna il record di DataUpdate
        update_data_update_record("CAPEC", capec_version, capec_date)

    elif entity == "CWE":
        CWE.objects.all().delete()

        # Esegui il download e l'importazione dei dati CWE
        download_cwe_data()
        cwe_version, cwe_date = import_cwe_data()

        # Aggiorna il record di DataUpdate
        update_data_update_record("CWE", cwe_version, cwe_date)

    elif entity == "CVE":
        CVE.objects.all().delete()

        # Esegui il download e l'importazione dei dati CVE
        download_cve_data()
        cve_most_recent = import_cve_data()

        # Aggiorna il record di DataUpdate
        update_data_update_record("CVE", version=None, last_update=cve_most_recent)

    else:
        raise ValueError(f"Unknown entity type: {entity}")

    # Concludi l'aggiornamento
    finalize_progress_file()

    # Elimina i files dalla cartella downloads
    clear_downloads_directory()

    # Rimuove file di progresso
    remove_progress_file()

def update_data_update_record(entity, version=None, last_update=None):
    """
    Funzione per aggiornare il record di DataUpdate per un'entità specificata.
    """
    data_update, created = DataUpdate.objects.get_or_create(name=entity)
    if version:
        data_update.version = version
    if last_update:
        data_update.last_update = last_update
    data_update.save()

def update_data_update_record(entity_name, version, last_update):
    """
    Aggiorna il record DataUpdate per l'entità specificata.
    """
    entity_update, created = DataUpdate.objects.get_or_create(name=entity_name)
    
    if not created:
        print(f"Updating existing record for {entity_name}")
    else:
        print(f"Created new record for {entity_name}")
    
    entity_update.has_been_updated = True  # Imposta su True

    # Se last_update è una stringa, convertila in datetime
    if isinstance(last_update, str):
        last_update = datetime.fromisoformat(last_update)  # Assumiamo che la stringa sia nel formato ISO 8601

    # Converte last_update in un datetime "aware" se necessario
    if last_update is not None and timezone.is_naive(last_update):
        last_update = timezone.make_aware(last_update)
    
    entity_update.last_update = last_update
    
    if version is not None:
        entity_update.version = version
    entity_update.schedule_next_update()
    entity_update.save(update_fields=['has_been_updated', 'last_update', 'version', 'next_scheduled_update'])

    # Verifica immediata dell'aggiornamento
    if entity_update.has_been_updated is not True:
        print(f"Errore: `has_been_updated` non aggiornato correttamente per {entity_name}")

### Update Objects

def reset_all_updates_to_pending():
    """
    Reimposta lo stato di tutti i DataUpdate a 'Pending'.
    """
    DataUpdate.objects.update(status="Pending")
    
def set_all_updates_in_progress():
    # Recupera tutti i record di DataUpdate e aggiorna lo stato a "In Progress"
    DataUpdate.objects.update(status="In Progress")

def set_update_status(update_name, status):
    """
    Imposta lo stato di un DataUpdate specifico in base al nome fornito.

    :param update_name: Nome dell'oggetto DataUpdate da aggiornare
    :param status: Nuovo stato da assegnare (ad esempio: 'Pending', 'In Progress', 'Complete', 'Failed')
    :return: True se l'aggiornamento è stato effettuato con successo, False se l'oggetto non è stato trovato
    """
    try:
        update = DataUpdate.objects.get(name=update_name)
        update.status = status
        update.save()
        return True
    except DataUpdate.DoesNotExist:
        return False
