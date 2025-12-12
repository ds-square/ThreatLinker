from django.core.exceptions import ObjectDoesNotExist
from celery import chord, shared_task
from core.tasks.task_config import *
from core.models import Task

import logging


# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

### Basic Task Functions

def get_task_by_id(task_id):
    """
    Recupera una task dal database dato il suo ID.

    :param task_id: ID della task da recuperare.
    :return: Oggetto Task.
    :raises ValueError: Se la task non esiste.
    """
    try:
        task = Task.objects.get(id=task_id)
        return task
    except ObjectDoesNotExist:
        logger.error(f"Task ID {task_id} does not exist.")
        raise ValueError(f"Task ID {task_id} does not exist.")
    except Exception as e:
        logger.error(f"Unexpected error while fetching Task ID {task_id}: {e}")
        raise ValueError(f"Error retrieving Task ID {task_id}: {e}")

def update_task_status(task, status):
    """
    Aggiorna lo stato di una task.

    :param task: Oggetto Task da aggiornare.
    :param status: Nuovo stato da impostare.
    :return: Task aggiornata.
    :raises ValueError: Se lo stato fornito non è valido.
    """
    valid_statuses = {"pending", "in_progress", "complete", "failed"}
    
    if status not in valid_statuses:
        logger.error(f"Invalid status '{status}' for Task ID {task.id}. Valid statuses: {valid_statuses}")
        raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}.")

    try:
        task.status = status
        task.save()
        logger.info(f"Task ID {task.id} status updated to '{status}'.")
        return task
    except Exception as e:
        logger.error(f"Error updating status for Task ID {task.id}: {e}")
        raise ValueError(f"Failed to update Task ID {task.id} status: {e}")

def get_task_type(task):
    """
    Restituisce il tipo di una task.

    :param task: Oggetto Task da cui ottenere il tipo.
    :return: Tipo della task.
    :raises AttributeError: Se il tipo della task non è definito o non è accessibile.
    """
    try:
        # Assumi che il tipo sia memorizzato in un attributo chiamato "type"
        task_type = task.type
        logger.info(f"Task ID {task.id} type retrieved: '{task_type}'.")
        return task_type
    except AttributeError as e:
        logger.error(f"Task ID {getattr(task, 'id', 'unknown')} has no attribute 'type': {e}")
        raise AttributeError(f"Task ID {getattr(task, 'id', 'unknown')} has no attribute 'type'.")
    except Exception as e:
        logger.error(f"Unexpected error while retrieving type for Task ID {getattr(task, 'id', 'unknown')}: {e}")
        raise RuntimeError(f"Failed to retrieve type for Task ID {getattr(task, 'id', 'unknown')}: {e}")

def is_correlation_task(task):
    """
    Verifica se il tipo della task è 'correlation'.

    :param task: Oggetto Task da verificare.
    :return: True se il tipo della task è 'correlation', False altrimenti.
    """
    try:
        task_type = get_task_type(task)
        is_correlation = task_type == "correlation"
        logger.info(f"Task ID {task.id} is_correlation: {is_correlation}.")
        return is_correlation
    except Exception as e:
        logger.error(f"Error determining if Task ID {getattr(task, 'id', 'unknown')} is correlation: {e}")
        return False



### Funzioni ausiliarie

def get_cve_ids(task):
    """
    Estrae gli ID delle CVE associati a una task, garantendo l'unicità.

    :param task: Oggetto Task da cui estrarre gli ID delle CVE.
    :return: Un set di ID univoci delle CVE.
    :raises ValueError: Se la task non contiene CVE valide.
    """
    try:
        # Controlla che la task abbia cve_hosts
        if not hasattr(task, 'cve_hosts') or not isinstance(task.cve_hosts, dict):
            raise ValueError(f"Task ID {task.id} does not have a valid 'cve_hosts' attribute.")
        
        # Estrai gli ID delle CVE
        cve_ids = set(task.cve_hosts.keys())
        
        # Controlla che ci siano CVE valide
        if not cve_ids:
            raise ValueError(f"Task ID {task.id} has no CVE IDs.")
        
        return cve_ids
    except Exception as e:
        logger.error(f"Error extracting CVE IDs for Task ID {task.id}: {e}")
        raise

### Chunks functions

def split_data_balanced(data_list, num_processes, gpu_processes):
    """
    Divide una lista di dati in chunk bilanciando il carico tra processi GPU e CPU,
    garantendo che i processi GPU abbiano proporzionalmente più carico.

    :param data_list: Lista di dati da dividere.
    :param num_processes: Numero totale di processi.
    :param gpu_processes: Numero di processi GPU.
    :return: Lista di chunk bilanciati.
    """
    try:
        # Validazioni
        if not data_list:
            raise ValueError("The input list cannot be empty.")
        if not isinstance(num_processes, int) or num_processes <= 0:
            raise ValueError("Number of processes must be a positive integer.")
        if not isinstance(gpu_processes, int) or gpu_processes < 0 or gpu_processes > num_processes:
            raise ValueError("GPU processes must be a non-negative integer and not exceed total processes.")
        
        # Calcolo proporzioni
        num_data = len(data_list)
        cpu_processes = num_processes - gpu_processes

        # Calcola i pesi per GPU e CPU
        total_weight = gpu_processes * 2 + cpu_processes  # Assegna doppio peso alle GPU
        gpu_weight = gpu_processes * 2 / total_weight
        cpu_weight = cpu_processes / total_weight

        # Calcolo dei carichi
        gpu_load = round(num_data * gpu_weight)
        cpu_load = num_data - gpu_load  # Assicura che il totale sia corretto

        # Distribuzione per GPU
        gpu_chunk_sizes = []
        if gpu_processes > 0:
            gpu_base_size = gpu_load // gpu_processes
            gpu_remainder = gpu_load % gpu_processes
            gpu_chunk_sizes = [gpu_base_size + 1 if i < gpu_remainder else gpu_base_size for i in range(gpu_processes)]

        # Distribuzione per CPU
        cpu_chunk_sizes = []
        if cpu_processes > 0:
            cpu_base_size = cpu_load // cpu_processes
            cpu_remainder = cpu_load % cpu_processes
            cpu_chunk_sizes = [cpu_base_size + 1 if i < cpu_remainder else cpu_base_size for i in range(cpu_processes)]

        # Combina le dimensioni dei chunk
        chunk_sizes = gpu_chunk_sizes + cpu_chunk_sizes

        # Suddivide la lista
        chunks = []
        start = 0
        for size in chunk_sizes:
            chunks.append(data_list[start:start + size])
            start += size

        return chunks
    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during chunking: {e}")
        raise



def split_data_into_chunks(data_list, num_processes=None):
    """
    Divide una lista in chunk, calcolando automaticamente le dimensioni per bilanciare il carico.

    :param data_list: Lista di dati da dividere (ad esempio, ID delle CVE).
    :param num_processes: Numero di processi disponibili.
    :return: Lista di chunk (sottoliste) bilanciati per i processi.
    :raises ValueError: Se la lista è vuota o il numero di processi non è valido.
    """
    try:
        num_processes = num_processes or NUM_PROCESSES
        # Validazioni
        if not data_list:
            raise ValueError("The input list cannot be empty.")
        if not isinstance(num_processes, int) or num_processes <= 0:
            raise ValueError("Number of processes must be a positive integer.")
        
        num_cves = len(data_list)

        # Calcola dimensioni dei chunk
        if num_cves < num_processes:
            # Più processi che CVE: alcuni processi saranno inattivi
            chunk_sizes = [1] * num_cves + [0] * (num_processes - num_cves)
        else:
            base_size = num_cves // num_processes
            remainder = num_cves % num_processes
            chunk_sizes = [base_size + 1 if i < remainder else base_size for i in range(num_processes)]

        logger.info(f"Chunk sizes calculated: {chunk_sizes}")

        # Suddivide la lista in base alle dimensioni dei chunk
        chunks = []
        start = 0
        for size in chunk_sizes:
            if size > 0:
                chunks.append(data_list[start:start + size])
                start += size

        logger.info(f"Successfully split list of size {num_cves} into {len(chunks)} chunks.")
        logger.info(f"Chunks: {chunks}")
        return chunks
    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during chunking: {e}")
        raise



### Validation function

def validate_task_inputs(task_id, ai_models, preprocessing_options, capec_version):
    """
    Valida gli input per la gestione di una task.

    :param task_id: ID della task.
    :param ai_models: Lista di modelli AI da utilizzare.
    :param preprocessing_options: Opzioni di preprocessing.
    :param capec_version: Versione CAPEC.
    :return: None.
    :raises ValueError: Se uno degli input non è valido.
    """
    if not task_id or not isinstance(task_id, int):
        raise ValueError("Task ID must be an int number.")
    if not ai_models or not isinstance(ai_models, list):
        raise ValueError("AI models must be a non-empty list.")
    if not isinstance(preprocessing_options, dict):
        raise ValueError("Preprocessing options must be a dictionary.")
    if not capec_version or not isinstance(capec_version, str):
        raise ValueError("CAPEC version must be a non-empty string.")
    logger.info("Task inputs validated successfully.")

@shared_task
def complete_task_progress(status, task_id):
    """
    Aggiorna lo stato di completamento di una task specificata e modifica il campo 'ai_models'
    aggiungendo il suffisso '_keyword' ai modelli già presenti.

    :param status: Stato corrente del processo (es. 'complete', 'in_progress').
    :param task_id: ID della task da aggiornare.
    :return: Dizionario con lo stato finale e l'ID della task.
    """
    logger.info(f"Start complete_task_progress for Task ID: {task_id}, status: {status}")
    
    task = get_task_by_id(task_id)

    try:
        # Verifica se la task è completata
        if task.check_task_completion():
            task.status = "complete"

            # Modifica il campo 'ai_models'
            if hasattr(task, "ai_models") and isinstance(task.ai_models, list):
                updated_models = task.ai_models + [f"{model}_keyword" for model in task.ai_models]
                task.ai_models = list(set(updated_models))  # Rimuove eventuali duplicati
            else:
                logger.warning(f"Task {task_id} has no valid 'ai_models' field. Skipping update.")

            task.save()
            logger.info(f"Task {task_id} marked as complete.")
            return {"status": "completed", "task_id": task_id}
        else:
            # Se non completata, aggiorna lo stato come ancora in progresso
            task.status = "in_progress"
            task.save()
            logger.info(f"Task {task_id} still in progress.")
            return {"status": "in_progress", "task_id": task_id}
    except Exception as e:
        # Log e gestione degli errori generici
        logger.error(f"Error while updating Task ID {task_id}: {e}")
        return {"status": "failed", "error": str(e), "task_id": task_id}


### Assign GPU Processes

def assign_gpu_cpu_processes(num_chunks):
    """
    Determina quali processi useranno GPU e quali CPU in base a USE_GPU.

    :param num_chunks: Numero totale di chunk.
    :return: Tuple (gpu_processes, cpu_processes).
    """
    from core.tasks.task_config import USE_GPU, NUM_PROCESSES

    if not USE_GPU:
        # Tutti i processi usano la CPU
        logger.info("USE_GPU è False. Tutti i processi useranno la CPU.")
        return [], list(range(num_chunks))

    # Calcola il numero di processi GPU e CPU
    num_gpu_processes = GPU_PROCESSES
    num_cpu_processes = NUM_PROCESSES - GPU_PROCESSES

    # Determina gli indici dei processi GPU e CPU
    gpu_processes = list(range(num_gpu_processes))  # Prima metà dei chunk
    cpu_processes = list(range(num_gpu_processes, num_chunks))  # Resto dei chunk

    logger.info(f"USE_GPU è True. {len(gpu_processes)} processi useranno la GPU, {len(cpu_processes)} useranno la CPU.")
    return gpu_processes, cpu_processes
