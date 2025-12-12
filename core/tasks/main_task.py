import os
from celery import shared_task

from core.tasks.task_utils import *
from core.tasks.task_config import *
from core.tasks.process import process_cve_block
from core.tasks.gpu_functions import *
import random
import logging

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@shared_task
def manage_task_status(task_id, ai_models, preprocessing_options, capec_version):
    logger.info(f"Start manage_task_status for Task ID: {task_id} (PID: {os.getpid()})")

    try:
        # 1. Valida gli input
        logger.info("Validating task inputs...")
        validate_task_inputs(task_id, ai_models, preprocessing_options, capec_version)

        # 2. Recupera la task dal database
        logger.info(f"Retrieving task with ID: {task_id}")
        task = get_task_by_id(task_id)

        # 3. Aggiorna lo stato della task
        logger.info(f"Updating task status to 'in_progress' for Task ID: {task_id}")
        update_task_status(task, "in_progress")

        logger.info(f"Checking if GroundTruth or Correlation for Task ID: {task_id}")
        if (is_correlation_task(task)):
            IS_CORRELATION = True
        else:
            IS_CORRELATION = False

        # 4. Estrai gli ID delle CVE e dividi in chunk
        logger.info("Extracting and chunking CVE IDs...")
        cve_ids = list(task.cve_hosts.keys())
        cve_chunks = split_data_balanced(cve_ids, NUM_PROCESSES, GPU_PROCESSES)
        logger.info(f"Divided {len(cve_ids)} CVE IDs into {len(cve_chunks)} chunks.")

        # 5. Determina quali processi usano GPU o CPU
        logger.info("Assigning processes to GPU and CPU...")
        gpu_processes, cpu_processes = assign_gpu_cpu_processes(len(cve_chunks))
        logger.info(f"Assigned {len(gpu_processes)} GPU processes and {len(cpu_processes)} CPU processes.")
        logger.info(f"GPU Processes: {gpu_processes}, CPU Processes: {cpu_processes}")

        # 6. Genera numeri casuali univoci per tutti i processi
        total_processes = len(gpu_processes) + len(cpu_processes)
        random_numbers = random.sample(range(100000, 999999), total_processes)
        logger.info(f"Generated random numbers for processes: {random_numbers}")

        # 7. Inizializza gli slot GPU con numeri casuali in Redis
        gpu_random_numbers = random_numbers[:len(gpu_processes)]
        initialize_gpu_slots_in_redis(gpu_random_numbers)

        # Verifica gli slot GPU in Redis
        gpu_status = get_gpu_slots_status_in_redis()
        logger.info(f"GPU Slots Status in Redis after initialization: {gpu_status}")

        # 8. Assegna i numeri casuali ai processi
        process_random_mapping = {}
        for i, chunk in enumerate(cve_chunks):
            process_random_mapping[i] = random_numbers.pop(0)
        logger.info(f"Process random mapping: {process_random_mapping}")

        # 9. Crea e avvia il job Celery
        job = create_celery_chord(
            cve_chunks,
            task_id,
            preprocessing_options,
            capec_version,
            ai_models,
            process_random_mapping,
        )
        job.apply_async()

        return task_id

    except ValueError as ve:
        logger.error(f"ValueError in manage_task_status for Task ID {task_id}: {ve}")
        return {"status": "error", "type": "ValueError", "message": str(ve)}

    except Exception as e:
        logger.error(f"Unexpected error in manage_task_status for Task ID {task_id}: {e}")
        return {"status": "error", "type": "Exception", "message": str(e)}


def create_celery_chord(cve_chunks, task_id, preprocessing_options, capec_version, ai_models, process_random_mapping):
    """
    Crea un Celery chord per processare i chunk di CVE.

    :param cve_chunks: Lista di chunk di CVE.
    :param task_id: ID della task.
    :param preprocessing_options: Opzioni di preprocessing.
    :param capec_version: Versione CAPEC.
    :param ai_models: Modelli AI da utilizzare.
    :param gpu_processes: Lista degli indici dei processi che useranno GPU.
    :return: Oggetto chord Celery.
    """
    try:
        # Creazione delle task per ogni chunk
        task_group = [
            process_cve_block.s(
                chunk,
                task_id,
                preprocessing_options,
                capec_version,
                ai_models,
                gpu_id=process_random_mapping[i]  # Passa il numero casuale associato al processo
            )
            for i, chunk in enumerate(cve_chunks)
        ]

        # Callback per completare la task
        chord_callback = complete_task_progress.s(task_id=task_id)

        # Creazione del chord
        job = chord(task_group, chord_callback)

        logger.info(f"Celery chord created for {len(cve_chunks)} chunks")
        return job
    except Exception as e:
        logger.error(f"Error creating Celery chord: {e}")
        raise


