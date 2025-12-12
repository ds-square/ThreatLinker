from multiprocessing import Semaphore
import time
import logging

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Variabile globale per il numero massimo di processi GPU
MAX_GPU_PROCESSES = 2
gpu_semaphore = Semaphore(MAX_GPU_PROCESSES)


def set_max_gpu_processes(max_processes):
    """
    Aggiorna il numero massimo di processi che possono accedere contemporaneamente alla GPU.
    :param max_processes: Numero massimo di processi GPU.
    """
    global MAX_GPU_PROCESSES, gpu_semaphore
    MAX_GPU_PROCESSES = max_processes
    gpu_semaphore = Semaphore(MAX_GPU_PROCESSES)


def acquire_gpu_lock(max_retries=5, retry_delay=1):
    """
    Prova ad acquisire il lock GPU con un numero massimo di tentativi.
    :param max_retries: Numero massimo di tentativi per acquisire il lock.
    :param retry_delay: Tempo in secondi tra un tentativo e l'altro.
    :return: True se il lock è stato acquisito, False altrimenti.
    """
    logger.info("Attempting to acquire GPU lock...")
    for attempt in range(max_retries):
        if gpu_semaphore.acquire(block=False):
            logger.info("GPU lock acquired.")
            return True
        logger.info(f"Attempt {attempt + 1}/{max_retries} failed. Retrying in {retry_delay}s...")
        time.sleep(retry_delay)
    logger.warning("Failed to acquire GPU lock after maximum retries.")
    return False


def release_gpu_lock():
    """
    Rilascia il lock GPU.
    """
    logger.info("Releasing GPU lock...")
    gpu_semaphore.release()
