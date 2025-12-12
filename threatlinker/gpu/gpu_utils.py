import torch
import logging

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FREE_MEMORY = 1000
MIN_BATCH_SIZE = 8
MAX_BATCH_SIZE = 64
MAX_MEMORY_PER_BATCH = 10**7

def is_gpu_available(threshold=FREE_MEMORY * 1024 * 1024):
    """
    Controlla se la GPU ha abbastanza memoria libera.
    :param threshold: Memoria minima necessaria in byte (default: 500MB).
    :return: True se la GPU è disponibile, False altrimenti.
    """
    if torch.cuda.is_available():
        free_memory = torch.cuda.mem_get_info()[0]  # Memoria libera sulla GPU
        return free_memory > threshold
    return False

def calculate_dynamic_batch_size():
    """
    Calcola dinamicamente la dimensione del batch in base alla memoria GPU disponibile.
    :return: Batch size calcolato.
    """
    try:
        if torch.cuda.is_available():
            global MIN_BATCH_SIZE
            global MAX_BATCH_SIZE
            global MAX_MEMORY_PER_BATCH
            total_memory = torch.cuda.get_device_properties(0).total_memory
            reserved_memory = torch.cuda.memory_reserved(0)
            allocated_memory = torch.cuda.memory_allocated(0)
            free_memory = total_memory - (reserved_memory + allocated_memory)

            # Batch size basato sulla memoria disponibile
            batch_size = max(MIN_BATCH_SIZE, int(free_memory / MAX_MEMORY_PER_BATCH))
            batch_size = min(batch_size, MAX_BATCH_SIZE)  # Clamp del batch size massimo

            logging.info(f"Calculated dynamic batch size: {batch_size} "
                         f"(Free memory: {free_memory}, Max memory per batch: {MAX_MEMORY_PER_BATCH})")
            return batch_size

        logging.warning("CUDA not available. Falling back to minimum batch size.")
        return MIN_BATCH_SIZE  # Fallback su CPU

    except Exception as e:
        logging.error(f"Error calculating dynamic batch size: {e}")
        return MIN_BATCH_SIZE  # In caso di errore, ritorna il batch minimo

def clear_gpu_cache():
    """
    Libera la memoria GPU non più utilizzata.
    """
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

def profile_gpu():
    """
    Ritorna un profilo dettagliato della memoria GPU e altre proprietà.
    :return: Dizionario con informazioni sulla GPU.
    """
    if torch.cuda.is_available():
        device = torch.cuda.current_device()
        properties = torch.cuda.get_device_properties(device)
        memory_info = torch.cuda.mem_get_info()

        return {
            "device_name": properties.name,
            "total_memory": properties.total_memory,
            "free_memory": memory_info[0],
            "reserved_memory": torch.cuda.memory_reserved(device),
            "allocated_memory": torch.cuda.memory_allocated(device),
        }
    return {"error": "GPU non disponibile"}

def get_cuda_device_count():
    """
    Ritorna il numero di dispositivi CUDA disponibili.
    :return: Numero di dispositivi CUDA.
    """
    return torch.cuda.device_count() if torch.cuda.is_available() else 0
