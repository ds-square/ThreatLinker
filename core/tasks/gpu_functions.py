import redis
import json
import logging
import time

# Configura il logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Configura Redis
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_GPU_SLOTS_KEY = "gpu_slots"
redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

### Funzioni per la gestione degli slot GPU in Redis ###

def get_redis_connection():
    """
    Restituisce una connessione a Redis utilizzando i parametri di configurazione predefiniti.

    :return: Oggetto Redis Connection.
    """
    try:
        # Configura i parametri di connessione
        redis_conn = redis.StrictRedis(
            host='localhost',  # Cambia con il tuo hostname di Redis
            port=6379,         # Cambia con la porta di Redis se diversa
            db=0,              # Specifica il database Redis (di default 0)
            decode_responses=True  # Decodifica automaticamente le risposte in stringhe
        )
        # Testa la connessione
        redis_conn.ping()
        return redis_conn
    except Exception as e:
        raise ConnectionError(f"Unable to connect to Redis: {e}")
    

def initialize_gpu_slots_in_redis(gpu_random_numbers):
    """
    Inizializza gli slot GPU in Redis come stringa JSON.

    :param gpu_random_numbers: Lista di numeri casuali da assegnare agli slot GPU.
    """
    try:
        redis_conn = get_redis_connection()

        # Controlla se la chiave esiste e il suo tipo
        if redis_conn.exists("gpu_slots"):
            key_type = redis_conn.type("gpu_slots").decode("utf-8")
            if key_type != "string":
                logger.error(f"Key 'gpu_slots' exists with incompatible type: {key_type}")
                raise ValueError(f"Incompatible key type for 'gpu_slots': {key_type}")

        # Serializza i dati come JSON e salva in Redis
        redis_conn.set("gpu_slots", json.dumps(gpu_random_numbers))
        logger.info(f"Initialized GPU slots in Redis with values: {gpu_random_numbers}")
    except Exception as e:
        logger.error(f"Error initializing GPU slots in Redis: {e}")
        raise RuntimeError(f"Error initializing GPU slots in Redis: {e}")


def verify_gpu_slots_type():
    """
    Verifica che la chiave `gpu_slots` in Redis sia del tipo corretto (lista).
    """
    try:
        redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)
        gpu_slots_key = "gpu_slots"
        
        key_type = redis_client.type(gpu_slots_key).decode()
        if key_type != "list":
            logger.error(f"GPU slots key has incorrect type: {key_type}")
            return False
        logger.info("GPU slots key is of correct type: list")
        return True
    except Exception as e:
        logger.error(f"Error verifying GPU slots type: {e}")
        raise

def get_gpu_slots_from_redis():
    """
    Recupera gli slot GPU da Redis.
    
    :return: Lista degli slot GPU.
    :raises RuntimeError: In caso di errore durante l'accesso a Redis.
    """
    try:
        gpu_slots_data = redis_client.get(REDIS_GPU_SLOTS_KEY)
        
        if gpu_slots_data is None:
            logger.warning("GPU slots not found in Redis.")
            return []
        
        # Decodifica e deserializza i dati JSON
        slots = json.loads(gpu_slots_data)
        logger.info(f"Retrieved GPU slots from Redis: {slots}")
        return slots
    
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding GPU slots data from Redis: {e}")
        raise RuntimeError(f"Invalid GPU slots data in Redis: {e}")
    
    except Exception as e:
        logger.error(f"Error retrieving GPU slots from Redis: {e}")
        raise RuntimeError(f"Error retrieving GPU slots from Redis: {e}")

def get_gpu_slots_status_in_redis():
    """
    Ottiene lo stato degli slot GPU in Redis.

    :return: Dizionario contenente:
        - "total": Numero totale di slot GPU.
        - "free": Numero di slot liberi.
        - "occupied": Numero di slot occupati.
        - "slots": Lista degli slot (None se libero, altrimenti contiene il process_id).
    :raises RuntimeError: In caso di errore durante l'accesso a Redis.
    """
    try:
        # Recupera gli slot GPU da Redis
        gpu_slots = get_gpu_slots_from_redis()
        
        # Calcola lo stato degli slot
        total_slots = len(gpu_slots)
        free_slots = gpu_slots.count(None)
        occupied_slots = total_slots - free_slots

        # Logga lo stato degli slot
        logger.info(f"GPU Slots Status - Total: {total_slots}, Free: {free_slots}, Occupied: {occupied_slots}")
        logger.debug(f"Current GPU Slots: {gpu_slots}")
        
        # Restituisce lo stato degli slot
        return {
            "total": total_slots,
            "free": free_slots,
            "occupied": occupied_slots,
            "slots": gpu_slots,
        }
    except Exception as e:
        logger.error(f"Error retrieving GPU slots status in Redis: {e}")
        raise RuntimeError(f"Error retrieving GPU slots status in Redis: {e}")


def acquire_gpu_slot_in_redis(pid):
    """
    Aggiunge un processo agli slot GPU disponibili in Redis.
    :param pid: ID del processo che vuole prenotare uno slot GPU.
    :return: True se lo slot è stato acquisito, False altrimenti.
    """
    try:
        gpu_slots = get_gpu_slots_from_redis()
        for i, slot in enumerate(gpu_slots):
            if slot is None:
                gpu_slots[i] = pid
                redis_client.set(REDIS_GPU_SLOTS_KEY, json.dumps(gpu_slots))
                logger.info(f"Process {pid} acquired GPU slot {i}.")
                return True
        logger.warning(f"No GPU slots available for process {pid}.")
        return False
    except Exception as e:
        logger.error(f"Error acquiring GPU slot for process {pid}: {e}")
        raise

def release_gpu_slot_in_redis(pid):
    """
    Rimuove un processo dagli slot GPU in Redis.

    :param pid: ID del processo che rilascia lo slot GPU.
    :return: True se lo slot è stato rilasciato con successo, False altrimenti.
    :raises RuntimeError: In caso di errore durante l'accesso a Redis.
    """
    try:
        # Recupera gli slot GPU da Redis
        gpu_slots = get_gpu_slots_from_redis()
        
        # Cerca lo slot associato al PID e lo rilascia
        if pid in gpu_slots:
            slot_index = gpu_slots.index(pid)
            gpu_slots[slot_index] = None  # Libera lo slot
            redis_client.set(REDIS_GPU_SLOTS_KEY, json.dumps(gpu_slots))  # Aggiorna Redis
            logger.info(f"Process {pid} released GPU slot {slot_index}.")
            return True

        logger.warning(f"Process {pid} did not hold a GPU slot.")
        return False
    except Exception as e:
        logger.error(f"Error releasing GPU slot for process {pid}: {e}")
        raise RuntimeError(f"Error releasing GPU slot for process {pid}: {e}")



def is_gpu_slot_available_in_redis():
    """
    Controlla se ci sono slot GPU liberi in Redis.
    :return: True se almeno uno slot GPU è libero, False altrimenti.
    """
    try:
        gpu_slots = get_gpu_slots_from_redis()
        available = any(slot is None for slot in gpu_slots)
        logger.info(f"GPU slot availability check: {'Available' if available else 'Not available'}.")
        return available
    except Exception as e:
        logger.error(f"Error checking GPU slot availability in Redis: {e}")
        raise


def promote_to_gpu_in_redis(pid):
    """
    Promuove un processo a GPU se c'è uno slot libero.

    :param pid: ID del processo.
    :return: True se la promozione è avvenuta, False altrimenti.
    """
    try:
        # Ottieni la lista degli slot GPU da Redis
        gpu_slots = get_gpu_slots_from_redis()

        # Cerca uno slot libero (indicato come None)
        for i, slot in enumerate(gpu_slots):
            if slot is None:  # Slot libero trovato
                gpu_slots[i] = pid  # Assegna il PID allo slot
                redis_client.set(REDIS_GPU_SLOTS_KEY, json.dumps(gpu_slots))  # Aggiorna Redis
                logger.info(f"Process {pid} promoted to GPU (slot {i}).")
                return True

        # Nessuno slot libero trovato
        logger.info(f"No GPU slots available for process {pid}.")
        return False
    except Exception as e:
        logger.error(f"Error promoting process {pid} to GPU in Redis: {e}")
        raise RuntimeError(f"Error promoting process {pid} to GPU in Redis: {e}")

