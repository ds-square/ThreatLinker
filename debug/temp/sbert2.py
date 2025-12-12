from sentence_transformers import SentenceTransformer, util
import torch
import warnings
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from threatlinker.gpu.gpu_utils import is_gpu_available, calculate_dynamic_batch_size, clear_gpu_cache, profile_gpu
from threatlinker.gpu.gpu_semaphore import acquire_gpu_lock, release_gpu_lock
import logging
from prometheus_client import Summary, Counter, CollectorRegistry

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Crea un registro personalizzato
registry_sbert = CollectorRegistry()

# Definisci le metriche nel registro personalizzato
REQUEST_TIME_SBERT = Summary(
    'request_processing_seconds_sbert',
    'Time spent processing requests in SBERT',
    registry=registry_sbert
)
BATCH_COUNT_SBERT = Counter(
    'batch_processed_total_sbert',
    'Total number of batches processed in SBERT',
    registry=registry_sbert
)
FALLBACK_COUNT_SBERT = Counter(
    'fallback_to_cpu_total_sbert',
    'Total number of GPU fallbacks to CPU in SBERT',
    registry=registry_sbert
)

# Ignora il warning specifico
warnings.filterwarnings("ignore", category=FutureWarning, message="`clean_up_tokenization_spaces` was not set")


class SbertSimilarity:
    def __init__(self, model_choice='mpnet', batch_size=32, max_threads=4, fallback_limit=3, 
                 lock_timeout=10, thread_timeout=30, device_preference='auto'):
        """
        :param model_choice: Modello SBERT da utilizzare ('minilm', 'distilroberta', 'mpnet').
        :param batch_size: Dimensione del batch.
        :param max_threads: Numero massimo di thread per il batch processing.
        :param fallback_limit: Limite massimo di fallback alla CPU.
        :param lock_timeout: Timeout per il lock della GPU.
        :param thread_timeout: Timeout per i thread.
        :param device_preference: 'cpu', 'gpu', o 'auto' per determinare il dispositivo preferito.
        """
        model_dict = {
            'minilm': 'all-MiniLM-L6-v2',
            'distilroberta': 'all-distilroberta-v1',
            'mpnet': 'paraphrase-mpnet-base-v2'
        }

        if model_choice not in model_dict:
            raise ValueError(f"Modello '{model_choice}' non riconosciuto. Scegli tra: {list(model_dict.keys())}.")

        self.model_name = model_dict[model_choice]
        self.batch_size = batch_size
        self.max_threads = max_threads
        self.fallback_limit = fallback_limit
        self.lock_timeout = lock_timeout
        self.thread_timeout = thread_timeout
        self.fallback_attempts = 0
        self.device_preference = device_preference.lower()

        # Determina il dispositivo iniziale in base alla preferenza
        self.device = self._determine_initial_device()

        # Carica il modello sul dispositivo scelto
        self.model = self._preload_model()
        logger.info(f"Modello '{self.model_name}' caricato su: {self.device}")

        # Caching degli embeddings
        self.cached_sentence = None
        self.cached_embedding = None


    @lru_cache(maxsize=5)
    def _preload_model(self):
        logger.info(f"Precaricamento del modello '{self.model_name}' su {self.device}.")
        return SentenceTransformer(self.model_name).to(self.device)

    def _determine_initial_device(self):
        if self.device_preference == 'gpu':
            if torch.cuda.is_available():
                logger.info("GPU disponibile. Utilizzo GPU come dispositivo iniziale.")
                return torch.device("cuda")
            else:
                logger.warning("GPU non disponibile. Passaggio alla CPU.")
                return torch.device("cpu")
        elif self.device_preference == 'cpu':
            logger.info("Preferenza per la CPU selezionata. Utilizzo CPU come dispositivo iniziale.")
            return torch.device("cpu")
        elif self.device_preference == 'auto':
            if torch.cuda.is_available():
                logger.info("Modalità 'auto' selezionata. Utilizzo GPU come dispositivo iniziale.")
                return torch.device("cuda")
            else:
                logger.warning("Modalità 'auto' selezionata, ma GPU non disponibile. Passaggio alla CPU.")
                return torch.device("cpu")
        else:
            raise ValueError(f"Valore non valido per 'device_preference': {self.device_preference}.")

    def _switch_device(self):
        acquired = False
        try:
            if self.device_preference == 'cpu':
                logger.info("Switch non necessario. Preferenza per la CPU impostata.")
                return

            acquired = acquire_gpu_lock(max_retries=3, retry_delay=0.5)
            if acquired and is_gpu_available():
                target_device = "cuda"
            else:
                target_device = "cpu"
                logger.warning("GPU unavailable or lock acquisition failed. Switching to CPU.")
        except Exception as e:
            logger.warning(f"Failed to acquire GPU lock: {e}")
            target_device = "cpu"

        if self.device.type != target_device:
            logger.info(f"Switching model to {target_device}")
            self.device = torch.device(target_device)
            self.model = self.model.to(self.device)

        if acquired:
            release_gpu_lock()


    def _fallback_to_cpu(self):
        if self.fallback_attempts >= self.fallback_limit:
            raise RuntimeError("Max fallback limit to CPU reached.")
        logger.warning("Fallback to CPU.")
        self.device = torch.device("cpu")
        self.model = self.model.to(self.device)
        torch.cuda.empty_cache()
        FALLBACK_COUNT_SBERT.inc()
        self.fallback_attempts += 1

    def log_gpu_memory(self):
        if torch.cuda.is_available():
            total_memory = torch.cuda.get_device_properties(0).total_memory
            reserved_memory = torch.cuda.memory_reserved(0)
            allocated_memory = torch.cuda.memory_allocated(0)
            logger.info(f"GPU Memory - Total: {total_memory}, Reserved: {reserved_memory}, Allocated: {allocated_memory}")

    def invalidate_cache(self):
        self._encode_sentence.cache_clear()
        self._preload_model.cache_clear()
        logger.info("Cache cleared.")

    @lru_cache(maxsize=5000)
    def _encode_sentence(self, sentence):
        self._switch_device()
        return self.model.encode(sentence, convert_to_tensor=True, device=self.device)

    @REQUEST_TIME_SBERT.time()
    def calculate_similarity(self, sentence1, sentence2):
        try:
            self._switch_device()
            embeddings1 = self._encode_sentence(sentence1)
            embeddings2 = self._encode_sentence(sentence2)
            similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2)
            self.fallback_attempts = 0
            return similarity_score.item()
        except RuntimeError as e:
            logger.error(f"Errore durante la similarità: {e}")
            self._fallback_to_cpu()
            return 0.0

    @REQUEST_TIME_SBERT.time()
    def calculate_similarity_batch(self, sentence, sentences_list):
        if not sentences_list:
            logger.warning("Empty sentence list provided for batch similarity.")
            return []

        acquired = False
        try:
            acquired = acquire_gpu_lock(max_retries=3, retry_delay=0.5)
            if not acquired:
                logger.info("GPU lock not available. Switching to CPU.")
                self.device = torch.device("cpu")
                self.model = self.model.to(self.device)

            self._switch_device()
            dynamic_batch_size = calculate_dynamic_batch_size()
            logger.info(f"Using dynamic batch size: {dynamic_batch_size}")
            self.log_gpu_memory()

            if self.cached_sentence != sentence:
                self.cached_sentence = sentence
                self.cached_embedding = self.model.encode(
                    sentence, convert_to_tensor=True, device=self.device
                )

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                embeddings_batches = list(executor.map(
                    lambda batch: self._safe_encode_batch(batch, dynamic_batch_size),
                    [sentences_list[i:i + dynamic_batch_size] for i in range(0, len(sentences_list), dynamic_batch_size)]
                ))

            similarity_scores = []
            for embeddings_batch in embeddings_batches:
                similarity_scores.extend(util.pytorch_cos_sim(self.cached_embedding, embeddings_batch).squeeze(0).tolist())

            return similarity_scores

        except RuntimeError as e:
            logger.error(f"[ERROR] Runtime error during batch calculation: {e}")
            self._fallback_to_cpu()
            return self.calculate_similarity_batch(sentence, sentences_list)

        finally:
            if acquired:
                release_gpu_lock()
            clear_gpu_cache()

    def _safe_encode_batch(self, batch, batch_size):
        try:
            return self.model.encode(batch, batch_size=batch_size, convert_to_tensor=True, device=self.device)
        except RuntimeError as e:
            logger.error(f"Error during batch encoding: {e}")
            self._fallback_to_cpu()
            return self.model.encode(batch, batch_size=batch_size, convert_to_tensor=True, device=torch.device("cpu"))

    def clear_cache(self):
        """
        Pulisce la cache degli embeddings.
        """
        self.cached_sentence = None
        self.cached_embedding = None
        clear_gpu_cache()

    def update_batch_size(self, new_batch_size):
        """
        Aggiorna dinamicamente la dimensione del batch.
        """
        self.batch_size = new_batch_size
        logger.info(f"Batch size aggiornato a {self.batch_size}.")

    def update_model(self, new_model_choice):
        """
        Aggiorna dinamicamente il modello SBERT.
        """
        model_dict = {
            'minilm': 'all-MiniLM-L6-v2',
            'distilroberta': 'all-distilroberta-v1',
            'mpnet': 'paraphrase-mpnet-base-v2'
        }
        if new_model_choice in model_dict:
            self.model_name = model_dict[new_model_choice]
            self.model = SentenceTransformer(self.model_name).to(self.device)
            self.invalidate_cache()
            logger.info(f"Modello aggiornato a '{self.model_name}'.")
        else:
            logger.error(f"Invalid model choice: {new_model_choice}")
