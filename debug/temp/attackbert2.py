from transformers import AutoTokenizer, AutoModel
import torch
from sentence_transformers import util
import warnings
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from prometheus_client import Summary, Counter, CollectorRegistry
import logging
from threatlinker.gpu.gpu_utils import is_gpu_available, calculate_dynamic_batch_size, clear_gpu_cache, profile_gpu
from threatlinker.gpu.gpu_semaphore import acquire_gpu_lock, release_gpu_lock

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Crea un registro personalizzato per AttackBERT
registry_attackbert = CollectorRegistry()

# Prometheus monitoring (registrato nel registro personalizzato)
REQUEST_TIME_ATTACKBERT = Summary(
    'request_processing_seconds_attackbert',
    'Time spent processing requests in AttackBERT',
    registry=registry_attackbert
)
BATCH_COUNT_ATTACKBERT = Counter(
    'batch_processed_total_attackbert',
    'Total number of batches processed in AttackBERT',
    registry=registry_attackbert
)
FALLBACK_COUNT_ATTACKBERT = Counter(
    'fallback_to_cpu_total_attackbert',
    'Total number of GPU fallbacks to CPU in AttackBERT',
    registry=registry_attackbert
)
# Ignora il warning specifico
warnings.filterwarnings("ignore", category=FutureWarning, message="`clean_up_tokenization_spaces` was not set")


class AttackBERTSimilarity:
    def __init__(self, model_choice='attackbert', batch_size=32, max_threads=4, fallback_limit=3, lock_timeout=10, max_length=512):
        """
        Inizializza la classe con il modello AttackBERT specificato.
        :param model_choice: Nome del modello ('attackbert').
        :param batch_size: Dimensione iniziale del batch.
        :param max_threads: Numero massimo di thread per parallelizzazione.
        :param fallback_limit: Numero massimo di fallback consecutivi alla CPU.
        :param lock_timeout: Timeout per il GPU lock.
        :param max_length: Lunghezza massima delle frasi per il tokenizer.
        """
        model_dict = {
            'attackbert': 'basel/ATTACK-BERT'
        }

        if model_choice not in model_dict:
            raise ValueError(f"Model '{model_choice}' not recognized. Choose from: {list(model_dict.keys())}.")

        self.model_name = model_dict[model_choice]
        self.batch_size = batch_size
        self.device = torch.device("cpu")  # Default iniziale
        self.max_threads = max_threads
        self.fallback_limit = fallback_limit
        self.lock_timeout = lock_timeout
        self.max_length = max_length
        self.fallback_attempts = 0

        # Carica il tokenizer e il modello (inizialmente sulla CPU)
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = self._preload_model()
        logger.info(f"Model '{self.model_name}' loaded on: {self.device}")

        # Caching degli embeddings
        self.cached_sentence = None
        self.cached_embedding = None

    @lru_cache(maxsize=5)
    def _preload_model(self):
        logger.info(f"Preloading model '{self.model_name}' on {self.device}.")
        return AutoModel.from_pretrained(self.model_name).to(self.device)

    def _switch_device(self):
        """
        Passa dinamicamente tra GPU e CPU in base alla disponibilità e al semaforo GPU.
        """
        acquired = False
        try:
            acquired = acquire_gpu_lock(max_retries=3, retry_delay=0.5)
            if acquired and is_gpu_available():
                target_device = "cuda"
            else:
                target_device = "cpu"
                logger.warning("GPU unavailable or lock acquisition failed. Switching to CPU.")
        except Exception as e:
            logger.warning(f"Failed to acquire GPU lock: {e}")
            target_device = "cpu"

        # Cambia dispositivo solo se necessario
        if self.device.type != target_device:
            logger.info(f"Switching model to {target_device}")
            self.device = torch.device(target_device)
            self.model = self.model.to(self.device)

        # Rilascia il lock GPU se acquisito
        if acquired:
            release_gpu_lock()

    def _fallback_to_cpu(self):
        """
        Passa il modello alla CPU in caso di errore GPU.
        """
        if self.fallback_attempts >= self.fallback_limit:
            raise RuntimeError("Max fallback limit to CPU reached.")
        logger.warning("Fallback to CPU.")
        self.device = torch.device("cpu")
        self.model = self.model.to(self.device)
        torch.cuda.empty_cache()  # Pulisci la cache GPU
        FALLBACK_COUNT_ATTACKBERT.inc()  # Cambia in FALLBACK_COUNT_ATTACKBERT per AttackBERT
        self.fallback_attempts += 1

    def _reset_fallback_attempts(self):
        self.fallback_attempts = 0

    def log_gpu_memory(self):
        """
        Registra lo stato della memoria GPU.
        """
        if torch.cuda.is_available():
            total_memory = torch.cuda.get_device_properties(0).total_memory
            reserved_memory = torch.cuda.memory_reserved(0)
            allocated_memory = torch.cuda.memory_allocated(0)
            logger.info(f"GPU Memory - Total: {total_memory}, Reserved: {reserved_memory}, Allocated: {allocated_memory}")

    def invalidate_cache(self):
        self._preload_model.cache_clear()
        logger.info("Cache cleared.")

    def _encode_sentence(self, sentence):
        """
        Codifica una singola frase utilizzando AttackBERT.
        """
        self._switch_device()
        inputs = self.tokenizer(sentence, return_tensors='pt', truncation=True, padding=True, max_length=self.max_length).to(self.device)
        with torch.no_grad():
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1)

    def _encode_batch(self, batch):
        """
        Effettua l'encoding di un batch con gestione degli errori per AttackBERT.
        """
        try:
            inputs = self.tokenizer(batch, return_tensors='pt', truncation=True, padding=True, max_length=self.max_length).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
            return outputs.last_hidden_state.mean(dim=1)
        except RuntimeError as e:
            logger.error(f"Error during batch encoding in AttackBERT: {e}")
            self._fallback_to_cpu()
            return self._encode_batch(batch)  # Ritenta sulla CPU


    @REQUEST_TIME_ATTACKBERT.time()
    def calculate_similarity(self, sentence1, sentence2):
        """
        Calcola la similarità tra due frasi.
        """
        try:
            self._switch_device()
            embeddings1 = self._encode_sentence(sentence1)
            embeddings2 = self._encode_sentence(sentence2)
            similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2)
            self._reset_fallback_attempts()
            return similarity_score.item()
        except RuntimeError as e:
            logger.error(f"Error during similarity calculation: {e}")
            self._fallback_to_cpu()
            return 0.0

    @REQUEST_TIME_ATTACKBERT.time()
    def calculate_similarity_batch(self, sentence, sentences_list):
        """
        Calcola la similarità tra una frase e una lista di frasi in batch.
        """
        if not sentences_list:
            logger.warning("Empty sentence list provided for batch similarity.")
            return []

        acquired = False
        try:
            # Prova ad acquisire il lock GPU con limite di tentativi
            acquired = acquire_gpu_lock(max_retries=3, retry_delay=0.5)
            if not acquired:
                logger.warning("Failed to acquire GPU lock after retries. Using CPU.")
                self.device = torch.device("cpu")
                self.model = self.model.to(self.device)

            self._switch_device()
            logger.info(f"GPU status before batch processing: {profile_gpu()}")

            dynamic_batch_size = calculate_dynamic_batch_size()
            logger.info(f"Using dynamic batch size: {dynamic_batch_size}")
            self.log_gpu_memory()

            if self.cached_sentence != sentence:
                self.cached_sentence = sentence
                self.cached_embedding = self._encode_sentence(sentence)

            start_time = time.time()

            # Parallelizzazione con ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                embeddings_batches = []
                for i in range(0, len(sentences_list), dynamic_batch_size):
                    batch = sentences_list[i:i + dynamic_batch_size]
                    try:
                        embeddings_batches.append(executor.submit(self._encode_batch, batch).result(timeout=30))
                    except TimeoutError:
                        logger.error(f"Timeout occurred for batch starting at index {i}")
                        continue

            similarity_scores = []
            for embeddings_batch in embeddings_batches:
                similarity_scores.extend(util.pytorch_cos_sim(self.cached_embedding, embeddings_batch).squeeze(0).tolist())

            elapsed_time = time.time() - start_time
            throughput = len(sentences_list) / elapsed_time
            BATCH_COUNT_ATTACKBERT.inc()
            logger.info(f"Batch processed in {elapsed_time:.2f} seconds, throughput: {throughput:.2f} sentences/second")
            logger.info(f"GPU status after batch processing: {profile_gpu()}")

            self.log_gpu_memory()
            self._reset_fallback_attempts()
            return similarity_scores

        except RuntimeError as e:
            logger.error(f"Error during batch calculation: {e}")
            self._fallback_to_cpu()
            return self.calculate_similarity_batch(sentence, sentences_list)

        finally:
            if acquired:
                release_gpu_lock()
            clear_gpu_cache()


    def clear_cache(self):
        """
        Pulisce la cache degli embeddings.
        """
        self.cached_sentence = None
        self.cached_embedding = None
        clear_gpu_cache()

    def update_batch_size(self, new_batch_size):
        """
        Aggiorna la dimensione del batch.
        """
        self.batch_size = new_batch_size
        logger.info(f"Batch size updated to {self.batch_size}.")

    def update_model(self, new_model_choice):
        """
        Aggiorna dinamicamente il modello AttackBERT.
        """
        model_dict = {
            'attackbert': 'basel/ATTACK-BERT'
        }
        if new_model_choice in model_dict:
            self.model_name = model_dict[new_model_choice]
            self.model = AutoModel.from_pretrained(self.model_name).to(self.device)
            self.invalidate_cache()
            logger.info(f"Model updated to '{self.model_name}'.")
        else:
            logger.error(f"Invalid model choice: {new_model_choice}")
