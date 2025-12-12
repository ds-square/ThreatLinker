from data.models import CVE, CAPEC, PreprocessedCAPEC
from core.models import Task, SingleCorrelation
from django.core.exceptions import ObjectDoesNotExist

from core.tasks.task_config import *
from core.preprocessing.text_preprocessing_service import preprocess_text
from core.similarity.sbert import SbertSimilarity
from core.similarity.attackbert import AttackBERTSimilarity
from core.similarity.keyword import KeywordSearchSimilarity
from core.tasks.gpu_functions import promote_to_gpu_in_redis
import logging


# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load the models

def load_models(ai_models, device):
    """
    Inizializza i modelli AI sul dispositivo specificato.
    :param ai_models: Lista di modelli AI da utilizzare.
    :param device: Dispositivo da utilizzare per i modelli ("cpu" o "cuda").
    :return: Lista di tuple (nome_modello, istanza_modello).
    """
    models = []
    for ai_model in ai_models:
        if ai_model == "SBERT":
            model_parameters = MODEL_PARAMETERS['SBERT'].copy()  # Copia per evitare modifiche accidentali globali
            model_parameters['initial_device'] = device  # Imposta il dispositivo specifico
            model_instance = SbertSimilarity(**model_parameters)
            models.append(('SBERT', model_instance))
            logger.info(f"Model SBERT initialized on device: {model_instance.device}")
        elif ai_model == "ATTACKBERT":
            model_parameters = MODEL_PARAMETERS['ATTACKBERT'].copy()  # Copia per evitare modifiche accidentali globali
            model_parameters['initial_device'] = device  # Imposta il dispositivo specifico
            model_instance = AttackBERTSimilarity(**model_parameters)
            models.append(('ATTACKBERT', model_instance))
            logger.info(f"Model ATTACKBERT initialized on device: {model_instance.device}")

    return models


# Load CAPECs

def load_capecs(capec_version):
    """
    Carica le CAPEC in base alla versione specificata, escludendo quelle con status "Deprecated".

    :param capec_version: Versione CAPEC da utilizzare.
    :return: QuerySet delle CAPEC da elaborare.
    """
    if capec_version != "default":
        # Filtra PreprocessedCAPEC con original_capec che non hanno status "Deprecated"
        capecs = PreprocessedCAPEC.objects.filter(
            preprocessed_version=capec_version
        ).exclude(original_capec__status="Deprecated")
    else:
        # Filtra CAPEC con status diverso da "Deprecated"
        capecs = CAPEC.objects.exclude(status="Deprecated")
    
    logger.info(f"Loaded {len(capecs)} CAPEC entries for version {capec_version}.")
    return capecs

def initialize_keyword_model():
    """
    Inizializza il modello KeywordSearchSimilarity.

    :return: Istanza del modello KeywordSearchSimilarity.
    :raises RuntimeError: Se l'inizializzazione del modello fallisce.
    """
    try:
        keyword_model = KeywordSearchSimilarity()
        logger.info("KeywordSearchSimilarity initialized successfully.")
        return keyword_model
    except Exception as e:
        logger.error(f"Error initializing KeywordSearchSimilarity: {e}")
        raise RuntimeError(f"Failed to initialize KeywordSearchSimilarity: {e}")


### Create SingleCorrelation

def create_single_correlation(cve_id, similarity_scores, task):
    """
    Crea una relazione di correlazione per una CVE con i risultati di similarità.

    :param cve_id: ID della CVE.
    :param similarity_scores: Risultati di similarità calcolati.
    :param task: Oggetto Task associato.
    :return: None.
    """
    try:
        SingleCorrelation.objects.create(
            cve_id=cve_id,
            hosts=get_cve_hosts(cve_id, task),
            similarity_scores=similarity_scores,
            status="complete",
            task=task
        )
        logger.info(f"SingleCorrelation created for CVE {cve_id}.")
    except Exception as e:
        logger.error(f"Error creating SingleCorrelation for CVE {cve_id}: {e}")
        raise

### Compare CVE with CAPECS for models

def get_cve_hosts(cve_id, task):
    """
    Recupera la lista dei valori associati a una specifica CVE (cve_id) 
    dal dizionario cve_hosts dell'oggetto Task fornito.

    :param cve_id: ID della CVE da cercare nel dizionario cve_hosts.
    :param task: Oggetto Task contenente il dizionario cve_hosts.
    :return: Lista di valori associati alla CVE se esiste, altrimenti None.
    :raises ValueError: Se cve_id non è valido o se cve_hosts non è un dizionario.
    :raises Exception: Per qualsiasi errore imprevisto.
    """
    try:
        # Validazione degli input
        if not cve_id or not isinstance(cve_id, str):
            raise ValueError("CVE ID must be a non-empty string.")
        if not task or not hasattr(task, 'cve_hosts'):
            raise ValueError("Task must be a valid object with a 'cve_hosts' attribute.")
        
        # Recupero del dizionario cve_hosts
        cve_hosts = task.cve_hosts
        if not isinstance(cve_hosts, dict):
            raise ValueError("The cve_hosts field must be a dictionary.")

        # Recupero dei valori associati alla CVE ID
        values = cve_hosts.get(cve_id, None)
        logger.info(f"Successfully retrieved values for CVE '{cve_id}' in Task: {values}.")
        return values

    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while retrieving CVE hosts: {e}")
        raise


### Preprocess CVE Description (cleaning text of CVE)

def preprocess_cve_description(cve_id, options):
    """
    Preprocessa una CVE: recupera la descrizione dal database, applica il TextCleaner e ritorna il testo pulito.

    :param cve_id: L'ID della CVE da elaborare.
    :param options: Opzioni per configurare il comportamento del TextCleaner.
    :return: Il testo della CVE pulito.
    :raises ValueError: Se la CVE non viene trovata, non ha descrizione o il preprocessing fallisce.
    """
    try:
        # Recupera la CVE dal database
        cve = CVE.objects.get(id=cve_id)
        logger.info(f"Successfully fetched CVE {cve_id}.")
    except CVE.DoesNotExist:
        logger.error(f"CVE with ID {cve_id} not found in the database.")
        raise ValueError(f"CVE con ID {cve_id} non trovata nel database.")

    # Verifica se la descrizione della CVE è presente
    if not cve.description or not cve.description.strip():
        logger.error(f"CVE {cve_id} has no valid description.")
        raise ValueError(f"CVE {cve_id} non ha una descrizione valida.")

    try:
        # Preprocessa il testo della CVE
        cleaned_description = preprocess_text(cve.description, options)
        logger.debug(f"CVE {cve_id} description preprocessed successfully: {cleaned_description[:100]}...")
        logger.debug(f"CVE {cve_id} Description Cleaned")
        logger.debug(f"{cleaned_description}")
        return cleaned_description
    except Exception as e:
        logger.error(f"Error during preprocessing of CVE {cve_id}: {e}")
        raise ValueError(f"Errore durante il preprocessing della CVE {cve_id}: {e}")

### Ranks Capecs for Keywords

def rank_capecs(capec_scores):
    """
    Ordina le CAPEC per 'final_score' in ordine decrescente e calcola i rank.

    :param capec_scores: Lista di CAPEC con i punteggi.
    :return: Lista di CAPEC ordinata e rankata.
    """
    try:
        # Ordina per final_score in ordine decrescente
        capec_ranked_scores = sorted(
            capec_scores,
            key=lambda x: float(x[1].get("final_score", 0)),
            reverse=True
        )

        # Aggiungi il rank
        for rank, (capec_id, score_data) in enumerate(capec_ranked_scores, start=1):
            score_data["rank"] = rank

        return capec_ranked_scores
    except Exception as e:
        logger.error(f"Error ranking CAPECs: {e}")
        return capec_scores

### CVE lists by Chunk of CVE
def filter_cve_by_chunk(cve_chunk):
    """
    Filtra le CVE dal database in base a un chunk di ID.

    :param cve_chunk: Lista di ID delle CVE da filtrare.
    :return: QuerySet di CVE corrispondenti al chunk fornito.
    :raises ValueError: Se il chunk è vuoto o non contiene CVE valide.
    """
    try:
        if not cve_chunk:
            raise ValueError("CVE chunk is empty. Cannot filter CVE.")

        # Filtra le CVE dal database
        cve_list = CVE.objects.filter(id__in=cve_chunk)
        if not cve_list.exists():
            raise ValueError(f"No CVEs found for the given chunk: {cve_chunk}")

        logger.info(f"Filtered {len(cve_list)} CVEs from the chunk: {cve_chunk}")
        return cve_list
    except Exception as e:
        logger.error(f"Error filtering CVEs by chunk: {e}")
        raise

### Reload models for using GPU/CPU

def reload_models(models, device):
    """
    Ricarica i modelli per il dispositivo specificato utilizzando le funzioni specifiche di ciascun modello.

    :param models: Lista di tuple (nome_modello, istanza_modello).
    :param device: Dispositivo target ("cpu" o "cuda").
    :return: Lista aggiornata di modelli caricati sul dispositivo.
    """
    try:
        updated_models = []
        for model_name, model_instance in models:
            try:
                # Verifica se il modello ha il metodo `reload_models_on_device`
                if hasattr(model_instance, 'reload_model_on_device'):
                    model_instance.reload_model_on_device(device)
                    logger.info(f"Model {model_name} reloaded on {device}.")
                else:
                    logger.warning(f"Model {model_name} does not support dynamic device reloading.")
                
                updated_models.append((model_name, model_instance))
            except Exception as e:
                logger.error(f"Error reloading model {model_name} on {device}: {e}")
                raise RuntimeError(f"Error reloading model {model_name} on {device}: {e}")

        return updated_models
    except Exception as e:
        logger.error(f"Error in reloading models on {device}: {e}")
        raise RuntimeError(f"Error in reloading models on {device}: {e}")

def promote_to_gpu_if_available(shared_state, gpu_id, models):
    """
    Controlla dinamicamente se promuovere l'elaborazione da CPU a GPU.
    Se disponibile, aggiorna il dispositivo nello shared_state e ricarica i modelli per la GPU.

    :param shared_state: Dizionario che contiene lo stato condiviso, incluso il dispositivo corrente.
    :param gpu_id: ID della GPU assegnata per il processo.
    :param models: Lista dei modelli attualmente caricati.
    :return: Lista dei modelli aggiornata, se promossi a GPU.
    """
    try:
        if shared_state["device"] == "cpu" and promote_to_gpu_in_redis(gpu_id):
            shared_state["device"] = "cuda"
            models = reload_models(models, shared_state["device"])  # Ricarica i modelli per GPU
            logger.info(f"Promoted to GPU with GPU ID: {gpu_id}.")
        return models
    except Exception as e:
        logger.error(f"Error during GPU promotion check: {e}")
        raise

