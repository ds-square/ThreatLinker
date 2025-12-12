from celery import shared_task
from core.tasks.process_utils import *
from core.tasks.task_utils import get_task_by_id
from core.tasks.task_config import *
from core.tasks.gpu_functions import *
from threatlinker.gpu.gpu_utils import clear_gpu_cache, profile_gpu

import threading
from queue import Queue

import logging
import os
import time

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@shared_task
def process_cve_block(cve_chunk, task_id, preprocessing_options, capec_version, ai_models, gpu_id):
    """
    Elabora un blocco di CVE.

    :param cve_chunk: Lista di CVE da processare.
    :param task_id: ID della task.
    :param preprocessing_options: Opzioni di preprocessing.
    :param capec_version: Versione CAPEC da utilizzare.
    :param ai_models: Lista di modelli AI da utilizzare.
    :param gpu_id: ID casuale del processo assegnato per identificare l'accesso a GPU.
    :return: Dizionario con lo stato del blocco.
    """
    pid = os.getpid()
    logger.info(f"[START] Process with PID {pid} and GPU ID: {gpu_id}")

    if not cve_chunk:
        logger.warning("CVE chunk is empty. Skipping processing.")
        return {"status": "skipped"}

    shared_state = {"device": "cpu"}
    acquired_gpu = False

    try:
        # Controlla se il gpu_id è negli slot GPU in Redis
        gpu_status = get_gpu_slots_status_in_redis()
        logger.info(f"GPU Status from Redis: {gpu_status}")
        if gpu_id in gpu_status["slots"]:
            shared_state["device"] = "cuda"
            acquired_gpu = True
            logger.info(f"Process {pid} with GPU ID {gpu_id} will use CUDA.")
            
            
        # Carica task e modelli
        task = get_task_by_id(task_id)
        models = load_models(ai_models, shared_state["device"])  # Carica i modelli sul dispositivo selezionato
        
        # Carica CAPEC
        capecs = load_capecs(capec_version)

        # Inizializza modello keyword
        keyword_model = initialize_keyword_model()

        # Elabora ciascuna CVE
        cve_list = filter_cve_by_chunk(cve_chunk)
        # Ciclo per elaborare ciascuna CVE
        for cve in cve_list:
            process_single_cve(cve, task, models, capecs, preprocessing_options, keyword_model, gpu_id, shared_state)

        # Pulizia GPU
        if shared_state["device"] == "cuda":
            acquired_gpu = True
            clear_gpu_cache()
            logger.info(f"Task {task_id} (PID: {pid}): Cleared GPU cache.")

        return {"status": "processed"}
    except Exception as e:
        logger.error(f"Error in process_cve_block: {e}")
        return {"status": "failed", "device": shared_state["device"], "error": str(e)}
    finally:
        # Rilascia lo slot GPU se acquisito
        if acquired_gpu:
            release_gpu_slot_in_redis(gpu_id)
            logger.info(f"Task {task_id} (PID: {pid}) released GPU slot in Redis.")


@shared_task
def process_single_cve(cve, task, models, capecs, preprocessing_options, keyword_model, gpu_id, shared_state):
    """
    Elabora una singola CVE: preprocessa, calcola le similarità, crea relazioni,
    e controlla dinamicamente se può essere promossa a GPU.

    :param cve: Oggetto CVE da elaborare.
    :param task: Oggetto Task associato.
    :param models: Lista di tuple (nome_modello, istanza_modello).
    :param capecs: QuerySet delle CAPEC.
    :param preprocessing_options: Opzioni di preprocessing.
    :param keyword_model: Modello per calcolare le similarità basate su keyword.
    :param gpu_id: Random ID assegnato per usare la GPU
    :param device: Dispositivo attualmente utilizzato ("cpu" o "cuda").
    :return: None.
    """
    pid = os.getpid()

    try:
        logger.info(f"Process PID: {pid}. Start processing CVE {cve.id} on {shared_state['device']}. Random GPU ID: {gpu_id}")

        models = promote_to_gpu_if_available(shared_state, gpu_id, models)

        # Preprocessing della descrizione della CVE
        cleaned_description = preprocess_cve_description(cve.id, preprocessing_options)
        logger.info(f"CVE {cve.id} description after preprocessing: {cleaned_description}")

        # Calcolo delle similarità per i modelli AI
        similarity_results = calculate_similarity_results(models, cleaned_description, capecs)
        logger.info(f"Similarity results for CVE {cve.id}: {similarity_results}")

        # Calcolo dei punteggi basati su keyword
        keyword_scores = process_cve_keywords(keyword_model, cleaned_description, capecs)
        logger.info(f"Keyword scores for CVE {cve.id}: {keyword_scores}")

        # Calcolo dei risultati ibridi
        hybrid_results = integrate_keyword_scores(similarity_results, keyword_scores)
        logger.info(f"Hybrid results calculated for CVE {cve.id}.")

        # Creazione della relazione nel database
        create_single_correlation(cve.id, hybrid_results, task)
        logger.info(f"SingleCorrelation created successfully for CVE {cve.id}.")

        # Restituisci il dispositivo attuale
        return {"status": "processed"}

    except Exception as e:
        logger.error(f"Error processing CVE {cve.id}: {e}")
        return {"status": "failed", "error": str(e)}


def calculate_similarity_results(models, cleaned_description, capecs):
    """
    Calcola i risultati di similarità per una descrizione di CVE rispetto alle CAPEC usando modelli AI.

    :param models: Lista di tuple (nome_modello, istanza_modello).
    :param cleaned_description: Descrizione preprocessata della CVE.
    :param capecs: QuerySet delle CAPEC.
    :return: Dizionario con i risultati di similarità per ciascun modello.
    """
    similarity_results = {}
    for model_name, model_instance in models:
        try:
            logger.info(f"Iterating {model_name} with {model_instance}")
            similarity_results[model_name] = compare_cve_to_capec(
                cleaned_description, capecs, model_name, model_instance
            )
            logger.info(f"Similarity results for model {model_name}: {similarity_results[model_name]}")
        except Exception as e:
            logger.error(f"Error calculating similarity with model {model_name}: {e}")
            similarity_results[model_name] = {"error": str(e)}
    return similarity_results

### Keyword Research

def process_cve_keywords(keyword_model, cleaned_cve_description, capecs_to_use):
    """
    Processa le CAPEC fornite utilizzando un modello di similarità basato su keyword.

    :param keyword_model: Modello per calcolare la similarità tra testo.
    :param cleaned_cve_description: Descrizione CVE preprocessata.
    :param capecs_to_use: Lista di CAPEC da analizzare.
    :return: Dizionario dei punteggi di similarità delle keyword per ciascuna CAPEC.
    """
    def is_valid_field(field):
        """Verifica se un campo è valido (non None e non vuoto)."""
        return field is not None and field != ""

    try:
        #logger.info(f"Processing {len(capecs_to_use)} CAPECs for keyword similarity.")
        keyword_similarity_scores = {}

        for capec in capecs_to_use:
            try:
                capec_id = capec.original_capec.id  # Usa l'ID della CAPEC per i punteggi
                #logger.info(f"Processing CAPEC with ID {capec_id}.")

                # Inizializza punteggio e struttura
                keyword_score = 0
                KEYWORD_MALUS_POINTS = 0.01
                keyword_similarity_scores.setdefault(capec_id, {})

                # Calcola la similarità per i campi principali della CAPEC
                if is_valid_field(capec.name):
                    #logger.info(f"Calculating keyword similarity for CAPEC name: {capec.name}")
                    keyword_score = max(keyword_score, keyword_model.calculate_similarity(capec.name, cleaned_cve_description))

                # Calcola la similarità per i termini alternativi, se presenti
                if is_valid_field(capec.alternate_terms):
                    for term in capec.alternate_terms:
                        try:
                            #logger.info(f"Calculating keyword similarity for alternate term: {term}")
                            term_score = keyword_model.calculate_similarity(term, cleaned_cve_description)
                            keyword_score = max(keyword_score, term_score)
                        except Exception as e:
                            logger.warning(f"Error calculating similarity for term '{term}': {e}")

                # Applica una penalità se il punteggio è zero
                if keyword_score == 0:
                    keyword_score -= KEYWORD_MALUS_POINTS

                # Salva il punteggio arrotondato
                keyword_similarity_scores[capec_id]['keyword_score'] = round(keyword_score, 3)
                #logger.info(f"Keyword similarity score for CAPEC {capec_id}: {round(keyword_score, 3)}")

            except Exception as capec_error:
                logger.error(f"Error processing CAPEC with ID {capec_id}: {capec_error}")
                continue

        return keyword_similarity_scores

    except Exception as e:
        logger.critical(f"Critical error in process_cve_keywords: {e}")
        return {}


def integrate_keyword_scores(similarity_results, keyword_scores):
    """
    Integra i punteggi di keyword nei risultati di similarità e calcola i rank aggiornati.

    :param similarity_results: Dizionario con i risultati di similarità per ciascun modello.
    :param keyword_scores: Dizionario con i punteggi di keyword per ciascuna CAPEC.
    :return: Dizionario aggiornato con i nuovi modelli "_keyword".
    """
    try:
        #logger.info("Integrating keyword scores with similarity results.")
        updated_results = similarity_results.copy()

        for model_name, capec_scores in similarity_results.items():
            # Nome del nuovo modello con keyword
            keyword_model_name = f"{model_name}_keyword"
            updated_results[keyword_model_name] = []

            for capec_id, score_data in capec_scores:
                try:
                    # Prendi il punteggio originale
                    original_final_score = score_data.get("final_score", 0)

                    # Integra il keyword score
                    keyword_score = keyword_scores.get(capec_id, {}).get("keyword_score", 0)
                    combined_score = original_final_score + keyword_score

                    # Crea il nuovo dizionario per il modello _keyword
                    new_score_data = score_data.copy()
                    new_score_data["final_score"] = round(combined_score, 3)
                    updated_results[keyword_model_name].append([capec_id, new_score_data])
                except Exception as e:
                    logger.error(f"Error integrating scores for CAPEC {capec_id}: {e}")
                    continue

            # Ordina e calcola i rank per il nuovo modello
            updated_results[keyword_model_name] = rank_capecs(updated_results[keyword_model_name])

        #logger.info("Keyword scores successfully integrated.")
        return updated_results
    except Exception as e:
        logger.critical(f"Critical error in integrate_keyword_scores: {e}")
        return {}

### Compare Single CVE with Capecs

@shared_task
def compare_cve_to_capec(cleaned_cve_description, capecs_to_use, ai_model, model):
    """
    Confronta una descrizione di una CVE con un CAPEC, utilizzando modelli AI per calcolare la similarità.

    :param cleaned_cve_description: La descrizione della CVE preprocessata.
    :param capec: L'oggetto CAPEC da confrontare con la CVE.
    :param ai_model: Il modello AI da utilizzare per il confronto (ad esempio 'SBERT' o 'ATTACKBERT').

    :return: Un dizionario contenente i punteggi di similarità per ogni CAPEC.
    """
    
    capec_similarity_scores = {}  # Dizionario per memorizzare i punteggi di tutte le CAPEC

    for capec in capecs_to_use:
        
        capec_id = capec.original_capec.id  # Usa l'ID della CAPEC per associare i punteggi
        
        # Inizializza un dizionario per questa CAPEC, se non esiste
        if capec_id not in capec_similarity_scores:
            capec_similarity_scores[capec_id] = {}

        # 1. Estrai tutti i campi aggregati da CAPEC in una lista (esclusi quelli non validi)
        capec_aggregated_fields = []
        field_names = []

        # Funzione per controllare se il campo è valido (non None e non vuoto)
        def is_valid_field(field):
            return field is not None and field != ""

        # Aggiungi i campi validi a capec_aggregated_fields e aggiorna i field_names
        if is_valid_field(capec.name):
            capec_aggregated_fields.append(capec.name)
            field_names.append('name')
        if is_valid_field(capec.description_aggregated):
            capec_aggregated_fields.append(capec.description_aggregated)
            field_names.append('description')                
        if is_valid_field(capec.prerequisites_aggregated):
            capec_aggregated_fields.append(capec.prerequisites_aggregated)
            field_names.append('prerequisites')           
        if is_valid_field(capec.resources_required_aggregated):
            capec_aggregated_fields.append(capec.resources_required_aggregated)
            field_names.append('resources_required')            
        if is_valid_field(capec.mitigations_aggregated):
            capec_aggregated_fields.append(capec.mitigations_aggregated)
            field_names.append('mitigations')           
        if is_valid_field(capec.skills_required_aggregated):
            capec_aggregated_fields.append(capec.skills_required_aggregated)
            field_names.append('skills_required')
        
        #if IS_CORRELATION and is_valid_field(capec.extended_description_aggregated):
            #capec_aggregated_fields.append(capec.extended_description_aggregated)
            #field_names.append('extended_description')       
        #if IS_CORRELATION and is_valid_field(capec.indicators_aggregated):
            #capec_aggregated_fields.append(capec.indicators_aggregated)
            #field_names.append('indicators')  
        #if IS_CORRELATION and is_valid_field(capec.example_instances_aggregated):
            #capec_aggregated_fields.append(capec.example_instances_aggregated)
            #field_names.append('example_instances')
                
        # 2. Preprocessamento della CVE (assumiamo che sia già preprocessata)
        preprocessed_cve_description = cleaned_cve_description
        
        # 3. Calcola la similarità batch usando il modello AI con i campi aggregati
        
        #gpu_status = profile_gpu()
        #logger.info(f"GPU status before batch processing: {gpu_status}")
        similarity_scores = model.calculate_similarity_batch(preprocessed_cve_description, capec_aggregated_fields)
        #gpu_status_after = profile_gpu()
        #logger.info(f"GPU status after batch processing: {gpu_status_after}")
        
        # 5. Associare i punteggi di similarità ai nomi dei campi
        field_similarity = []
        for idx, score in enumerate(similarity_scores):
            field_similarity.append((field_names[idx], score))

        # 1. Raccogli i campi di ExecutionFlow (PreprocessedAttackStep) se presenti
        executionflow_aggregated_fields = []  # Lista per i punteggi massimi
        executionflow_field_names = []  # Lista per i nomi dei campi
        executionflow_average_score = 0
        attack_description_list = []  # Lista per le description degli attack step
        attack_techniques_list = []  # Lista per le techniques degli attack step

        if capec.preprocessed_execution_flow:         
            attack_step_count = 0
            attack_description_names = []
            attack_technique_names = []
        
            for idx, attack_step in enumerate(capec.preprocessed_execution_flow.preprocessed_attack_steps.all()):
                description_valid = is_valid_field(attack_step.description_aggregated)
                techniques_valid = is_valid_field(attack_step.techniques_aggregated)
                
                if description_valid or techniques_valid:
                    attack_step_count += 1
                    # Aggiungi alla lista per la comparazione batch
                    if description_valid:
                        attack_description_list.append(attack_step.description_aggregated)
                        attack_description_names.append(f'attack_step_{idx+1}_description')
                    if techniques_valid:
                        attack_techniques_list.append(attack_step.techniques_aggregated)
                        attack_technique_names.append(f'attack_step_{idx+1}_techniques')

            # 2. Esegui la comparazione batch per description e techniques insieme
            if attack_step_count > 0:
                execution_flow_combined_list = attack_description_list + attack_techniques_list
                
                #gpu_status = profile_gpu()
                #logger.info(f"GPU status before batch processing: {gpu_status}")
                attack_step_similarity_scores = model.calculate_similarity_batch(preprocessed_cve_description, execution_flow_combined_list)
                #gpu_status_after = profile_gpu()
                #logger.info(f"GPU status after batch processing: {gpu_status_after}")
                
                # 3. Associare i punteggi di similarità ai nomi dei campi
                field_similarity_for_attack_steps = []

                # Prima aggiungiamo i nomi delle descrizioni
                for idx, score in enumerate(attack_step_similarity_scores[:len(attack_description_names)]):
                    field_similarity_for_attack_steps.append((attack_description_names[idx], score))

                # Poi aggiungiamo i nomi delle tecniche
                for idx, score in enumerate(attack_step_similarity_scores[len(attack_description_names):len(attack_description_names) + len(attack_technique_names)]):
                    field_similarity_for_attack_steps.append((attack_technique_names[idx], score))

                for i in range(attack_step_count):
                    attack_description_score = 0  # Imposta direttamente a 0
                    attack_techniques_score = 0  # Imposta direttamente a 0

                    for field_name, score in field_similarity_for_attack_steps:
                        if field_name == f'attack_step_{i+1}_description':
                            attack_description_score = score                         
                        if field_name == f'attack_step_{i+1}_techniques':
                            attack_techniques_score = score
                            
                    # Calcola il massimo tra description e techniques per il passo d'attacco
                    max_score = max(attack_description_score, attack_techniques_score)

                    # Memorizza il punteggio massimo
                    executionflow_aggregated_fields.append(max_score)
                    executionflow_field_names.append(f'attack_step_{i+1}_max_score')

            # Calcola la media dei punteggi aggregati
            if executionflow_aggregated_fields:
                executionflow_average_score = sum(executionflow_aggregated_fields) / len(executionflow_aggregated_fields)

        # Aggiungi i punteggi per questa CAPEC al dizionario capec_similarity_scores
        for field_name, score in field_similarity:

            # Assicurati che capec_similarity_scores[capec_id] sia un dizionario
            if isinstance(capec_similarity_scores[capec_id], dict):
                capec_similarity_scores[capec_id][f'{field_name}_score'] = round(score, 3)        
                
        # Aggiungi il punteggio massimo (execution_flow_score) per questa CAPEC
        if executionflow_average_score:
            capec_similarity_scores[capec_id]['execution_flow_score'] = executionflow_average_score

        # Aggiungi il punteggio finale per la CAPEC (media di tutti i punteggi)
        if capec_similarity_scores[capec_id]:
            total_score = sum(capec_similarity_scores[capec_id].values())  # Somma tutti i punteggi
            total_count = len(capec_similarity_scores[capec_id])  # Conta quanti punteggi ci sono
            final_score = total_score / total_count  # Calcola il punteggio medio finale

            # Aggiungi il punteggio medio finale
            capec_similarity_scores[capec_id]['final_score'] = round(final_score, 3)
  
    # Ordina i CAPECs per 'final_score' in ordine decrescente
    capec_ranked_scores = sorted(capec_similarity_scores.items(), key=lambda x: float(x[1].get('final_score', 0)), reverse=True)
    
    # Aggiungi il rank a ciascun CAPEC ordinato
    for rank, (capec_id, score_data) in enumerate(capec_ranked_scores, start=1):
        score_data['rank'] = rank

    # Restituisci il dizionario capec_similarity_scores
    return capec_ranked_scores


### Compare single CVE with CAPECS (Threads)

def compare_cve_to_capec_threads(cleaned_cve_description, capecs_to_use, ai_model, model, max_threads=4):
    """
    Confronta una descrizione di una CVE con un CAPEC, utilizzando modelli AI per calcolare la similarità.
    Il calcolo avviene con threading per parallelizzare le operazioni mantenendo l'intera logica.

    :param cleaned_cve_description: La descrizione preprocessata della CVE.
    :param capecs_to_use: QuerySet o lista di CAPEC da confrontare.
    :param ai_model: Nome del modello AI (es. SBERT, ATTACKBERT).
    :param model: Istanza del modello AI.
    :param max_threads: Numero massimo di thread da utilizzare.
    :return: Dizionario contenente i punteggi di similarità per ogni CAPEC.
    """
    capec_similarity_scores = {}
    lock = threading.Lock()
    task_queue = Queue()

    def process_capec(capec):
        """
        Processa una singola CAPEC, calcolando la similarità per campi aggregati e ExecutionFlow.
        """
        try:
            capec_id = capec.original_capec.id

            with lock:
                if capec_id not in capec_similarity_scores:
                    capec_similarity_scores[capec_id] = {}

            capec_aggregated_fields = []
            field_names = []

            def is_valid_field(field):
                return field is not None and field.strip() != ""

            if is_valid_field(capec.name):
                capec_aggregated_fields.append(capec.name)
                field_names.append("name")
            if is_valid_field(capec.description_aggregated):
                capec_aggregated_fields.append(capec.description_aggregated)
                field_names.append("description")
            if IS_CORRELATION and is_valid_field(capec.extended_description_aggregated):
                capec_aggregated_fields.append(capec.extended_description_aggregated)
                field_names.append("extended_description")
            if IS_CORRELATION and is_valid_field(capec.indicators_aggregated):
                capec_aggregated_fields.append(capec.indicators_aggregated)
                field_names.append("indicators")
            if is_valid_field(capec.prerequisites_aggregated):
                capec_aggregated_fields.append(capec.prerequisites_aggregated)
                field_names.append("prerequisites")
            if is_valid_field(capec.resources_required_aggregated):
                capec_aggregated_fields.append(capec.resources_required_aggregated)
                field_names.append("resources_required")
            if is_valid_field(capec.mitigations_aggregated):
                capec_aggregated_fields.append(capec.mitigations_aggregated)
                field_names.append("mitigations")
            if is_valid_field(capec.skills_required_aggregated):
                capec_aggregated_fields.append(capec.skills_required_aggregated)
                field_names.append("skills_required")
            if IS_CORRELATION and is_valid_field(capec.example_instances_aggregated):
                capec_aggregated_fields.append(capec.example_instances_aggregated)
                field_names.append("example_instances")

            similarity_scores = model.calculate_similarity_batch(
                cleaned_cve_description, capec_aggregated_fields
            )
            field_similarity = {
                field_names[i]: similarity_scores[i] for i in range(len(similarity_scores))
            }

            # 1. Raccogli i campi di ExecutionFlow (PreprocessedAttackStep) se presenti
            executionflow_aggregated_fields = []  # Lista per i punteggi massimi
            executionflow_field_names = []  # Lista per i nomi dei campi
            executionflow_average_score = 0
            attack_description_list = []  # Lista per le description degli attack step
            attack_techniques_list = []  # Lista per le techniques degli attack step

            if capec.preprocessed_execution_flow:
                attack_step_count = 0
                attack_description_names = []
                attack_technique_names = []
                
                for idx, attack_step in enumerate(capec.preprocessed_execution_flow.preprocessed_attack_steps.all()):
                    description_valid = is_valid_field(attack_step.description_aggregated)
                    techniques_valid = is_valid_field(attack_step.techniques_aggregated)
                    
                    if description_valid or techniques_valid:
                        attack_step_count += 1
                        if description_valid:
                            attack_description_list.append(attack_step.description_aggregated)
                            attack_description_names.append(f'attack_step_{idx+1}_description')
                        if techniques_valid:
                            attack_techniques_list.append(attack_step.techniques_aggregated)
                            attack_technique_names.append(f'attack_step_{idx+1}_techniques')

                # 2. Esegui la comparazione batch per description e techniques insieme
                if attack_step_count > 0:
                    execution_flow_combined_list = attack_description_list + attack_techniques_list
                    attack_step_similarity_scores = model.calculate_similarity_batch(cleaned_cve_description, execution_flow_combined_list)

                    # 3. Associare i punteggi di similarità ai nomi dei campi
                    field_similarity_for_attack_steps = []

                    # Prima aggiungiamo i nomi delle descrizioni
                    for idx, score in enumerate(attack_step_similarity_scores[:len(attack_description_names)]):
                        field_similarity_for_attack_steps.append((attack_description_names[idx], score))

                    # Poi aggiungiamo i nomi delle tecniche
                    for idx, score in enumerate(attack_step_similarity_scores[len(attack_description_names):len(attack_description_names) + len(attack_technique_names)]):
                        field_similarity_for_attack_steps.append((attack_technique_names[idx], score))

                    # 4. Calcola il punteggio massimo tra description e techniques per il passo d'attacco
                    for i in range(attack_step_count):
                        attack_description_score = 0  # Imposta direttamente a 0
                        attack_techniques_score = 0  # Imposta direttamente a 0

                        # Cerca i punteggi per description e techniques
                        for field_name, score in field_similarity_for_attack_steps:                         
                            if field_name == f'attack_step_{i+1}_description':
                                attack_description_score = score
                            if field_name == f'attack_step_{i+1}_techniques':
                                attack_techniques_score = score
                                
                        # Calcola il massimo tra description e techniques per il passo d'attacco
                        max_score = max(attack_description_score, attack_techniques_score)

                        # Memorizza il punteggio massimo
                        executionflow_aggregated_fields.append(max_score)
                        executionflow_field_names.append(f'attack_step_{i+1}_max_score')

                # Calcola la media dei punteggi aggregati
                if executionflow_aggregated_fields:
                    field_similarity["execution_flow_score"]  = round(sum(executionflow_aggregated_fields) / len(executionflow_aggregated_fields), 3)

            # Calcolo del final_score
            all_scores = list(field_similarity.values())
            if "execution_flow_score" in field_similarity:
                all_scores.append(field_similarity["execution_flow_score"])

            final_score = sum(all_scores) / len(all_scores) if all_scores else 0
            field_similarity["final_score"] = round(final_score, 3)

            # Aggiorna i risultati nel dizionario thread-safe
            with lock:
                capec_similarity_scores[capec_id] = field_similarity

        except Exception as e:
            logger.error(f"Error processing CAPEC {capec.original_capec.id}: {e}")

    def worker():
        """
        Funzione worker per elaborare le CAPEC dalla coda.
        """
        while not task_queue.empty():
            capec = task_queue.get()
            process_capec(capec)
            task_queue.task_done()

    # Riempie la coda con le CAPEC
    for capec in capecs_to_use:
        task_queue.put(capec)

    # Avvia i thread
    threads = []
    for _ in range(min(max_threads, len(capecs_to_use))):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Attende il completamento di tutti i thread
    for thread in threads:
        thread.join()

    # Ordina i risultati e assegna i rank
    capec_ranked_scores = sorted(
        capec_similarity_scores.items(),
        key=lambda x: x[1].get("final_score", 0),
        reverse=True
    )
    for rank, (capec_id, score_data) in enumerate(capec_ranked_scores, start=1):
        score_data["rank"] = rank

    return capec_similarity_scores
