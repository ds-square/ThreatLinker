from celery import shared_task, chord
from debug.debug_utils import debug_print
import os
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from core.models import Task, SingleCorrelation
from data.models import CVE, CAPEC, PreprocessedCAPEC
from core.preprocessing.text_preprocessing_service import preprocess_text
from core.similarity.sbert import SbertSimilarity
from core.similarity.attackbert import AttackBERTSimilarity
from core.similarity.keyword import KeywordSearchSimilarity
from threatlinker.gpu.gpu_utils import clear_gpu_cache, profile_gpu
import logging


# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


NUM_PROCESSES = 4
IS_CORRELATION = True

MODEL_PARAMETERS = {
    'SBERT': {
        'model_choice': 'mpnet',
        'batch_size': 32,
        'lock_timeout': 10,
        'max_threads': 4,
    },
    'ATTACKBERT': {
        'model_choice': 'attackbert',
        'batch_size': 16,
        'lock_timeout': 10,
        'max_threads': 4,
        'max_length': 512,
    },
}


@shared_task
def manage_task_status(task_id, ai_models, preprocessing_options, capec_version):
    debug_print("INFO", f"Start manage_task_status for Task ID: {task_id} (PID: {os.getpid()})")
    try:
        task = Task.objects.get(id=task_id)
        debug_print("INFO", f"Task {task_id} loaded: {task}")
    except Task.DoesNotExist:
        debug_print("ERROR", f"Task ID {task_id} does not exist.")
        return "Task not found"

    task.status = "in_progress"
    task.save()
    debug_print("INFO", f"Task {task_id} status updated to 'in_progress'.")

    cve_ids = list(task.cve_hosts.keys())
    debug_print("INFO", f"Extracted CVE IDs for task: {cve_ids}")

    try:
        chunk_size = max(1, len(cve_ids) // NUM_PROCESSES)
        cve_chunks = [cve_ids[i:i + chunk_size] for i in range(0, len(cve_ids), chunk_size)]
        debug_print("INFO", f"CVE chunks created: {cve_chunks}")

        job = chord(
            (process_cve_block.s(chunk, task_id, preprocessing_options, capec_version, ai_models) for chunk in cve_chunks),
            complete_task_progress.s(task_id=task_id)
        )
        debug_print("INFO", "Chord job for CVE processing created.")
        job.apply_async()
        debug_print("INFO", "Chord job applied.")
        return task_id
    except Exception as e:
        debug_print("ERROR", f"Error during task management: {e}")
        return str(e)


@shared_task
def complete_task_progress(status, task_id):
    debug_print("INFO", f"Start complete_task_progress for Task ID: {task_id}, status: {status}")
    try:
        task = Task.objects.get(id=task_id)
        debug_print("INFO", f"Task {task_id} loaded: {task}")
    except Task.DoesNotExist:
        debug_print("ERROR", f"Task ID {task_id} does not exist.")
        return {"status": "failed", "error": "Task not found"}

    if task.check_task_completion():
        task.status = "complete"
        task.save()
        debug_print("INFO", f"Task {task_id} marked as complete.")
        return {"status": "completed", "task_id": task_id}
    else:
        task.status = "in_progress"
        task.save()
        debug_print("INFO", f"Task {task_id} still in progress.")
        return {"status": "in_progress", "task_id": task_id}


@shared_task
def process_cve_block(cve_chunk, task_id, preprocessing_options, capec_version, ai_models):
    debug_print("INFO", f"Start process_cve_block with chunk: {cve_chunk} (PID: {os.getpid()})")
    if not cve_chunk:
        debug_print("WARNING", "CVE chunk is empty. Skipping processing.")
        return {"status": "skipped"}

    try:
        task = Task.objects.get(id=task_id)
        debug_print("INFO", f"Task {task_id} loaded: {task}")
    except Task.DoesNotExist:
        debug_print("ERROR", f"Task ID {task_id} does not exist.")
        return "Task not found"

    cve_list = CVE.objects.filter(id__in=cve_chunk)
    debug_print("INFO", f"Found CVEs: {[cve.id for cve in cve_list]}")

    models = []
    for ai_model in ai_models:
        if ai_model == "SBERT":
            model_instance = SbertSimilarity(**MODEL_PARAMETERS['SBERT'])
            models.append(('SBERT', model_instance))
            logger.info(f"Model SBERT initialized on device: {model_instance.device}")

        elif ai_model == "ATTACKBERT":
            model_instance = AttackBERTSimilarity(**MODEL_PARAMETERS['ATTACKBERT'])
            models.append(('ATTACKBERT', model_instance))
            logger.info(f"Model ATTACKBERT initialized on device: {model_instance.device}")

    debug_print("INFO", f"Model {ai_model} initialized.")

    keyword_model = KeywordSearchSimilarity()
    debug_print("INFO", "KeywordSearchSimilarity initialized.")

    capecs_to_use = (PreprocessedCAPEC.objects.filter(preprocessed_version=capec_version)
                     if capec_version != "default" else CAPEC.objects.exclude(status="Deprecated"))
    debug_print("INFO", f"Using {len(capecs_to_use)} CAPEC entries.")

    for cve in cve_list:
        try:
            debug_print("INFO", f"Processing CVE {cve.id}")
            cleaned_cve_description = preprocess_cve_description(cve.id, preprocessing_options)
            debug_print("INFO", f"Cleaned CVE description for {cve.id}: {cleaned_cve_description[:100]}")

            similarity_results = {}
            for model_name, model_instance in models:
                debug_print("INFO", f"Using model {model_name} for CVE {cve.id}")
                similarity_results[model_name] = compare_cve_to_capec(cleaned_cve_description, capecs_to_use, model_name, model_instance)
                debug_print("INFO", f"Similarity results for model {model_name}: {similarity_results[model_name]}")

            keyword_scores = process_cve_keywords(keyword_model, cleaned_cve_description, capecs_to_use)
            debug_print("INFO", f"Keyword scores: {keyword_scores}")

            hybrid_results = integrate_keyword_scores(similarity_results, keyword_scores)
            debug_print("INFO", f"Hybrid similarity results: {hybrid_results}")

            SingleCorrelation.objects.create(
                cve_id=cve.id,
                similarity_scores=hybrid_results,
                status="complete",
                task=task
            )
            debug_print("INFO", f"SingleCorrelation created for CVE {cve.id}.")
        except Exception as e:
            debug_print("ERROR", f"Error processing CVE {cve.id}: {e}")
            continue

    clear_gpu_cache()
    debug_print("INFO", "GPU cache cleared.")
    return {"status": "processed"}


### Auxiliar Functions

def preprocess_cve_description(cve_id, options):
    """
    Preprocessa una CVE: recupera la descrizione dal database, applica il TextCleaner e ritorna il testo pulito.
    
    :param cve_id: L'ID della CVE da elaborare
    :param options: Opzioni per configurare il comportamento del TextCleaner
    :return: Il testo della CVE pulito
    """
    try:
        # Recupera la CVE dal database
        cve = CVE.objects.get(id=cve_id)
        debug_print("INFO", f"Successfully fetched CVE {cve_id}")
    except ObjectDoesNotExist:
        raise ValueError(f"CVE con ID {cve_id} non trovato nel database.")
    
    # Verifica se la descrizione della CVE è presente
    if not cve.description:
        raise ValueError(f"CVE {cve_id} non ha descrizione.")

    # Preprocessa il testo della CVE
    try:
        cleaned_description = preprocess_text(cve.description, options)
        debug_print("INFO", f"CVE {cve_id} description preprocessed successfully.")
    except Exception as e:
        raise ValueError(f"Errore durante il preprocessing della CVE {cve_id}: {e}")

    return cleaned_description


@shared_task
def process_cve_keywords(keyword_model, cleaned_cve_description, capecs_to_use):
    """
    Processa le CAPEC fornite utilizzando un modello di similarità basato su keyword.
    
    :param keyword_model: Modello per calcolare la similarità tra testo.
    :param cleaned_cve_description: Descrizione CVE preprocessata.
    :param capecs_to_use: Lista di CAPEC da analizzare.
    :return: Dizionario dei punteggi di similarità delle keyword per ciascuna CAPEC.
    """
    try:
        debug_print("INFO", f"Processing {len(capecs_to_use)} CAPECs...")
        keyword_similarity_scores = {}  # Dizionario per memorizzare i punteggi

        for capec in capecs_to_use:
            try:
                capec_id = capec.original_capec.id  # Usa l'ID della CAPEC per associare i punteggi
                debug_print("INFO", f"Processing CAPEC with ID {capec_id}...")

                # Default settings for keyword approach
                keyword_score = 0
                keyword_malus = False
                KEYWORD_MALUS_POINTS = 0.01

                # Inizializza un dizionario per questa CAPEC, se non esiste
                if capec_id not in keyword_similarity_scores:
                    keyword_similarity_scores[capec_id] = {}

                # Funzione per controllare se il campo è valido (non None e non vuoto)
                def is_valid_field(field):
                    return field is not None and field != ""

                # Controlla e processa i campi della CAPEC
                if is_valid_field(capec.name):
                    debug_print("INFO", f"Calculating keyword similarity for CAPEC name: {capec.name}")
                    keyword_score = keyword_model.calculate_similarity(capec.name, cleaned_cve_description)
                
                # Processa i termini alternativi della CAPEC, se presenti
                if is_valid_field(capec.alternate_terms):
                    for term in capec.alternate_terms:
                        try:
                            debug_print("DEBUG", f"Calculating keyword similarity for alternate term: {term}")
                            term_score = keyword_model.calculate_similarity(term, cleaned_cve_description)
                            keyword_score = max(keyword_score, term_score)
                        except Exception as e:
                            debug_print("ERROR", f"Error calculating similarity for term '{term}': {e}")
                
                # Applica penalità, se necessario
                if keyword_malus and keyword_score == 0:
                    keyword_score -= KEYWORD_MALUS_POINTS

                # Salva il punteggio arrotondato
                keyword_similarity_scores[capec_id]['keyword_score'] = round(keyword_score, 3)
                debug_print("INFO", f"Keyword similarity score for CAPEC {capec_id}: {round(keyword_score, 3)}")

            except Exception as capec_error:
                debug_print("ERROR", f"Error processing CAPEC with ID {capec_id}: {capec_error}")
                continue

        return keyword_similarity_scores

    except Exception as e:
        debug_print("CRITICAL", f"Error in process_cve_keywords: {e}")
        return {}

@shared_task
def integrate_keyword_scores(similarity_results, keyword_scores):
    """
    Integra i punteggi di keyword nei risultati di similarità e calcola i rank aggiornati.

    :param similarity_results: Dizionario con i risultati di similarità per ciascun modello.
        Esempio:
        {
            "SBERT": [
                ["CAPEC-217", {"final_score": 0.491, ...}],
                ["CAPEC-489", {"final_score": 0.46, ...}]
            ],
            ...
        }
    :param keyword_scores: Dizionario con i punteggi di keyword per ciascuna CAPEC.
        Esempio:
        {
            "CAPEC-10": {"keyword_score": 0.8},
            "CAPEC-20": {"keyword_score": 0.1}
        }
    :return: Dizionario aggiornato con i nuovi modelli "_keyword".
    """
    # Copia dei risultati per modificarli senza influenzare i dati originali
    updated_results = similarity_results.copy()

    for model_name, capec_scores in similarity_results.items():
        # Nome del nuovo modello con keyword
        keyword_model_name = f"{model_name}_keyword"
        updated_results[keyword_model_name] = []

        # Itera tutte le CAPEC nel modello attuale
        for capec_id, score_data in capec_scores:
            # Prendi il final_score dal modello originale
            original_final_score = score_data.get("final_score", 0)

            # Aggiungi il keyword_score se esiste
            keyword_score = keyword_scores.get(capec_id, {}).get("keyword_score", 0)
            combined_score = original_final_score + keyword_score

            # Crea il nuovo dato per il modello _keyword
            new_score_data = score_data.copy()
            new_score_data["final_score"] = round(combined_score, 3)  # Somma e arrotonda
            updated_results[keyword_model_name].append([capec_id, new_score_data])

        # Calcola i rank per il nuovo modello
        # Ordina i CAPECs per 'final_score' in ordine decrescente
        capec_ranked_scores = sorted(
            updated_results[keyword_model_name],
            key=lambda x: float(x[1].get("final_score", 0)),
            reverse=True
        )

        # Aggiungi il rank a ciascun CAPEC ordinato
        for rank, (capec_id, score_data) in enumerate(capec_ranked_scores, start=1):
            score_data["rank"] = rank

        # Aggiorna il modello con i CAPEC ordinati e rankati
        updated_results[keyword_model_name] = capec_ranked_scores

    return updated_results


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
    global IS_CORRELATION
    
    debug_print("INFO", f"Processing {len(capecs_to_use)} CAPECs...")
    for capec in capecs_to_use:
        capec_id = capec.original_capec.id  # Usa l'ID della CAPEC per associare i punteggi
        debug_print("INFO", f"Processing CAPEC with ID {capec_id}...")

        # Inizializza un dizionario per questa CAPEC, se non esiste
        if capec_id not in capec_similarity_scores:
            capec_similarity_scores[capec_id] = {}

        # Debug: Controlla il tipo di capec_similarity_scores[capec_id]
        debug_print("INFO", f"Type of capec_similarity_scores[{capec_id}]: {type(capec_similarity_scores[capec_id])}")

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
            debug_print("INFO", "Added 'name' field to aggregated fields.")
        if is_valid_field(capec.description_aggregated):
            capec_aggregated_fields.append(capec.description_aggregated)
            field_names.append('description')
            debug_print("INFO", "Added 'description' field to aggregated fields.")
        if is_valid_field(capec.extended_description_aggregated):
            capec_aggregated_fields.append(capec.extended_description_aggregated)
            field_names.append('extended_description')
            debug_print("INFO", "Added 'extended_description' field to aggregated fields.")
        if is_valid_field(capec.indicators_aggregated):
            capec_aggregated_fields.append(capec.indicators_aggregated)
            field_names.append('indicators')
            debug_print("INFO", "Added 'indicators' field to aggregated fields.")
        if is_valid_field(capec.prerequisites_aggregated):
            capec_aggregated_fields.append(capec.prerequisites_aggregated)
            field_names.append('prerequisites')
            debug_print("INFO", "Added 'prerequisites' field to aggregated fields.")
        if is_valid_field(capec.resources_required_aggregated):
            capec_aggregated_fields.append(capec.resources_required_aggregated)
            field_names.append('resources_required')
            debug_print("INFO", "Added 'resources_required' field to aggregated fields.")
        if is_valid_field(capec.mitigations_aggregated):
            capec_aggregated_fields.append(capec.mitigations_aggregated)
            field_names.append('mitigations')
            debug_print("INFO", "Added 'mitigations' field to aggregated fields.")
        if is_valid_field(capec.skills_required_aggregated):
            capec_aggregated_fields.append(capec.skills_required_aggregated)
            field_names.append('skills_required')
            debug_print("INFO", "Added 'skills_required' field to aggregated fields.")

        if IS_CORRELATION:
            if is_valid_field(capec.example_instances_aggregated):
                capec_aggregated_fields.append(capec.example_instances_aggregated)
                field_names.append('example_instances')
                debug_print("INFO", "Added 'example_instances' field to aggregated fields.")

        # 2. Preprocessamento della CVE (assumiamo che sia già preprocessata)
        preprocessed_cve_description = cleaned_cve_description
        debug_print("INFO", "CVE description preprocessed.")

        # 3. Calcola la similarità batch usando il modello AI con i campi aggregati
        debug_print("INFO", f"Calculating similarity using model {ai_model}...")
        gpu_status = profile_gpu()
        logger.info(f"GPU status before batch processing: {gpu_status}")
        similarity_scores = model.calculate_similarity_batch(preprocessed_cve_description, capec_aggregated_fields)
        gpu_status_after = profile_gpu()
        logger.info(f"GPU status after batch processing: {gpu_status_after}")
        debug_print("INFO", f"Similarity scores calculated for CAPEC {capec_id}.")
        
        # 5. Associare i punteggi di similarità ai nomi dei campi
        field_similarity = []
        for idx, score in enumerate(similarity_scores):
            field_similarity.append((field_names[idx], score))
        
        debug_print("INFO", f"Field_similarity: {field_similarity}")

        debug_print("INFO", "Similarity scores associated with field names.")

        # 1. Raccogli i campi di ExecutionFlow (PreprocessedAttackStep) se presenti
        executionflow_aggregated_fields = []  # Lista per i punteggi massimi
        executionflow_field_names = []  # Lista per i nomi dei campi
        executionflow_average_score = 0
        attack_description_list = []  # Lista per le description degli attack step
        attack_techniques_list = []  # Lista per le techniques degli attack step

        if capec.preprocessed_execution_flow:
            debug_print("INFO", f"Processing execution flow for CAPEC {capec_id}...")
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
                debug_print("INFO", "Calculating execution flow similarity...")
                gpu_status = profile_gpu()
                logger.info(f"GPU status before batch processing: {gpu_status}")
                attack_step_similarity_scores = model.calculate_similarity_batch(preprocessed_cve_description, execution_flow_combined_list)
                gpu_status_after = profile_gpu()
                logger.info(f"GPU status after batch processing: {gpu_status_after}")
                debug_print("INFO", "Execution flow similarity calculated.")

                # 3. Associare i punteggi di similarità ai nomi dei campi
                field_similarity_for_attack_steps = []

                # Prima aggiungiamo i nomi delle descrizioni
                for idx, score in enumerate(attack_step_similarity_scores[:len(attack_description_names)]):
                    field_similarity_for_attack_steps.append((attack_description_names[idx], score))

                # Poi aggiungiamo i nomi delle tecniche
                for idx, score in enumerate(attack_step_similarity_scores[len(attack_description_names):len(attack_description_names) + len(attack_technique_names)]):
                    field_similarity_for_attack_steps.append((attack_technique_names[idx], score))

                debug_print("INFO", "Similarity scores for attack steps calculated.")

                # Debug: Controlla il contenuto di field_similarity_for_attack_steps
                debug_print("INFO", f"field_similarity_for_attack_steps: {field_similarity_for_attack_steps}")
                debug_print("INFO", f"attack_step_count: {attack_step_count}")

                # 4. Calcola il punteggio massimo tra description e techniques per il passo d'attacco
                for i in range(attack_step_count):
                    attack_description_score = 0  # Imposta direttamente a 0
                    attack_techniques_score = 0  # Imposta direttamente a 0

                    # Debug: Mostra l'indice del passo d'attacco
                    debug_print("INFO", f"Processing attack step {i+1}...")

                    # Cerca i punteggi per description e techniques
                    for field_name, score in field_similarity_for_attack_steps:
                        # Debug: Mostra il campo e il punteggio che stai controllando
                        debug_print("INFO", f"Checking field: {field_name}, Score: {score}")
                        
                        if field_name == f'attack_step_{i+1}_description':
                            attack_description_score = score
                            debug_print("INFO", f"Set attack_description_score: {attack_description_score} for {field_name}")
                        if field_name == f'attack_step_{i+1}_techniques':
                            attack_techniques_score = score
                            debug_print("INFO", f"Set attack_techniques_score: {attack_techniques_score} for {field_name}")

                    # Calcola il massimo tra description e techniques per il passo d'attacco
                    max_score = max(attack_description_score, attack_techniques_score)

                    # Debug: Mostra il punteggio massimo calcolato
                    debug_print("INFO", f"Max score for attack step {i+1}: {max_score}")

                    # Memorizza il punteggio massimo
                    executionflow_aggregated_fields.append(max_score)
                    executionflow_field_names.append(f'attack_step_{i+1}_max_score')

            # Calcola la media dei punteggi aggregati
            if executionflow_aggregated_fields:
                executionflow_average_score = sum(executionflow_aggregated_fields) / len(executionflow_aggregated_fields)
                # Debug: Mostra la media dei punteggi aggregati
                debug_print("INFO", f"Execution flow average score: {executionflow_average_score}")


        # Aggiungi i punteggi per questa CAPEC al dizionario capec_similarity_scores
        for field_name, score in field_similarity:
            # Debug: Mostra i punteggi aggiunti per ogni campo
            debug_print("INFO", f"Adding score for field {field_name}: {score}")
            
            # Assicurati che capec_similarity_scores[capec_id] sia un dizionario
            if isinstance(capec_similarity_scores[capec_id], dict):
                capec_similarity_scores[capec_id][f'{field_name}_score'] = round(score, 3)
            else:
                debug_print("ERROR", f"capec_similarity_scores[capec_id] is not a dictionary for CAPEC {capec_id}")

        debug_print("INFO", f"Scores added for CAPEC {capec_id}.")

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

        # Debug: Stampa i risultati finali per ogni CAPEC
        debug_print("INFO", f"Results for CAPEC {capec_id}:")
        for field_name, score in capec_similarity_scores[capec_id].items():
            debug_print("INFO", f"  {field_name}: {score}")
            
    debug_print("INFO", "Finished processing CAPECs. Returning similarity scores.")
    
    # Ordina i CAPECs per 'final_score' in ordine decrescente
    capec_ranked_scores = sorted(capec_similarity_scores.items(), key=lambda x: float(x[1].get('final_score', 0)), reverse=True)
    
    # Aggiungi il rank a ciascun CAPEC ordinato
    for rank, (capec_id, score_data) in enumerate(capec_ranked_scores, start=1):
        score_data['rank'] = rank

    # Restituisci il dizionario capec_similarity_scores
    return capec_ranked_scores

