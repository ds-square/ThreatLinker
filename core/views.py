# Create your views here.
import cProfile
import io
from pstats import Stats

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.db import connection
from django.core.cache import cache
import json

from data.models import CVE, CAPEC
from core.models import Task, GroundTruth

from core.similarity.similarity_service import calculate_similarity_scores, get_available_similarity_methods
from core.preprocessing.text_preprocessing_service import preprocess_text
from core.correlation.correlation_service import extract_valid_cves
from core.correlation.correlation_task_service import create_correlation_task_structure, create_groundtruth_task_structure

from core.generator.generate_graphs import analyze_task_with_groundtruth, model_recursive_k_recall, model_recursive_k_precision, calculate_mrr, calculate_f1_recursive_k, calculate_mrr_recursive_k, calculate_ndcg_recursive_k, calculate_coverage
from core.generator.generate_top_capecs import create_excel_with_task_hosts
from core.generator.generate_groundtruth import create_groundtruth_excel

### Text Similarity Functions

def text_similarity(request):
    """
    Visualizza il form per inserire le frasi da confrontare.
    """
    return render(request, 'core/text/text_similarity.html')

def text_similarity_result(request):
    """
    Calcola la similarità tra le due frasi utilizzando i modelli disponibili e visualizza i risultati.
    """
    if request.method == 'POST':
        sentence1 = request.POST.get('sentence1')
        sentence2 = request.POST.get('sentence2')

        # Calcola la similarità utilizzando il servizio
        scores = calculate_similarity_scores(sentence1, sentence2)

        # Passa i risultati alla template per la visualizzazione
        context = {
            'sentence1': sentence1,
            'sentence2': sentence2,
            'sbert_score': scores['sbert_score'],
            'attackbert_score': scores['attackbert_score']
        }
        return render(request, 'core/text/text_similarity_results.html', context)
    else:
        # Se non si usa POST, reindirizza alla pagina del form
        return redirect('core:text_similarity')

### Text Preprocessing

def text_preprocessing(request):
    """
    Visualizza il form per inserire la frase e selezionare le opzioni di preprocessing.
    """
    return render(request, 'core/text/text_preprocessing.html')

def text_preprocessing_results(request):
    """
    Esegue il preprocessing del testo e visualizza il risultato.
    """
    if request.method == 'POST':
        sentence = request.POST.get('sentence')

        # Ottieni le opzioni selezionate dall'utente come True o False
        options = {
            'lowercase': request.POST.get('lowercase') == 'on',
            'remove_space_newline': request.POST.get('remove_space_newline') == 'on',
            'remove_punctuation': request.POST.get('remove_punctuation') == 'on',
            'remove_digits': request.POST.get('remove_digits') == 'on',
            'remove_links': request.POST.get('remove_links') == 'on',
            'remove_dates': request.POST.get('remove_dates') == 'on',
            'remove_parentheses_content': request.POST.get('remove_parentheses_content') == 'on',
            'remove_consecutive_repeat': request.POST.get('remove_consecutive_repeat') == 'on',
            'remove_special_characters': request.POST.get('remove_special_characters') == 'on',
            'expand_contractions': request.POST.get('expand_contractions') == 'on',
            'genitive': request.POST.get('genitive') == 'on',
            'remove_file_names': request.POST.get('remove_file_names') == 'on',
            'remove_stop_words': request.POST.get('remove_stop_words') == 'on',
            'lemmatize': request.POST.get('lemmatize') == 'on',
        }

        # Preprocessa il testo
        processed_text = preprocess_text(sentence, options)

        context = {
            'original_sentence': sentence,
            'processed_text': processed_text,
            'options': options,
        }
        return render(request, 'core/text/text_preprocessing_results.html', context)
    else:
        return redirect('core:text_preprocessing')
    
### Tasks

def tasks_list(request):
    tasks = Task.objects.all()  # Recupera tutte le Task
    return render(request, 'core/tasks/tasks_list.html', {'tasks': tasks})

def task_detail(request, task_id):
    # Recupera la task specifica
    task = get_object_or_404(Task, id=task_id)

    # Recupera tutte le SingleCorrelations associate a questa task
    correlations = task.single_correlations.all()
    single_correlations_count = task.single_correlations.count()  # Relazione inversa predefinita

    # Creiamo un dizionario per associare gli hosts con le CVE
    hosts_with_cves = {}
    for correlation in correlations:
        cve = CVE.objects.get(id=correlation.cve_id)  # Recupera il CVE con cve_id
        hosts = task.cve_hosts.get(correlation.cve_id, [])  # Ottieni gli hosts associati alla CVE
        for host in hosts:
            if host not in hosts_with_cves:
                hosts_with_cves[host] = []
            hosts_with_cves[host].append({
                'correlation': correlation,
                'cve': cve
            })

    # Ordina le CVE per ogni host in base all'anno
    for host in hosts_with_cves:
        hosts_with_cves[host].sort(key=lambda item: int(item['cve'].id.split('-')[1]))  # Ordina per anno (YYYY)

    context = {
        'task': task,
        'hosts_with_cves': hosts_with_cves,
        'single_correlations_count': single_correlations_count
    }

    return render(request, 'core/tasks/task_detail.html', context)

# Vista per eliminare una Task
def delete_task(request, task_id):
    if request.method == 'POST':
        try:
            task = Task.objects.get(id=task_id)
            # Ora puoi eliminare la Task
            task.delete()
            return redirect('core:tasks_list')  # Redirect alla lista delle task
        except Task.DoesNotExist:
            return HttpResponse("Task not found", status=404)
    else:
        return HttpResponse("Invalid request method", status=400)

import cProfile
import io
from pstats import Stats
from django.core.cache import cache
from django.db import connection
from django.shortcuts import get_object_or_404, render
from core.models import Task, SingleCorrelation
from data.models import CVE, CAPEC
import logging

# Configura il logger
logger = logging.getLogger(__name__)

def single_correlation_detail(request, task_id, cve_id):
    """
    Vista per mostrare i dettagli di una singola correlazione.
    Include strumenti di debug per identificare colli di bottiglia nelle query.
    """
    # Inizia il profiling
    profiler = cProfile.Profile()
    profiler.enable()

    # Misura il tempo totale della vista
    from time import time
    start_time = time()

    # Recupera la task e la CVE specifica
    task_start = time()
    task = get_object_or_404(Task, id=task_id)
    cve = get_object_or_404(CVE, id=cve_id)
    logger.info(f"Task and CVE retrieval took {time() - task_start:.4f} seconds")

    # Recupera la SingleCorrelation per questa CVE
    correlation_start = time()
    correlation = task.single_correlations.get(cve_id=cve.id)
    logger.info(f"SingleCorrelation retrieval took {time() - correlation_start:.4f} seconds")

    # Recupera i similarity_scores dalla correlation
    scores_start = time()
    similarity_scores = correlation.similarity_scores
    logger.info(f"Similarity scores retrieval took {time() - scores_start:.4f} seconds")

    # Creiamo la lista dei modelli utilizzati (dalle chiavi di similarity_scores)
    model_names = list(similarity_scores.keys())

    # Recupera tutti gli oggetti CAPEC dal database (usando la cache)
    # Recupera solo ID e nome delle CAPEC (usando la cache se disponibile)
    capecs = cache.get('capec_dict')
    if not capecs:
        capec_query = CAPEC.objects.exclude(status='Deprecated').values('id', 'name')
        capecs = {capec['id']: {'name': capec['name']} for capec in capec_query}
        cache.set('capec_dict', capecs, 60 * 60)  # Cache per 1 ora
        logging.info("CAPEC dictionary loaded from database and cached")
    else:
        logging.info("CAPEC dictionary loaded from cache")

    # Stampa tutte le query SQL eseguite
    logger.info("Executed SQL queries:")
    for query in connection.queries:
        logger.info(f"QUERY: {query['sql']} - TIME: {query['time']} seconds")

    # Passa i dati al template
    context = {
        'task': task,
        'cve': cve,
        'correlation': correlation,
        'model_names': model_names,
        'modelName_ordered_scores': similarity_scores,
        'capecs': capecs,  # Passiamo la lista completa dei CAPEC al template
    }

    # Termina il profiling
    profiler.disable()

    # Stampa il risultato del profiling
    s = io.StringIO()
    stats = Stats(profiler, stream=s).sort_stats('time')  # Ordina per tempo
    stats.print_stats(20)  # Mostra le prime 20 funzioni
    logger.info("Profiling results:\n" + s.getvalue())

    # Logga il tempo totale della vista
    logger.info(f"Total view time: {time() - start_time:.4f} seconds")

    return render(request, 'core/tasks/single_correlation_detail.html', context)


### Correlations

def correlation_make_request(request):
    if request.method == 'POST':
        # Ottieni la lista di CVE dall'input manuale o dal file
        cve_list_input = request.POST.get('cve_list', '')
        cve_list = [cve.strip() for cve in cve_list_input.split(',')]
        input_data = request.FILES['file'] if 'file' in request.FILES else cve_list
        
        # Estrai i dati validi delle CVE
        result = extract_valid_cves(input_data)

        # Ottieni i metodi di similarità selezionati
        selected_methods = request.POST.getlist('similarity_methods')

        # Modifica hosts per evitare il problema di serializzazione (convertendo i set in liste)
        hosts = result.get('hosts')
        if isinstance(hosts, dict):
            # Trasforma ogni set in lista
            hosts = {host: list(cves) for host, cves in hosts.items()}

        # Memorizza i dati nella sessione
        request.session['hosts'] = hosts
        request.session['similarity_methods'] = selected_methods

        # Passa i dati al template
        return render(request, 'core/correlation/correlation_request_summary.html', {
            'cve_count': result['total_count'],
            'cve_list': list(result['cves']),
            'selected_similarity_methods': selected_methods,
            'hosts': hosts  # Ora hosts è un dizionario con liste di CVE
        })

    # Passa i metodi di similarità disponibili alla pagina
    similarity_methods = get_available_similarity_methods()
    return render(request, 'core/correlation/make_request.html', {
        'similarity_methods': similarity_methods
    })

def start_correlation_task(request):
    if request.method == 'POST':
        # Recupero dei dati dal form
        task_name = request.POST.get('task_name')
        task_notes = request.POST.get('task_notes')
        
        # Recupero delle opzioni di preprocessing come JSON
        processing_options_json = request.POST.get('processing_options')
        preprocessing_options = json.loads(processing_options_json) if processing_options_json else {}

        # Recupero della versione CAPEC scelta
        capec_version = request.POST.get('capec_version', 'default')

        # Recupero i dati dalla sessione
        hosts = request.session.get('hosts')
        similarity_methods = request.session.get('similarity_methods')

        if not hosts or not similarity_methods:
            return HttpResponse("Missing required data.", status=400)

        # Creazione di Task, CorrelationTask e SingleCorrelation al servizio
        task = create_correlation_task_structure(
            task_name, task_notes, hosts, similarity_methods,
            preprocessing_options=preprocessing_options,
            capec_version=capec_version
        )

        # Messaggio di successo
        messages.success(request, 'Correlation Task started successfully!')

        # Reindirizzamento alla pagina di dettaglio della Task
        return redirect('core:tasks_list')

    else:
        return HttpResponse("Invalid request method.", status=400)

### GroundTruth

def groundtruth_list(request):
    groundtruths = GroundTruth.objects.all()  # Recupera tutti i GroundTruth presenti
    return render(request, 'core/groundtruth/groundtruth_list.html', {'groundtruths': groundtruths})

def create_groundtruth(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        json_file = request.FILES.get('json_file')
        mapping = {}

        # Se un file JSON è stato caricato
        if json_file:
            try:
                data = json.load(json_file)
                for entry in data:
                    cve_id = entry.get('CVE_ID')
                    capec_ids = entry.get('Assigned_CAPEC_ID')
                    if cve_id and isinstance(capec_ids, list):
                        mapping[cve_id] = capec_ids
            except json.JSONDecodeError:
                return render(request, 'core/groundtruth/create_groundtruth.html', {'error': 'Invalid JSON file'})

        # Altrimenti usa i dati manuali
        else:
            cve_ids = request.POST.getlist('cve_id[]')
            capec_sets = request.POST.getlist('capec_set[]')
            for cve_id, capec_set in zip(cve_ids, capec_sets):
                capec_list = [capec.strip() for capec in capec_set.split(',') if capec.strip()]
                mapping[cve_id] = capec_list

        groundtruth = GroundTruth.objects.create(name=name, mapping=mapping, created_at=timezone.now(), updated_at=timezone.now())
        return redirect('core:groundtruth_list')

    return render(request, 'core/groundtruth/create_groundtruth.html')

def groundtruth_detail(request, groundtruth_id):
    groundtruth = get_object_or_404(GroundTruth, id=groundtruth_id)
    return render(request, 'core/groundtruth/groundtruth_detail.html', {
        'groundtruth': groundtruth,
        'mapping': groundtruth.mapping,
    })

def delete_groundtruth(request, groundtruth_id):
    groundtruth = get_object_or_404(GroundTruth, id=groundtruth_id)
    groundtruth.delete()
    return redirect('core:groundtruth_list')

def correlate_groundtruth(request, groundtruth_id):
    groundtruth = get_object_or_404(GroundTruth, id=groundtruth_id)

    if request.method == 'POST':
        task_name = request.POST.get('task_name')
        task_notes = request.POST.get('task_notes')
        capec_version = request.POST.get('capec_version')
        
        # Process text preprocessing options
        processing_options = {
            "lowercase": request.POST.get('preprocessing_lowercase') == 'on',
            "remove_stopwords": request.POST.get('preprocessing_remove_stopwords') == 'on',
            "lemmatize": request.POST.get('preprocessing_lemmatize') == 'on'
        }

        # Create the Correlation Task (placeholder logic)
        # Task creation logic goes here

        return redirect('core:groundtruth_detail', groundtruth.id)
    
    # Passa i metodi di similarità disponibili alla pagina
    similarity_methods = get_available_similarity_methods()
    return render(request, 'core/groundtruth/correlate_groundtruth.html', {
        'groundtruth': groundtruth,
        'similarity_methods': similarity_methods
    })

def start_groundtruth_correlation_task(request, groundtruth_id):
    if request.method == 'POST':
        # Recupero dei dati dal form
        task_name = request.POST.get('task_name')
        task_notes = request.POST.get('task_notes')
        
        # Recupero delle opzioni di preprocessing come JSON
        processing_options_json = request.POST.get('processing_options')
        preprocessing_options = json.loads(processing_options_json) if processing_options_json else {}

        # Recupero della versione CAPEC scelta
        capec_version = request.POST.get('capec_version', 'default')

        # Recupera i similarity methods scelti
        selected_methods = request.POST.getlist('similarity_methods')

        # Controlla se sono stati selezionati metodi
        if not selected_methods:
            messages.error(request, "At least one similarity method must be selected.")
        else:
            # Logica con i metodi selezionati
            print(f"Selected methods: {selected_methods}")
            # Fai qualcosa con `selected_methods`, ad esempio salvarli o usarli in calcoli

        # Creazione di Task, CorrelationTask e SingleCorrelation al servizio
        task = create_groundtruth_task_structure(
            task_name, task_notes, groundtruth_id, selected_methods,
            preprocessing_options=preprocessing_options,
            capec_version=capec_version
        )

        # Messaggio di successo
        messages.success(request, 'Correlation Task started successfully!')

        # Reindirizzamento alla pagina di dettaglio della Task
        return redirect('core:tasks_list')

    else:
        return HttpResponse("Invalid request method.", status=400)

def get_cve_suggestions(request):
    query = request.GET.get('query', '').upper()  # Forzare la query a maiuscole per compatibilità
    suggestions = []
    
    if query:
        # Filtra i CVE che contengono la query e prendine solo i primi 10
        cve_objects = CVE.objects.filter(id__icontains=query)[:10]
        suggestions = [{"id": cve.id, "description": cve.get_summary()} for cve in cve_objects]

    return JsonResponse(suggestions, safe=False)

def get_capec_suggestions(request):
    query = request.GET.get('query', '').upper()
    suggestions = []

    if query:
        # Filtra le CAPEC che contengono la query e prendine solo i primi 10
        capec_objects = CAPEC.objects.filter(id__icontains=query)[:10]
        suggestions = [{"id": capec.id, "name": capec.name} for capec in capec_objects]

    return JsonResponse(suggestions, safe=False)


### Stats and Results functions

def export_top_capecs(request, task_id):
    """
    View per mostrare la pagina di selezione per l'esportazione delle CAPECs.
    """
    task = get_object_or_404(Task, id=task_id)

    # Modelli AI disponibili presi dalla Task
    ai_models = task.ai_models if task.ai_models else []

    if request.method == "POST":
        # Recupera i dati inviati dal form
        top_count = int(request.POST.get("top_count", 10))  # Default: 10
        selected_models = request.POST.getlist("ai_models")  # Modelli selezionati dall'utente

        # Filtra i modelli selezionati per verificare che siano tra quelli disponibili nella Task
        valid_models = [model for model in selected_models if model in ai_models]

        if not valid_models:
            message = "Nessun modello AI valido selezionato."
        else:
            # Genera il file Excel
            file_path = create_excel_with_task_hosts(task_id, top_count, valid_models)

            # Messaggio di successo
            message = f"File Excel generato con successo: {file_path.name}"

        return render(request, "core/tasks/export_top_capecs.html", {
            "task": task,
            "ai_models": ai_models,
            "message": message,
        })
    
    return render(request, "core/tasks/export_top_capecs.html", {
        "task": task,
        "ai_models": ai_models,
    })


def groundtruth_graphs(request, task_id):
    print("Inizio funzione `groundtruth_graphs`")
    task = get_object_or_404(Task, id=task_id)
    print(f"Task recuperato: {task}")
    
    groundtruths = GroundTruth.objects.all()
    print(f"GroundTruths totali trovati: {groundtruths.count()}")

    recall_ranks = {}
    precision_ranks = {}
    mrr_ranks = {}
    cr_ranks = {}
    mrr_recursive_ranks = {}
    f1_recursive_ranks = {}
    ndcg_recursive_ranks = {}

    formatted_recall_ranks = {}
    formatted_precision_ranks = {}
    formatted_mrr_ranks = {}
    formatted_cr_ranks = {}
    formatted_mrr_recursive_ranks = {}
    formatted_f1_recursive_ranks = {}
    formatted_ndcg_recursive_ranks = {}

    if request.method == "POST":
        print("Metodo POST rilevato")
        selected_groundtruth_id = request.POST.get("groundtruth")
        print(f"GroundTruth selezionato dall'utente: {selected_groundtruth_id}")
        
        if selected_groundtruth_id:
            selected_groundtruth = GroundTruth.objects.get(id=selected_groundtruth_id)
            print(f"GroundTruth recuperato: {selected_groundtruth}")

            # Calcolo dei rank
            print("Calcolo dei rank iniziato")
            ranks = analyze_task_with_groundtruth(task, selected_groundtruth)
            print(f"Ranks calcolati: {ranks}")

            recall_ranks = model_recursive_k_recall(ranks, 20)
            print(f"Recall@k calcolati: {recall_ranks}")

            precision_ranks = model_recursive_k_precision(ranks, 20)
            print(f"Precision@k calcolati: {precision_ranks}")

            mrr_ranks = calculate_mrr(ranks)
            print(f"MRR calcolati: {mrr_ranks}")

            cr_ranks = calculate_coverage(ranks)
            print(f"CR calcolati: {cr_ranks}")
            # Nuove metriche ricorsive
            mrr_recursive_ranks = calculate_mrr_recursive_k(ranks, 20)
            print(f"MRR ricorsivi calcolati: {mrr_recursive_ranks}")

            f1_recursive_ranks = calculate_f1_recursive_k(ranks, 20)
            print(f"F1 ricorsivi calcolati: {f1_recursive_ranks}")

            ndcg_recursive_ranks = calculate_ndcg_recursive_k(ranks, 20)
            print(f"NDCG ricorsivi calcolati: {ndcg_recursive_ranks}")

            # Formattazione dei dati per Recall@k
            formatted_recall_ranks = {
                model: {
                    "Recall_at_1": values[0],
                    "Recall_at_5": values[4],
                    "Recall_at_10": values[9],
                    "Recall_at_20": values[19],
                }
                for model, values in recall_ranks.items()
            }
            print(f"Formatted Recall Ranks: {formatted_recall_ranks}")

            # Formattazione dei dati per Precision@k
            formatted_precision_ranks = {
                model: {
                    "Precision_at_1": values[0],
                    "Precision_at_5": values[4],
                    "Precision_at_10": values[9],
                    "Precision_at_20": values[19],
                }
                for model, values in precision_ranks.items()
            }
            print(f"Formatted Precision Ranks: {formatted_precision_ranks}")

            # Formattazione dei dati per MRR
            formatted_mrr_ranks = {
                model: {"MRR_Rank": mrr} for model, mrr in mrr_ranks.items()
            }
            print(f"Formatted MRR Ranks: {formatted_mrr_ranks}")

             # Formattazione dei dati per MRR
            formatted_cr_ranks = {
                model: {"CR_Rank": cr} for model, cr in cr_ranks.items()
            }
            print(f"Formatted CR Ranks: {formatted_cr_ranks}")

            # Formattazione dei dati per MRR@K (solo at_1, at_5, at_10, at_20)
            formatted_mrr_recursive_ranks = {
                model: {
                    "MRR_at_1": values[0],
                    "MRR_at_5": values[4],
                    "MRR_at_10": values[9],
                    "MRR_at_20": values[19],
                }
                for model, values in mrr_recursive_ranks.items()
            }
            print(f"Formatted MRR Recursive Ranks: {formatted_mrr_recursive_ranks}")

            # Formattazione dei dati per F1@K (solo at_1, at_5, at_10, at_20)
            formatted_f1_recursive_ranks = {
                model: {
                    "F1_at_1": values[0],
                    "F1_at_5": values[4],
                    "F1_at_10": values[9],
                    "F1_at_20": values[19],
                }
                for model, values in f1_recursive_ranks.items()
            }
            print(f"Formatted F1 Recursive Ranks: {formatted_f1_recursive_ranks}")

            # Formattazione dei dati per NDCG@K (solo at_1, at_5, at_10, at_20)
            formatted_ndcg_recursive_ranks = {
                model: {
                    "NDCG_at_1": values[0],
                    "NDCG_at_5": values[4],
                    "NDCG_at_10": values[9],
                    "NDCG_at_20": values[19],
                }
                for model, values in ndcg_recursive_ranks.items()
            }
            print(f"Formatted NDCG Recursive Ranks: {formatted_ndcg_recursive_ranks}")

    # Context per il template
    context = {
        'task': task,
        'groundtruths': groundtruths,
        'recall_ranks': json.dumps(recall_ranks),  # Serializza come JSON
        'precision_ranks': json.dumps(precision_ranks),
        'mrr_ranks': json.dumps(mrr_ranks),
        'cr_ranks': json.dumps(cr_ranks),
        'mrr_recursive_ranks': json.dumps(mrr_recursive_ranks),
        'f1_recursive_ranks': json.dumps(f1_recursive_ranks),
        'ndcg_recursive_ranks': json.dumps(ndcg_recursive_ranks),
        'formatted_recall_ranks': formatted_recall_ranks,
        'formatted_precision_ranks': formatted_precision_ranks,
        'formatted_mrr_ranks': formatted_mrr_ranks,
        'formatted_cr_ranks': formatted_cr_ranks,
        'formatted_mrr_recursive_ranks': formatted_mrr_recursive_ranks,
        'formatted_f1_recursive_ranks': formatted_f1_recursive_ranks,
        'formatted_ndcg_recursive_ranks': formatted_ndcg_recursive_ranks,
    }
    print(f"Context finale: {context}")
    return render(request, 'core/groundtruth/groundtruth_graphs.html', context)



def export_groundtruth_results(request, task_id):
    """
    View per mostrare il form per esportare i risultati di GroundTruth.
    """
    task = get_object_or_404(Task, id=task_id)
    groundtruths = GroundTruth.objects.all()  # Recupera tutti i GroundTruth disponibili

    if request.method == "POST":
        top_count = int(request.POST.get("top_count", 10))  # Default: 10
        selected_groundtruth_id = request.POST.get("groundtruth")
        selected_models = request.POST.getlist("ai_models")

        # Recupera il GroundTruth selezionato
        selected_groundtruth = get_object_or_404(GroundTruth, id=selected_groundtruth_id)

        # Genera il file Excel
        try:
            file_path = create_groundtruth_excel(task, selected_groundtruth, selected_models, top_count)

            # Restituisce il file come download
            with open(file_path, "rb") as f:
                response = HttpResponse(f.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                response["Content-Disposition"] = f"attachment; filename={file_path.name}"
                return response
        except Exception as e:
            return render(request, "core/tasks/export_groundtruth_results.html", {
                "task": task,
                "groundtruths": groundtruths,
                "selected_groundtruth": selected_groundtruth,
                "selected_models": selected_models,
                "message": f"Error during export: {e}",
            })

    return render(request, "core/tasks/export_groundtruth_results.html", {
        "task": task,
        "groundtruths": groundtruths,
    })