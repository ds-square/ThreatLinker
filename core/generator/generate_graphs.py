import matplotlib.pyplot as plt
import io
import base64

def generate_recall_at_k_graph(model_ranks_dict, k_max=20):
    """
    Genera un grafico di Recall@k per più modelli, visualizzando una linea separata per ciascun modello.

    :param model_ranks_dict: Dizionario con i rank per ogni modello, ad es. {'SBERT': [1, 2, 5, ...], 'BERT': [3, 1, 10, ...]}
    :param k_max: Il massimo valore di k da considerare (default: 20).
    :return: L'immagine del grafico in formato base64.
    """
    
    # Funzione di utilità per calcolare recall@k
    def recall_at_k(ranks, k, total_relevant):
        relevant_retrieved = sum(1 for rank in ranks if rank <= k)
        return relevant_retrieved / total_relevant if total_relevant > 0 else 0

    # Definire i valori di k
    k_values = range(1, k_max + 1)
    total_relevant = len(next(iter(model_ranks_dict.values())))  # Presuppone che tutti i modelli abbiano la stessa lunghezza

    # Creazione del grafico
    plt.figure(figsize=(10, 6))
    
    for model, ranks in model_ranks_dict.items():
        # Calcola il Recall@k per ogni valore di k
        recall_values = [recall_at_k(ranks, k, total_relevant) for k in k_values]
        
        # Disegna la linea per il modello corrente
        plt.plot(k_values, recall_values, marker='o', label=f"{model} Recall@k")
    
    # Configurazione del grafico
    plt.xlabel("k")
    plt.ylabel("Recall")
    plt.title("Recall@k for Different Models")
    plt.xticks(k_values)
    plt.legend()
    plt.grid(True)

    # Converti il grafico in un'immagine base64
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    recall_graph_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.clf()  # Pulizia del grafico

    return recall_graph_base64

def analyze_task_with_groundtruth(task, groundtruth):
    """
    Analizza una Task con un GroundTruth e restituisce i rank delle CAPEC per ogni modello AI,
    ordinando i risultati per CVE_ID.

    :param task: Oggetto Task associato.
    :param groundtruth: Oggetto GroundTruth selezionato.
    :return: Lista di tuple nel formato (model_name, model_ranks, ranks_len).
    """
    import re

    def extract_cve_sort_key(cve_id):
        """
        Estrae una chiave di ordinamento dagli ID delle CVE nel formato CVE-YYYY-XXXX.
        """
        match = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
        if match:
            year, number = match.groups()
            return int(year), int(number)
        return float('inf'), float('inf')  # Per eventuali ID non validi

    print(f"Starting analysis for Task ID: {task.id}, GroundTruth ID: {groundtruth.id}")

    # 1. Recupera i modelli AI dalla Task
    ai_models = task.ai_models if task.ai_models else []
    print(f"AI Models from Task: {ai_models}")

    # 2. Recupera le SingleCorrelations associate alla Task
    single_correlations = task.single_correlations.all()
    print(f"Total SingleCorrelations: {single_correlations.count()}")

    # Recupera il mapping di GroundTruth
    groundtruth_mapping = groundtruth.mapping  # {'CVE-XXX': ['CAPEC-1', 'CAPEC-2']}
    print(f"GroundTruth Mapping: {groundtruth_mapping}")

    # Trova le CVE presenti sia in SingleCorrelations che in GroundTruth
    relevant_cve_ids = set(groundtruth_mapping.keys())
    matched_cve_ids = set()

    for single_correlation in single_correlations:
        if single_correlation.cve_id in relevant_cve_ids:
            matched_cve_ids.add(single_correlation.cve_id)

    print(f"Matched CVE IDs: {matched_cve_ids}")
    print(f"Total Matched CVE IDs: {len(matched_cve_ids)}")

    # Ordina le CVE corrispondenti
    sorted_cve_ids = sorted(matched_cve_ids, key=extract_cve_sort_key)
    print(f"Sorted CVE IDs: {sorted_cve_ids}")

    # 3. Calcola i rank per ogni modello AI
    results = []

    for model in ai_models:
        print(f"Processing model: {model}")
        model_ranks = []

        for cve_id in sorted_cve_ids:
            # Cerca la SingleCorrelation corrispondente
            single_correlation = next(
                (sc for sc in single_correlations if sc.cve_id == cve_id), None
            )
            if single_correlation:
                similarity_scores = single_correlation.similarity_scores.get(model, [])
                print(f"Similarity Scores for {model} in CVE {cve_id}: {similarity_scores}")

                # Trova il rank della o delle CAPEC associate nel GroundTruth
                for capec_id in groundtruth_mapping[cve_id]:
                    for score_data in similarity_scores:
                        if score_data[0] == capec_id:
                            model_ranks.append(score_data[1].get("rank"))
                            print(f"Found rank for CAPEC {capec_id}: {score_data[1].get('rank')}")

        # Aggiungi i risultati per il modello corrente
        results.append((model, model_ranks, len(model_ranks)))

    # Stampa i risultati finali
    for model, ranks, ranks_len in results:
        print(f"Model: {model}, Ranks: {ranks}, Total Ranks: {ranks_len}")

    return results

def model_recursive_k_recall(model_ranks, k):
    """
    Calcola la Recall@K per ciascun modello fino a un valore massimo di K, arrotondata a 3 cifre decimali.

    :param model_ranks: Lista di tuple nel formato (model_name, model_ranks, ranks_len).
                        Esempio: [("SBERT", [1, 4, 5, 6], 50), ("AttackBERT", [2, 6, 10], 50)]
    :param k: Numero massimo di posizioni da considerare per la Recall@K.
    :return: Dizionario nel formato:
             {
                'SBERT': [Recall@1, Recall@2, ..., Recall@k],
                'AttackBERT': [Recall@1, Recall@2, ..., Recall@k],
             }
    """
    results = {}

    for model_name, ranks, total_relevant in model_ranks:
        recall_values = []
        for current_k in range(1, k + 1):
            # Conta i rank <= current_k
            relevant_retrieved = sum(1 for rank in ranks if rank <= current_k)
            # Calcola Recall@current_k e arrotonda a 3 cifre decimali
            recall_at_k = round(relevant_retrieved / total_relevant, 3) if total_relevant > 0 else 0
            recall_values.append(recall_at_k)
        results[model_name] = recall_values
        print(f"Model: {model_name}, Recall@K values: {recall_values}")

    return results

def model_recursive_k_precision(model_ranks, k):
    """
    Calcola la Precision@K per ciascun modello fino a un valore massimo di K.
    Restituisce la Precision@K media per ciascun K.

    :param model_ranks: Lista di tuple nel formato (model_name, model_ranks, ranks_len).
                        Esempio: [("SBERT", [1, 4, 5, 6], 50), ("AttackBERT", [2, 6, 10], 50)]
    :param k: Numero massimo di posizioni da considerare per la Precision@K.
    :return: Dizionario nel formato:
             {
                'SBERT': [Precision@1, Precision@2, ..., Precision@k],
                'AttackBERT': [Precision@1, Precision@2, ..., Precision@k],
             }
    """
    results = {}

    for model_name, ranks, _ in model_ranks:
        precision_values = []

        for current_k in range(1, k + 1):
            # Calcola Precision@k per ogni rank
            precision_at_k_per_rank = [1 / current_k for rank in ranks if 1 <= rank <= current_k]
            # Calcola la media Precision@k
            mean_precision_at_k = round(sum(precision_at_k_per_rank) / len(ranks), 3) if ranks else 0
            precision_values.append(mean_precision_at_k)

        results[model_name] = precision_values
        print(f"Model: {model_name}, Precision@K values: {precision_values}")

    return results

def calculate_mrr(model_ranks):
    """
    Calcola il Mean Reciprocal Rank (MRR) per ciascun modello.
    
    :param model_ranks: Lista di tuple nel formato:
                        [
                            ("Model1", [1, 4, 5, ...], 50),  # Modello, lista dei rank, numero totale di rilevanti
                            ("Model2", [2, 6, 10, ...], 50),
                        ]
    :return: Dizionario con l'MRR per ciascun modello:
             {
                 'Model1': 0.42,
                 'Model2': 0.35,
             }
    """
    mrr_results = {}

    for model_name, ranks, total_relevant in model_ranks:
        # Calcola il Reciprocal Rank per ogni elemento
        reciprocal_ranks = [1 / rank if rank > 0 else 0 for rank in ranks]
        # Media dei Reciprocal Rank
        mrr = round(sum(reciprocal_ranks) / total_relevant, 3) if total_relevant > 0 else 0
        mrr_results[model_name] = mrr
        print(f"Model: {model_name}, MRR: {mrr}, Reciprocal Ranks: {reciprocal_ranks}")

    return mrr_results

def calculate_mrr_recursive_k(model_ranks, k):
    """
    Calcola MRR ricorsivo fino a K per ciascun modello.

    :param model_ranks: Lista di tuple nel formato:
                        [
                            ("Model1", [1, 4, 5, ...], 50),  # Modello, lista dei rank, numero totale di rilevanti
                            ("Model2", [2, 6, 10, ...], 50),
                        ]
    :param k: Valore massimo di K da considerare.
    :return: Dizionario con una lista di MRR@1, MRR@2, ..., MRR@k per ciascun modello:
             {
                 'Model1': [0.5, 0.6, ...],
                 'Model2': [0.4, 0.5, ...],
             }
    """
    results = {}

    for model_name, ranks, total_relevant in model_ranks:
        mrr_values = []
        for current_k in range(1, k + 1):
            reciprocal_ranks = [
                1 / rank if rank <= current_k else 0 for rank in ranks
            ]
            mrr_at_k = round(sum(reciprocal_ranks) / total_relevant, 3) if total_relevant > 0 else 0
            mrr_values.append(mrr_at_k)
        results[model_name] = mrr_values
        print(f"Model: {model_name}, MRR@K values: {mrr_values}")

    return results

def calculate_f1_recursive_k(model_ranks, k):
    """
    Calcola F1 ricorsivo fino a K per ciascun modello.

    :param model_ranks: Lista di tuple nel formato:
                        [
                            ("Model1", [1, 4, 5, ...], 50),  # Modello, lista dei rank, numero totale di rilevanti
                            ("Model2", [2, 6, 10, ...], 50),
                        ]
    :param k: Valore massimo di K da considerare.
    :return: Dizionario con una lista di F1@1, F1@2, ..., F1@k per ciascun modello:
             {
                 'Model1': [0.5, 0.6, ...],
                 'Model2': [0.4, 0.5, ...],
             }
    """
    results = {}

    for model_name, ranks, total_relevant in model_ranks:
        f1_values = []
        for current_k in range(1, k + 1):
            relevant_retrieved = sum(1 for rank in ranks if rank <= current_k)
            precision_at_k_per_rank = [1 / current_k for rank in ranks if 1 <= rank <= current_k]
            precision_at_k = round(sum(precision_at_k_per_rank) / len(ranks), 3) if ranks else 0

            recall_at_k = relevant_retrieved / total_relevant if total_relevant > 0 else 0

            if precision_at_k + recall_at_k > 0:
                f1_at_k = round(2 * (precision_at_k * recall_at_k) / (precision_at_k + recall_at_k), 3)
            else:
                f1_at_k = 0

            f1_values.append(f1_at_k)
        results[model_name] = f1_values
        print(f"Model: {model_name}, F1@K values: {f1_values}")

    return results

import math

def calculate_ndcg_recursive_k(model_ranks, k_max):
    """
    Calcola NDCG per ciascun modello iterando su k da 1 a k_max.

    :param model_ranks: Lista di tuple nel formato:
                        [
                            ("Model1", [1, 4, 5, ...], 50),  # Modello, lista dei rank, numero totale di rilevanti
                            ("Model2", [2, 6, 10, ...], 50),
                        ]
    :param k_max: Numero massimo di k da considerare.
    :return: Dizionario nel formato:
             {
                 "Model1": [NDCG@1, NDCG@2, ..., NDCG@k],
                 "Model2": [NDCG@1, NDCG@2, ..., NDCG@k],
             }
    """
    results = {}

    for model_name, ranks, _ in model_ranks:
        ndcg_values = []

        for k in range(1, k_max + 1):
            # Calcolo del DCG per k
            dcg = sum(
                1 / math.log2(rank + 1) for rank in ranks if rank <= k
            )

            # L'IDCG ideale è 1 per ogni posizione, dato che la CAPEC corretta sarebbe sempre al primo posto
            idcg = 1.0

            # Calcola il NDCG per k
            ndcg_at_k = dcg / idcg if idcg > 0 else 0.0
            ndcg_at_k_mean = ndcg_at_k / len(ranks)
            ndcg_values.append(round(ndcg_at_k_mean, 3))  # Arrotonda a 3 cifre decimali

        results[model_name] = ndcg_values
        print(f"Model: {model_name}, NDCG@k values: {ndcg_values}")  # Debug

    return results

def calculate_coverage(model_ranks):
    """
    Calcola il Coverage per ciascun modello.

    :param model_ranks: Lista di tuple nel formato:
                        [
                            ("Model1", [1, 4, 5, ...], 50),  # Modello, lista dei rank, numero totale di rilevanti
                            ("Model2", [2, 6, 10, ...], 50),
                        ]
    :return: Dizionario con il Coverage per ciascun modello:
             {
                 'Model1': 3.0,
                 'Model2': 5.7,
             }
    """
    coverage_results = {}

    for model_name, ranks, total_relevant in model_ranks:
        # Media dei rank delle CAPEC corrette
        if total_relevant > 0:
            coverage = round(sum(ranks) / total_relevant, 3)
        else:
            coverage = 0
        coverage_results[model_name] = coverage
        print(f"Model: {model_name}, Coverage: {coverage}, Ranks: {ranks}")

    return coverage_results

