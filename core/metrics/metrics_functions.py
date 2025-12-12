def mean_reciprocal_rank(ranks):
    """
    Calcola il Mean Reciprocal Rank (MRR) dato un elenco di rank per ogni query.
    
    :param ranks: Lista di rank (posizione del primo risultato corretto) per ogni query.
                  Se una query non ha un risultato corretto, il valore dovrebbe essere None o un valore alto (ad esempio float('inf')).
    :return: Mean Reciprocal Rank.
    """
    reciprocal_ranks = [1 / rank if rank and rank > 0 else 0 for rank in ranks]
    return sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else 0.0

def recall_at_k(ranks, k):
    """
    Calcola la recall @k.
    
    :param ranks: Lista di rank (posizione del primo risultato corretto) per ogni query.
                  Se una query non ha un risultato corretto, il valore dovrebbe essere None o un valore alto (ad esempio float('inf')).
    :param k: Numero massimo di posizioni da considerare.
    :return: Recall @k.
    """
    # Conta il numero di rank <= k (che sono considerati corretti entro il cutoff di k)
    relevant_at_k = sum(1 for rank in ranks if rank and rank <= k)
    
    # Calcola la recall come proporzione del totale degli elementi
    return relevant_at_k / len(ranks) if ranks else 0.0

def precision_at_k(y_true, y_pred, k):
    """
    Calcola la precisione @k per una singola CVE.
    
    :param y_true: Lista dei CAPEC rilevanti per la CVE (ground truth).
    :param y_pred: Lista dei CAPEC predetti (ordinata per confidenza).
    :param k: Numero massimo di posizioni da considerare.
    :return: Precision@k per la singola CVE.
    """
    y_pred = y_pred[:k]  # Prende i primi k risultati predetti
    true_positives = len(set(y_pred) & set(y_true))
    return true_positives / k if k > 0 else 0

def mean_precision_at_k(y_true_list, y_pred_list, k):
    """
    Calcola la Precision@k media per tutte le CVE.
    
    :param y_true_list: Lista di liste di CAPEC rilevanti per ciascuna CVE.
    :param y_pred_list: Lista di liste di CAPEC predetti per ciascuna CVE (ordinate per confidenza).
    :param k: Numero massimo di posizioni da considerare.
    :return: Precision@k media su tutte le CVE.
    """
    precisions = [precision_at_k(y_true, y_pred, k) for y_true, y_pred in zip(y_true_list, y_pred_list)]
    return sum(precisions) / len(precisions) if precisions else 0.0