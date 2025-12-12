from core.similarity.sbert import SbertSimilarity
from core.similarity.attackbert import AttackBERTSimilarity

def calculate_similarity_scores(sentence1, sentence2):
    """
    Calcola la similarità tra due frasi utilizzando i modelli disponibili.
    :param sentence1: Prima frase.
    :param sentence2: Seconda frase.
    :return: Dizionario con i punteggi di similarità per ogni modello.
    """
    # Calcola la similarità con SbertSimilarity
    sbert_sim = SbertSimilarity(model_choice='mpnet')
    sbert_score = sbert_sim.calculate_similarity(sentence1, sentence2)

    # Calcola la similarità con AttackBERTSimilarity
    attackbert_sim = AttackBERTSimilarity(model_choice='attackbert')
    attackbert_score = attackbert_sim.calculate_similarity(sentence1, sentence2)

    return {
        'sbert_score': sbert_score,
        'attackbert_score': attackbert_score
    }

def compare_single_with_batch(sentence, sentences_list, field_names, methods=['SBERT', 'ATTACKBERT']):
    """
    Confronta una singola frase con un batch di frasi utilizzando i metodi di similarità specificati.
    Ogni punteggio è associato a un nome di campo specifico.

    :param sentence: La singola frase da confrontare.
    :param sentences_list: Una lista di frasi da confrontare con la frase singola.
    :param field_names: Una lista dei nomi di ciascun campo (per associare i punteggi).
    :param methods: Una lista di metodi di similarità da usare ('SBERT', 'ATTACKBERT', etc.).
    :return: Un dizionario con i punteggi di similarità per ogni metodo e per ogni frase nella lista.
    """
    similarity_scores = {}

    # Verifica che la lunghezza di sentences_list e field_names sia uguale
    if len(sentences_list) != len(field_names):
        raise ValueError("La lista delle frasi (sentences_list) e la lista dei nomi dei campi (field_names) devono avere la stessa lunghezza.")

    # Loop per ogni metodo di similarità specificato
    for method in methods:
        print(f"Comparing using {method}...")

        if method.upper() == 'SBERT':
            sbert_sim = SbertSimilarity(model_choice='mpnet')  # Modifica a seconda delle tue esigenze
            # Calcola la similarità per il batch (la descrizione della CVE con tutti i campi aggregati del CAPEC)
            batch_scores = sbert_sim.calculate_similarity_batch(sentence, sentences_list)

            # Associa i punteggi ai nomi dei campi
            for idx, field_name in enumerate(field_names):
                similarity_scores[f'{field_name}_sbert_score'] = batch_scores[idx]

        elif method.upper() == 'ATTACKBERT':
            attackbert_sim = AttackBERTSimilarity(model_choice='attackbert')  # Modifica a seconda delle tue esigenze
            # Calcola la similarità per il batch (la descrizione della CVE con tutti i campi aggregati del CAPEC)
            batch_scores = attackbert_sim.calculate_similarity_batch(sentence, sentences_list)

            # Associa i punteggi ai nomi dei campi
            for idx, field_name in enumerate(field_names):
                similarity_scores[f'{field_name}_attackbert_score'] = batch_scores[idx]

        else:
            print(f"Similarity method {method} is not recognized. Please use 'SBERT' or 'ATTACKBERT'.")

    return similarity_scores


def get_available_similarity_methods():
    """
    Restituisce una lista dei metodi di similarità disponibili.
    """
    return [
        'SBERT',
        'ATTACKBERT'
    ]