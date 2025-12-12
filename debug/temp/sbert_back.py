from sentence_transformers import SentenceTransformer, util
import torch
import warnings
from functools import lru_cache

# Ignora il warning specifico relativo a `clean_up_tokenization_spaces`
warnings.filterwarnings("ignore", category=FutureWarning, message="`clean_up_tokenization_spaces` was not set")

class SbertSimilarity:
    def __init__(self, model_choice='mpnet', batch_size=32):
        """
        Inizializza la classe con il modello SBERT specificato.
        :param model_choice: Nome del modello semplificato ('minilm', 'distilroberta', 'mpnet')
        :param batch_size: Dimensione dei batch da usare per il processing in batch.
        """
        # Dizionario dei modelli SBERT pre-addestrati
        model_dict = {
            'minilm': 'all-MiniLM-L6-v2',
            'distilroberta': 'all-distilroberta-v1',
            'mpnet': 'paraphrase-mpnet-base-v2'
        }

        # Seleziona il modello specificato o restituisci un avviso se non valido
        if model_choice in model_dict:
            model_name = model_dict[model_choice]
        else:
            raise ValueError(f"Modello '{model_choice}' non riconosciuto. Scegli tra: {list(model_dict.keys())}.")

        # Imposta il dispositivo: utilizza 'cuda' se disponibile, altrimenti 'cpu'
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Utilizzando il dispositivo: {self.device}")

        # Carica il modello SBERT sul dispositivo specificato
        self.model = SentenceTransformer(model_name)
        if torch.cuda.is_available():
            self.model = self.model.to(self.device)

        # Imposta la dimensione del batch per il processamento
        self.batch_size = batch_size

        # Aggiunta cache per evitare di ricodificare sentence1
        self.cached_sentence = None  # Memorizza la frase principale
        self.cached_embedding = None  # Memorizza l'embedding della frase principale

    @lru_cache(maxsize=5000)  # Caching dei risultati per evitare ricalcoli
    def _encode_sentence(self, sentence):
        """
        Codifica una singola frase utilizzando SBERT.
        :param sentence: Frase da codificare.
        :return: Embedding della frase.
        """
        return self.model.encode(sentence, convert_to_tensor=True, device=self.device)

    def calculate_similarity(self, sentence1, sentence2):
        """
        Calcola la similarità tra due frasi utilizzando il modello SBERT.
        :param sentence1: Prima frase.
        :param sentence2: Seconda frase.
        :return: Punteggio di similarità (coseno) tra le due frasi.
        """
        # Codifica le frasi
        embeddings1 = self._encode_sentence(sentence1)
        embeddings2 = self._encode_sentence(sentence2)

        # Calcola la similarità utilizzando il prodotto scalare (pytorch_cos_sim)
        similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2)
        return similarity_score.item()

    def calculate_similarity_batch(self, sentence, sentences_list):
        """
        Confronta una singola frase con una lista di frasi in batch utilizzando SBERT.
        :param sentence: Frase singola.
        :param sentences_list: Lista di frasi da confrontare.
        :return: Lista di punteggi di similarità (coseno) tra la frase singola e le frasi nella lista.
        """
        try:
            # Verifica se la frase è la stessa già in cache
            if self.cached_sentence != sentence:
                self.cached_sentence = sentence
                self.cached_embedding = self._encode_sentence(sentence)
                
            # Se il batch non è cambiato, calcola gli embedding una sola volta
            embeddings_batch = self.model.encode(
                sentences_list, 
                batch_size=self.batch_size, 
                convert_to_tensor=True, 
                device=self.device
            )
            
            # Calcola la similarità tra la frase singola e gli embeddings del batch
            similarity_scores = util.pytorch_cos_sim(self.cached_embedding, embeddings_batch).squeeze(0).tolist()
            
            # Liberare la memoria della GPU non più necessaria (per evitare over-utilizzazione)
            del embeddings_batch  # Aumenta l'efficienza della memoria
            torch.cuda.empty_cache()  # Libera la memoria GPU non più utilizzata

            return similarity_scores
        except RuntimeError as e:
            print(f"[ERROR] Runtime error during batch similarity calculation: {e}")
            raise
        finally:
            # Libera la memoria GPU non più utilizzata
            torch.cuda.empty_cache()

    def clear_cache(self):
        """
        Pulisce la cache dell'embedding della frase principale.
        """
        self.cached_sentence = None
        self.cached_embedding = None
        torch.cuda.empty_cache()  # Libera la memoria GPU non più utilizzata
        
# Esempio di utilizzo
if __name__ == "__main__":
    sentence1 = "cross site scripting xss"
    sentence2 = "a cross-site scripting xss vulnerability has been reported and confirmed for beyondtrust secure remote access base software version 6.0.1 and older, which allows the injection of unauthenticated, specially-crafted web requests without proper sanitization."

    sentences_list = [
        "mime conversion",
        "an attacker exploits a weakness in the mime conversion routine to cause a buffer overflow and gain control over the mail server machine.",
        "the target system uses a mail server. mail server vendor has not released a patch for the mime conversion routine.",
        "stay up to date with third party vendor patches.",
        "it be trivial to cause a dos via this attack pattern causing arbitrary code to execute on the target system."
    ]

    # Si può scegliere il modello tramite una variabile semplice: 'minilm', 'distilroberta', 'mpnet'
    sbert_sim = SbertSimilarity(model_choice='mpnet', batch_size=64)

    # Calcola la similarità tra due frasi
    similarity_score = sbert_sim.calculate_similarity(sentence1, sentence2)
    print(f"SBERT Similarity Score: {similarity_score:.4f}")

    # Calcola la similarità in batch
    similarity_scores = sbert_sim.calculate_similarity_batch(sentence1, sentences_list)
    print(f"SBERT Batch Similarity Scores (first 5): {similarity_scores[:5]}")
