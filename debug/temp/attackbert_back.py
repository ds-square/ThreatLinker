from transformers import AutoTokenizer, AutoModel
import torch
from sentence_transformers import util
import warnings

# Ignora il warning specifico relativo a `clean_up_tokenization_spaces`
warnings.filterwarnings("ignore", category=FutureWarning, message="`clean_up_tokenization_spaces` was not set")

class AttackBERTSimilarity:
    def __init__(self, model_choice='attackbert'):
        """
        Inizializza la classe con il modello AttackBERT specificato.
        :param model_choice: Nome del modello ('attackbert')
        """
        # Dizionario dei modelli AttackBERT
        model_dict = {
            'attackbert': 'basel/ATTACK-BERT'
        }

        # Seleziona il modello specificato o alza un errore se non esiste
        if model_choice in model_dict:
            model_name = model_dict[model_choice]
        else:
            raise ValueError(f"Model '{model_choice}' not recognized. Choose from: {list(model_dict.keys())}.")

        # Imposta il dispositivo: utilizza 'cuda' se disponibile, altrimenti 'cpu'
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")

        # Carica il tokenizer e il modello AttackBERT sul dispositivo specificato
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device)

        # Caching per evitare ricalcoli
        self.cached_sentence = None
        self.cached_embedding = None

    def encode_sentence(self, sentence):
        """
        Codifica una singola frase utilizzando AttackBERT.
        :param sentence: Frase da codificare.
        :return: Embedding della frase.
        """
        inputs = self.tokenizer(sentence, return_tensors='pt', truncation=True, padding=True, max_length=512).to(self.device)
        with torch.no_grad():
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1)

    def calculate_similarity(self, sentence1, sentence2):
        """
        Calcola la similarità tra due frasi utilizzando il modello AttackBERT.
        :param sentence1: Prima frase.
        :param sentence2: Seconda frase.
        :return: Punteggio di similarità (coseno) tra le due frasi.
        """
        embeddings1 = self.encode_sentence(sentence1)
        embeddings2 = self.encode_sentence(sentence2)

        # Calcola la similarità coseno tra i due embedding
        similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2)
        return similarity_score.item()

    def calculate_similarity_batch(self, sentence, sentences_list):
        """
        Confronta una singola frase con una lista di frasi in batch utilizzando AttackBERT.
        :param sentence: Frase singola.
        :param sentences_list: Lista di frasi da confrontare.
        :return: Lista di punteggi di similarità (coseno) tra la frase singola e le frasi nella lista.
        """
        # Codifica la frase di riferimento
        if self.cached_sentence != sentence:
            self.cached_sentence = sentence
            self.cached_embedding = self.encode_sentence(sentence)

        # Codifica tutte le frasi nel batch
        inputs_batch = self.tokenizer(sentences_list, return_tensors='pt', truncation=True, padding=True, max_length=512).to(self.device)
        with torch.no_grad():
            outputs_batch = self.model(**inputs_batch)

        # Calcola la similarità coseno tra la frase di riferimento e tutte le frasi nel batch
        embeddings_batch = outputs_batch.last_hidden_state.mean(dim=1)  # Ottieni gli embeddings medi per ogni frase
        similarity_scores = util.pytorch_cos_sim(self.cached_embedding, embeddings_batch).squeeze(0).tolist()

        # Liberare la memoria non più utilizzata
        torch.cuda.empty_cache()  # Libera la memoria GPU non più utilizzata

        return similarity_scores

    def clear_cache(self):
        """
        Pulisce la cache dell'embedding della frase principale.
        """
        self.cached_sentence = None
        self.cached_embedding = None
        torch.cuda.empty_cache()  # Libera la memoria GPU non più utilizzata
        
# Esempio di utilizzo
if __name__ == "__main__":
    sentence1 = "Buffer overflow in the login program allows remote attackers to execute arbitrary code."
    sentence2 = "Remote attackers can exploit a buffer overflow vulnerability in the authentication process."

    # Crea l'istanza del modello AttackBERT
    attackbert_sim = AttackBERTSimilarity(model_choice='attackbert')
    
    # Calcola la similarità tra due frasi
    similarity_score = attackbert_sim.calculate_similarity(sentence1, sentence2)
    print(f"AttackBERT Similarity Score: {similarity_score:.4f}")

    # Calcola la similarità in batch
    sentences_list = [
        "An attacker could exploit a buffer overflow vulnerability.",
        "Buffer overflows can allow unauthorized access.",
        "The authentication process has a potential security issue."
    ]
    similarity_scores = attackbert_sim.calculate_similarity_batch(sentence1, sentences_list)
    print(f"AttackBERT Batch Similarity Scores: {similarity_scores}")
