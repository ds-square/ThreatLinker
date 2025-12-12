from transformers import AutoTokenizer, AutoModel
import torch
from sentence_transformers import util
import warnings
import logging

# Configura il logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ignora il warning specifico relativo a `clean_up_tokenization_spaces`
warnings.filterwarnings("ignore", category=FutureWarning, message="`clean_up_tokenization_spaces` was not set")


class AttackBERTSimilarity:
    def __init__(self, model_choice='attackbert', batch_size=32, initial_device='auto'):
        """
        Inizializza la classe con il modello AttackBERT specificato.
        :param model_choice: Nome del modello ('attackbert').
        :param batch_size: Dimensione dei batch per il processamento.
        :param initial_device: Dispositivo iniziale ('cpu', 'cuda', 'auto').
        """
        model_dict = {
            'attackbert': 'basel/ATTACK-BERT'
        }

        if model_choice not in model_dict:
            raise ValueError(f"Model '{model_choice}' not recognized. Choose from: {list(model_dict.keys())}.")

        self.model_name = model_dict[model_choice]
        self.batch_size = batch_size

        # Determina il dispositivo iniziale
        self.device = self._determine_initial_device(initial_device)
        logger.info(f"Dispositivo iniziale scelto: {self.device}")

        # Carica il tokenizer e il modello sul dispositivo scelto
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModel.from_pretrained(self.model_name).to(self.device)
        logger.info(f"Modello '{self.model_name}' caricato su {self.device}.")

        # Caching per migliorare le performance
        self.cached_sentence = None
        self.cached_embedding = None

    def _determine_initial_device(self, initial_device):
        """
        Determina il dispositivo iniziale ('cpu', 'cuda', 'auto').
        :param initial_device: Preferenza dell'utente ('cpu', 'cuda', 'auto').
        :return: Dispositivo scelto.
        """
        if initial_device == 'cuda' and torch.cuda.is_available():
            return torch.device("cuda")
        elif initial_device in ['cpu', 'auto']:
            return torch.device("cpu")
        elif initial_device == 'auto' and torch.cuda.is_available():
            return torch.device("cuda")
        else:
            raise ValueError(f"Dispositivo non valido o non supportato: {initial_device}")

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
        try:
            embeddings1 = self.encode_sentence(sentence1)
            embeddings2 = self.encode_sentence(sentence2)
            similarity_score = util.pytorch_cos_sim(embeddings1, embeddings2).item()
            logger.info(f"Similarità calcolata tra le frasi: {similarity_score:.4f}")
            return similarity_score
        except Exception as e:
            logger.error(f"Errore durante il calcolo della similarità: {e}")
            raise

    def calculate_similarity_batch(self, sentence, sentences_list):
        """
        Calcola le similarità tra una frase e una lista di frasi in batch utilizzando AttackBERT.
        :param sentence: Frase di riferimento.
        :param sentences_list: Lista di frasi da confrontare.
        :return: Lista di punteggi di similarità (coseno) tra la frase e la lista.
        """
        try:
            if self.cached_sentence != sentence:
                self.cached_sentence = sentence
                self.cached_embedding = self.encode_sentence(sentence)

            results = []
            for i in range(0, len(sentences_list), self.batch_size):
                batch = sentences_list[i:i + self.batch_size]
                inputs_batch = self.tokenizer(batch, return_tensors='pt', truncation=True, padding=True, max_length=512).to(self.device)
                with torch.no_grad():
                    outputs_batch = self.model(**inputs_batch)

                embeddings_batch = outputs_batch.last_hidden_state.mean(dim=1)
                batch_scores = util.pytorch_cos_sim(self.cached_embedding, embeddings_batch).squeeze(0).tolist()
                results.extend(batch_scores)

            #logger.info(f"Similarità batch calcolata con successo per {len(sentences_list)} frasi.")
            return results
        except Exception as e:
            logger.error(f"Errore durante il calcolo della similarità in batch: {e}")
            raise
        finally:
            if self.device.type == "cuda":
                torch.cuda.empty_cache()  # Libera la memoria GPU

    def reload_model_on_device(self, new_device):
        """
        Cambia dinamicamente il dispositivo del modello.
        :param new_device: Nuovo dispositivo ('cpu' o 'cuda').
        """
        try:
            self.device = torch.device(new_device)
            self.model = AutoModel.from_pretrained(self.model_name).to(self.device)
            logger.info(f"Modello ricaricato con successo su {new_device}.")
        except Exception as e:
            logger.error(f"Errore durante il ricaricamento del modello su {new_device}: {e}")
            raise

    def clear_cache(self):
        """
        Pulisce la cache della frase principale.
        """
        self.cached_sentence = None
        self.cached_embedding = None
        if self.device.type == "cuda":
            torch.cuda.empty_cache()
        logger.info("Cache pulita con successo.")
