
import sys
import os
import json
import re
import spacy
import nltk
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from functools import lru_cache
from fuzzywuzzy import fuzz
from spacy.lang.en.stop_words import STOP_WORDS

from debug.debug_utils import debug_print


class KeywordSearchSimilarity:

    nlp = spacy.load('en_core_web_sm')  # Caricato una sola volta per tutti gli oggetti
    stop_words = set(stopwords.words('english'))
    porter_stemmer = PorterStemmer()

    # Scarica i pacchetti di NLTK necessari
    nltk.download('punkt')
    nltk.download('wordnet')
    nltk.download('omw-1.4')
    # Carica il modello linguistico di spaCy
    nlp = spacy.load('en_core_web_sm')

    MAX_SCORE = 0.3
    PARTIAL_MAX_SCORE = 0.2
    MAX_BONUS = 0.05
    FUZZY_THRESHOLD = 0.80
    METHOD_TYPE = "sum"

    def __init__(self):
        """
        Inizializza la classe per il calcolo della similarità tramite varie tecniche di ricerca di keyword.
        """

    def calculate_similarity(self, keyword, text):
        """
        Calcola la similarità tra una keyword e un testo utilizzando diverse tecniche di matching.
        :param keyword: Keyword da cercare nel testo.
        :param text: Testo in cui cercare la keyword.
        :return: Punteggio di similarità (1 per exact match, 0.5 per partial match, 0 altrimenti).
        """

        keyword = self._uniform_string(keyword)
        text = self._uniform_string(text)

        debug_print("[KEYWORD]", f"Calcolo similarità per keyword: '{keyword}' nel testo: '{text}'")

        keyword_without_acronyms = self._replace_acronyms(keyword)
        text_without_acronyms = self._replace_acronyms(text)
        
        debug_print("[KEYWORD]", f"Keyword dopo sostituzione acronimi {keyword_without_acronyms}")
        debug_print("[KEYWORD]", f"Testo dopo sostiuzione acronimi {text_without_acronyms}")
        
        keyword = keyword_without_acronyms
        text = text_without_acronyms

        # Prova l'exact match
        exact_score = self._exact_match(keyword, text)
        if exact_score == self.MAX_SCORE:
            debug_print("[KEYWORD]", "Exact match trovato.")
            return exact_score
        debug_print("[KEYWORD]", "Exact match non trovato, procedo con lemmatizzazione e rimozione delle stopwords.")

        # Prova exact match con rimozione delle stopwords
        filtered_keyword = self._remove_stopwords(keyword).strip()
        filtered_text = self._remove_stopwords(text).strip()
       
        # Prova exact match con lemmatizzazione e rimozione delle stopwords insieme
        lemmatized_filtered_keyword = self._lemmatize_text(filtered_keyword).strip()
        lemmatized_filtered_text = self._lemmatize_text(filtered_text).strip()
        debug_print("[KEYWORD]", f"Keyword lemmatizzata e senza stopwords: '{lemmatized_filtered_keyword}', Testo lemmatizzato e senza stopwords: '{lemmatized_filtered_text}'")

        keyword_stem = ' '.join(self._stem_porter(lemmatized_filtered_keyword))
        text_stem = ' '.join(self._stem_porter(lemmatized_filtered_text))
        debug_print("[INFO]", f"Keyword stemming: {keyword_stem}")
        debug_print("[INFO]", f"Text stemming: {text_stem}")
    
        exact_score = self._exact_match(keyword_stem, text_stem)
        if exact_score == self.MAX_SCORE:
            debug_print("[KEYWORD]", "Exact match trovato dopo stem, lemmatizzazione e rimozione delle stopwords insieme.")
            return exact_score
        debug_print("[KEYWORD]", "Exact match non trovato, procedo con il partial match.")
 
        # Prova partial match con lemmatizzazione e rimozione delle stopwords insieme
        partial_score = self._partial_match(lemmatized_filtered_keyword, lemmatized_filtered_text)
        if partial_score > 0.0:
            debug_print("[KEYWORD]", "Partial match trovato dopo lemmatizzazione e rimozione delle stopwords insieme.")
            return partial_score
        debug_print("[KEYWORD]", "Partial match non trovato, restituisco 0.")

        # Se nessuna corrispondenza è trovata, restituisce 0
        return 0.0

    def _exact_match(self, keyword, text):
        """
        Calcola la similarità tra una keyword e un testo verificando se la keyword è presente esattamente nel testo.
        :param keyword: Keyword da cercare nel testo.
        :param text: Testo in cui cercare la keyword.
        :return: Punteggio di similarità (1 se la keyword è presente, 0 altrimenti).
        """
        debug_print("[INFO]", f"Eseguo exact match per keyword: '{keyword}' nel testo: '{text}'")
        # Converte sia la keyword che il testo in minuscolo per una ricerca case-insensitive
        keyword_lower = keyword.lower()
        text_lower = text.lower()

        # Verifica se la keyword è presente nel testo
        if keyword_lower in text_lower:
            return self.MAX_SCORE
        else:
            return 0.0

    # Tokenizzazione della frase
    def tokenize_text(self, text):
        return word_tokenize(text)

    def _stem_porter(self, text):
        tokens = self.tokenize_text(text)
        return [self.porter_stemmer.stem(token) for token in tokens]

    def _partial_match(self, search_text, target_text):

        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Inizio funzione per {search_text} e {target_text}")

        search_text = self._stem_porter(search_text.lower())
        text = self._stem_porter(target_text.lower())

        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Search Text Stemmed, Lemmatized, Removed Stop words: {search_text}")
        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Target Text Stemmed, Lemmatized, Removed Stop words: {target_text}")

        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Modalità scelta: {self.METHOD_TYPE}, Punteggi dentro partial: MAX_SCORE: {self.MAX_SCORE}, PARTIAL_MAX_SCORE: {self.PARTIAL_MAX_SCORE}")

        # Punteggio iniziale
        n = len(search_text)
        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Numero di parole in {search_text}: {n}")
        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Inizio ricerca parole esatte")
        word_found = 0
        for word in search_text:
            if word in text:
                word_found += 1
                debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Parola {word} trovata. Numero di parole trovate attualmente: {word_found}. Punteggio per ogni parola trovata: {self.PARTIAL_MAX_SCORE} / {n}")
        score = (self.PARTIAL_MAX_SCORE/n) * word_found
        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Punteggio Partial Match dopo fase corrispondenze esatte: {score}")

        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Inizio ricerca parole consecutive per BONUS CONSECUTIVITA")
        # Calcolo del bonus per la consecutività
        
        
        best_bonus = 0.0

        for i, search_word in enumerate(search_text[:-1]):
            next_word = search_text[i + 1]
            occurrences = [idx for idx, word in enumerate(text) if word == search_word]
            for start_idx in occurrences:
                consecutive_count = 1
                current_bonus = self.MAX_BONUS / n
                bonus = 0.0

                for j in range(1, n - i):
                    if start_idx + j < len(text) and text[start_idx + j] == search_text[i + j]:
                        consecutive_count += 1
                        bonus += current_bonus
                        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Parola consecutiva trovata: '{text[start_idx + j]}' in posizione {start_idx + j}. Bonus attuale: {bonus}")
                        current_bonus = min(self.MAX_BONUS, self.MAX_BONUS / (n / consecutive_count))
                    else:
                        break

                best_bonus = max(best_bonus, bonus)
                debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Bonus attuale massimo consecutivo: {best_bonus}")

        # Limita il bonus massimo a 1
        best_bonus = min(best_bonus, self.MAX_BONUS)

        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Bonus consecutivo finale trovato: {best_bonus}")

        score += best_bonus
        
        debug_print("[DEBUG]", f"[PARTIAL_SCORE_KEYWORD] Punteggio parziale dopo bonus consecutività: {score}")
        
        # Controlla se la stringa è di almeno 4 parole ed esiste metà stringa (prima o seconda) nel testo
        if n >= 4:
            debug_print("[INFO]", f"[PARTIAL_SCORE_KEYWORD] La stringa ha piu di 4 parole, controllo se una metà è presente interamente")
            half_point = n // 2
            first_half = ' '.join(search_text[:half_point])
            second_half = ' '.join(search_text[half_point:])
            debug_print("[INFO]", f"[PARTIAL_SCORE_KEYWORD] Queste sono le due metà stringhe: ('{first_half}' o '{second_half}'). Controllo se presenti una delle due.")

            text_stemmed = ' '.join(text)  # Unisce i token in una stringa
            if first_half in text_stemmed or second_half in text_stemmed:
                score += 0.15
                debug_print("[INFO]", f"[PARTIAL_SCORE_KEYWORD] Una delle due metà stringhe è presente. ('{first_half}' o '{second_half}'), aggiunto bonus di 0.15")
                return score
            else:
                debug_print("[INFO]", f"[PARTIAL_SCORE_KEYWORD] Metà stringhe non presenti. Non aggiungo bonus.")

            
        # Controlla se ci sono almeno due parole della search_text nel testo
        if word_found >= 2:
            score += 0.1
            debug_print("[INFO]", f"[PARTIAL_SCORE_KEYWORD] Almeno due parole della keyword trovate nel testo, aggiunto bonus di 0.1")
    
        debug_print("INFO", f"[PARTIAL_SCORE_KEYWORD] Punteggio parziale finale: {score}")
        return score

    def _partial_fuzzy_match(self, title, text):
        """
        Calcola il punteggio di similarità di un titolo all'interno di un testo.
        :param title: Il titolo da cercare.
        :param text: Il testo nel quale cercare il titolo.
        :param keywords: Parole chiave principali che hanno più rilevanza.
        :return: Un punteggio di similarità basato su match parziali o fuzzy.
        """

        # Se il titolo completo è presente nel testo, assegna un punteggio aggiuntivo
        if title.lower() in text.lower():
            total_score = self.MAX_SCORE
            return total_score 
        
        # Tokenizza il titolo e il testo in parole separate
        title_words = self._stem_porter(title.lower())
        text_words = self._stem_porter(text.lower())
        
        # Inizializza punteggio e conteggio delle parole trovate
        total_score = 0.0
        total_words = len(title_words)
        matched_words = 0
        
        # Calcolo del match esatto per le parole
        for word in title_words:
            if word in text_words:
                matched_words += 1
                total_score += self.MAX_SCORE / total_words  # Aggiungi peso maggiore per le parole chiave
            else:
                # Controlla fuzzy match solo per le parole non trovate
                max_fuzzy_score = max([fuzz.ratio(word, tw) for tw in text_words])
                if max_fuzzy_score > self.FUZZY_THRESHOLD:  # Se la similarità è alta (>80), assegna un punteggio parziale
                    total_score += 0.15 / total_words
        
        # Se il match parziale è tra il 50% e il 75%, aggiungi punteggio proporzionale
        if 0.5 <= matched_words / total_words < 0.75:
            total_score += 0.1

        # Se il match parziale è tra il 25% e il 50%, aggiungi un punteggio ridotto
        elif 0.25 <= matched_words / total_words < 0.5:
            total_score += 0.05

        debug_print("[INFO]", f"Punteggio finale partial fuzzy match: {total_score}")
        return total_score

    def _remove_stop_words(self, text):
        """Rimuove le stop words dal testo utilizzando spaCy."""
        doc = self.nlp(text)
        return ' '.join([token.text for token in doc if not token.is_stop])
    
    def _remove_stopwords(self, text):
        """
        Rimuove le stop words dal testo.
        :param text: Testo da cui rimuovere le stop words.
        :return: Testo senza stop words.
        """
        words = text.split()
        filtered_words = [word for word in words if word.lower() not in self.stop_words]
        filtered_text = ' '.join(filtered_words)
        debug_print("[INFO]", f"Testo dopo rimozione delle stop words: '{filtered_text}'")
        return filtered_text

    @lru_cache(maxsize=None)  # Cache senza limite per questa sessione
    def _lemmatize_text(self, text):
        """
        Lemmatizza le parole nel testo utilizzando spaCy.
        :param text: Testo da lemmatizzare.
        :return: Testo lemmatizzato.
        """
        doc = self.nlp(text)
        lemmatized_words = [token.lemma_ for token in doc]
        lemmatized_text = ' '.join(lemmatized_words)
        debug_print("[INFO]", f"Testo dopo lemmatizzazione: '{lemmatized_text}'")
        return lemmatized_text

    def _uniform_string(self, text):
        """
        Sostituisce i caratteri speciali come '_', '-', '/' con uno spazio.
        Rimuove le tabulazioni e gli spazi extra.
        Rimuove solo i punti di punteggiatura che non sono parte di estensioni o versioni.
        :param text: Testo da modificare.
        :return: Testo con caratteri speciali sostituiti da spazi e rimozione dei punti di punteggiatura.
        """
        # Regex per rimuovere punti non seguiti da estensioni di file (es: .php) o numeri (es: .1)
        text = re.sub(r'(?<!\w)\.(?!\w{2,4})', ' ', text)  # Questo rimuove i punti che non sono parte di estensioni/file
        text = re.sub(r'(?<!\d)\.(?!\d)', ' ', text)  # Questo rimuove i punti che non sono parte di numeri di versione
        
        # Sostituisce gli altri caratteri speciali con uno spazio
        text = text.replace('_', ' ').replace('-', ' ').replace('/', ' ').replace('(', ' ').replace(')', ' ').replace(',', ' ').replace(';', ' ').lower()

        # Rimuove spazi extra e tabulazioni
        text = ' '.join(text.split()).strip()
        
        # Debug print per il testo modificato
        debug_print("[INFO]", f"Testo dopo sostituzione dei caratteri speciali e rimozione degli spazi extra: '{text}'")
        
        return text
    
    def _replace_acronyms(self, input_string):
        """Carica gli acronimi da un file JSON."""
        
        acronyms_file = os.path.join(os.path.dirname(__file__), 'acronyms.json')

        with open(acronyms_file, 'r') as f:
            data = json.load(f)
        
        acronyms = data['acronyms']

        """Fase 1: Sostituisce gli acronimi nella stringa o li rimuove se l'espansione è già presente."""
        for acronym, expansions in acronyms.items():
            for expansion in expansions:
                # Pattern per rilevare "espansione + acronimo" (es: "Cross-Site Scripting XSS")
                pattern_with_acronym = re.compile(r'\b' + re.escape(expansion) + r'\s+' + re.escape(acronym) + r'\b', re.IGNORECASE)
                
                # Rimuovi l'acronimo se è preceduto dall'espansione
                input_string = pattern_with_acronym.sub(expansion, input_string)
                
                # Se non c'è l'espansione, sostituisci l'acronimo con l'espansione
                pattern_acronym_only = re.compile(r'\b' + re.escape(acronym) + r'\b', re.IGNORECASE)
                input_string = pattern_acronym_only.sub(expansion, input_string)

        """Fase 2: Sostituisce l'espansione con l'acronimo"""
        for acronym, expansions in acronyms.items():
            for expansion in expansions:
                # Sostituisci l'espansione con l'acronimo corrispondente
                pattern_expansion = re.compile(r'\b' + re.escape(expansion) + r'\b', re.IGNORECASE)
                input_string = pattern_expansion.sub(acronym, input_string)
        
        return input_string
     
    def _remove_parentheses_content(self, text):
        """
        Rimuove il contenuto tra parentesi tonde, comprese le parentesi stesse.
        :param text: Testo da cui rimuovere il contenuto tra parentesi.
        :return: Testo senza contenuto tra parentesi.
        """
        import re
        text = re.sub(r'\(.*?\)', '', text)
        text = ' '.join(text.split())  # Rimuove spazi extra
        debug_print("[INFO]", f"Testo dopo rimozione del contenuto tra parentesi: '{text}'")
        return text
    
    def _extract_parentheses_content(self, text):
        """
        Estrae il contenuto tra parentesi tonde e lo restituisce come testo senza parentesi.
        :param text: Testo da cui estrarre il contenuto tra parentesi.
        :return: Testo contenente solo il contenuto tra parentesi, senza parentesi.
        """
        import re
        match = re.search(r'\((.*?)\)', text)
        if match:
            extracted_content = match.group(1)
            debug_print("[INFO]", f"Testo estratto tra parentesi: '{extracted_content}'")
            return extracted_content
        else:
            debug_print("[INFO]", "Nessun contenuto tra parentesi trovato.")
            return text


# Esempio di utilizzo
if __name__ == "__main__":
    keyword = "	Predict Session Falsification through Credential"
    text = "Jetty before 4.2.27, 5.1 before 5.1.12, 6.0 before 6.0.2, and 6.1 before 6.1.0pre3 generates predictable session identifiers using java.util.random, which makes it easier for remote attackers to guess a session identifier through brute force attacks, bypass authentication requirements, and possibly conduct cross-site request forgery attacks."

    # Inizializza l'oggetto KeywordSearchSimilarity
    keyword_search_sim = KeywordSearchSimilarity()
    
    # Calcola la similarità
    similarity_score = keyword_search_sim.calculate_similarity(keyword, text)
    print(f"Calculated Similarity Score: {similarity_score:.4f}")
