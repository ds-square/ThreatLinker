import re
import string
import spacy
import contractions

import nltk
from nltk.corpus import stopwords, wordnet
from nltk.tokenize import sent_tokenize

from core.preprocessing.cpe_uri_remover import process_cpe_uris_in_text
from debug.debug_utils import debug_print


class TextCleaner:
    def __init__(self, lowercase=True, remove_space_newline=True, remove_punctuation=True, preserve_file_extensions=True, 
                 remove_digits=False, remove_links=True, remove_dates=False, remove_parentheses_content=False, 
                 remove_consecutive_repeat=False, remove_special_characters=False, expand_contractions=False,
                 genitive=True, remove_file_names=False, remove_file_paths=False, 
                 replace_file_paths=False, remove_entities=False, remove_versions=False, remove_products=False, 
                 remove_stop_words=False, advanced_tokenization=False, sentence_tokenization=False, lemmatize=False, 
                 remove_puncts=True):
        """
        Inizializza il cleaner di testo con diverse opzioni per la pulizia.
        :param lowercase: Converti il testo in minuscolo.
        :param remove_punctuation: Rimuovi la punteggiatura.
        :param remove_digits: Rimuovi i numeri.
        :param remove_extra_spaces: Rimuovi spazi extra.
        :param remove_newlines: Rimuovi i caratteri di a capo.
        :param remove_tabs: Rimuovi le tabulazioni.
        :param remove_at: Rimuovi i simboli '@'.
        :param remove_links: Rimuovi i link.
        :param remove_citations: Rimuovi le citazioni (ad esempio '@username').
        """

        # General cleaning
        self.lowercase = lowercase
        self.remove_space_newline = remove_space_newline
        self.remove_punctuation = remove_punctuation
        self.remove_special_characters = remove_special_characters
        self.remove_digits = remove_digits
        self.remove_dates = remove_dates
        self.remove_parentheses_content = remove_parentheses_content
        self.remove_consecutive_repeat = remove_consecutive_repeat
        self.remove_links = remove_links
        self.expand_contractions = expand_contractions
        self.remove_puncts = remove_puncts

        # Specific Software Cleaning
        self.remove_versions = remove_versions
        self.remove_products = remove_products
        self.remove_entities = remove_entities

        # File related cleaning
        self.preserve_file_extensions = preserve_file_extensions
        self.remove_file_names = remove_file_names
        self.remove_file_paths = remove_file_paths
        self.replace_file_paths = replace_file_paths

        # Linguaggio
        self.remove_stop_words = remove_stop_words
        try:
            self.stopwords = set(stopwords.words('english'))
        except LookupError:
            nltk.download('stopwords')
            self.stopwords = set(stopwords.words('english'))
        self.genitive = genitive

        self.lemmatize = lemmatize
        try:
            self.nlp = spacy.load('en_core_web_sm')
            debug_print("[INFO]", f"Modello linguistico EN_CORE_WEB_SM caricato con successo.")
        except OSError:
            debug_print("[ERROR]", f"Il modello linguistico 'EN_CORE_WEB_SM non è stato trovato. Per favore, scaricalo utilizzando 'python -m spacy download'.")
            raise
        
        self.nlp = spacy.load('en_core_web_sm')  # Cambia la lingua se necessario
        self.sentence_tokenization = sentence_tokenization
        self.advanced_tokenization = advanced_tokenization

        
    ### General Cleaning Functions

    def convert_to_lowercase_func(self, text, lowercase=True):
        """
        Converts the text to lowercase if the lowercase option is set to True.
        
        Args:
            text (str): The text to be converted.
            lowercase (bool): If True, converts the text to lowercase.
        
        Returns:
            str: The text converted to lowercase, if specified.
        """
        if lowercase:
            text = text.lower()
            debug_print("[INFO]", f"Text after converting to lowercase: '{text}'")
        return text
    
    def remove_links_func(self, text, remove_links=True):
        """
        Removes valid URLs from the text if the remove_links option is set to True.
        Ensures that words containing 'http' or 'www' are not removed unless they are part of a valid URL.

        Args:
            text (str): The text to be processed.
            remove_links (bool): If True, removes URLs from the text.

        Returns:
            str: The text with URLs removed, if specified.
        """
        if remove_links:
            # Pattern to match URLs starting with http://, https://, or www.,
            # ensuring they are not part of a larger word
            pattern = r'(?<!\w)(https?://\S+|www\.\S+)'
            
            # Remove matched URLs
            text = re.sub(pattern, '', text)
            debug_print("[INFO]", f"Text after removing links: '{text}'")
            
            # Remove any extra spaces introduced by removing URLs
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after cleaning spaces post link removal: '{text}'")
        
        return text
      
    def remove_consecutive_repeats_func(self, text, remove_repeats=True):
        """
        Removes consecutive repeated words from the text if the remove_repeats option is set to True.

        Args:
            text (str): The text to be processed.
            remove_repeats (bool): If True, removes consecutive repeated words from the text.

        Returns:
            str: The text with consecutive repeated words removed, if specified.
        """
        if remove_repeats:
            # Pattern to find consecutive repeated words, ignoring case and allowing for optional punctuation/spaces
            pattern = r'(?i)\b(\w+)\b[\s,.;:]*\1+'

            # Continue replacing until no more consecutive repeats are found
            previous_text = None
            while previous_text != text:
                previous_text = text
                text = re.sub(pattern, r'\1', text)

            # Log the final cleaned text
            debug_print("[INFO]", f"Text after removing consecutive repeated words: '{text}'")

        return text
    
    def remove_digits_func(self, text, remove_digits=True):
        """
        Removes digits from the text if the remove_digits option is set to True.

        Args:
            text (str): The text to be processed.
            remove_digits (bool): If True, removes digits from the text.

        Returns:
            str: The text with digits removed, if specified.
        """
        if remove_digits:
            original_text = text  # Preserve the original text for debugging

            # Remove all digits from the text
            text = re.sub(r'\d+', '', text)
            debug_print("[INFO]", f"Text after removing digits: '{text}'")

            # Remove any extra spaces introduced by digit removal
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after cleaning spaces post digit removal: '{text}'")

        return text
    
    def remove_punctuation_func(self, text, remove_punctuation=True, preserve_file_extensions=False):
        """
        Removes punctuation from the text based on the specified options.

        Args:
            text (str): The text to be processed.
            remove_punctuation (bool): If True, removes punctuation from the text.
            preserve_file_extensions (bool): If True, preserves periods in file extensions like .exe, .dll, etc.

        Returns:
            str: The text with punctuation removed, if specified.
        """
        if remove_punctuation:
            if preserve_file_extensions:
                # Preserve dots in file extensions by removing dots not associated with words
                text = re.sub(r'(?<!\w)\.(?!\w)', '', text)  # Remove dots not part of words
                # Replace hyphens and slashes with spaces to prevent words from joining
                text = text.replace('-', ' ').replace('/', ' ')
                # Remove all punctuation except dots
                text = text.translate(str.maketrans('', '', string.punctuation.replace('.', '')))
            else:
                # Replace hyphens and slashes with spaces to prevent words from joining
                text = text.replace('-', ' ').replace('/', ' ')
                # Remove all punctuation
                text = text.translate(str.maketrans('', '', string.punctuation))
            
            debug_print("[INFO]", f"Text after removing punctuation: '{text}'")

        return text
   
    def remove_space_newline_func(self, text, remove_space_newline=True):
        """
        Removes newline characters (\n), carriage returns (\r), tab characters (\t),
        and extra spaces from the text if the clean option is set to True.

        Args:
            text (str): The text to be processed.
            clean (bool): If True, cleans the text by removing specified characters and extra spaces.

        Returns:
            str: The cleaned text, if specified.
        """
        if remove_space_newline:
            original_text = text  # Preserve the original text for debugging

            # Remove newline characters, carriage returns, and tab characters
            text = text.replace('\n', ' ').replace('\t', ' ').replace('\r', ' ')
            debug_print("[INFO]", f"Text after removing newline, carriage return, and tab characters: '{text}'")

            # Remove extra spaces using regex
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after removing extra spaces: '{text}'")

        return text
    
    def remove_puncts_func(self, text, remove_puncts=True):
        
        if remove_puncts:
            # Rimuovi i ";" e ","
            text = text.replace(";", "").replace(",", "")
            
            # Rimuovi i punti che separano frasi ma non rimuovere i punti nelle estensioni dei file o nei numeri
            # La regex trova i punti seguiti da uno spazio e una lettera maiuscola (indicativo di una nuova frase).
            text = re.sub(r'(?<=\w)\.(?=\s+[A-Z])', '', text)
            
            # Rimuovi eventuali spazi, tabulazioni, e a capo extra
            text = re.sub(r'\s+', ' ', text).strip()
            
            debug_print("[INFO]", f"Final text after puncts and other removal: '{text}'")
        return text
    
    def remove_parentheses_content_func(self, text, remove_parentheses_content=True):
        """
        Removes all content within parentheses, including the parentheses themselves, from the text
        if the remove_parentheses_content option is set to True.

        Args:
            text (str): The text to be processed.
            remove_parentheses_content (bool): If True, removes content within parentheses.

        Returns:
            str: The text with content within parentheses removed, if specified.
        """
        if remove_parentheses_content:
            # Remove all content within parentheses including the parentheses
            text = re.sub(r'\(.*?\)', '', text)
            debug_print("[INFO]", f"Text after removing parentheses content: '{text}'")

            # Remove any extra spaces introduced by the removal
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after cleaning spaces post parentheses removal: '{text}'")

        return text
    
    def remove_special_characters_func(self, text, remove_special_characters=True):
        """
        Rimuove i caratteri speciali dal testo se l'opzione remove_special_characters è impostata a True.
        
        Args:
            text (str): Il testo da elaborare.
            remove_special_characters (bool): Se True, rimuove i caratteri speciali dal testo.
        
        Returns:
            str: Il testo senza caratteri speciali, se specificato.
        """
        if remove_special_characters:
            original_text = text
            text = re.sub(r'[^\w\s]', '', text)
            debug_print("[INFO]", f"Testo dopo rimozione dei caratteri speciali: '{text}'")
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Testo finale dopo pulizia degli spazi: '{text}'")
            return text
        return text

    def remove_dates_and_months_func(self, text, remove_dates=True):
        """
        Removes dates and month names from the text if the remove option is set to True.

        Args:
            text (str): The text to be processed.
            remove (bool): If True, removes dates and month names from the text.

        Returns:
            str: The text with dates and month names removed, if specified.
        """
        if remove_dates:
            original_text = text  # Preserve the original text for debugging

            # Remove dates in the format DD/MM/YYYY or DD-MM-YYYY
            date_pattern1 = r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'
            text = re.sub(date_pattern1, '', text)
            debug_print("[INFO]", f"Text after removing dates (pattern1): '{text}'")

            # Remove dates in the format YYYY/MM/DD or YYYY-MM-DD
            date_pattern2 = r'\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b'
            text = re.sub(date_pattern2, '', text)
            debug_print("[INFO]", f"Text after removing dates (pattern2): '{text}'")

            # Remove full month names and their abbreviations, case-insensitive
            months_regex = r'\b(January|February|March|April|May|June|July|August|' \
                          r'September|October|November|December|' \
                          r'Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b'
            text = re.sub(months_regex, '', text, flags=re.IGNORECASE)
            debug_print("[INFO]", f"Text after removing months: '{text}'")

            # Remove any extra spaces introduced by removals
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after removing dates and months: '{text}'")

        return text
    
    def expand_contractions_func(self, text, expand_contractions=True):
        """
        Espande le contrazioni nel testo se l'opzione expand è impostata a True.
        
        Args:
            text (str): Il testo da elaborare.
            expand (bool): Se True, espande le contrazioni nel testo.
        
        Returns:
            str: Il testo con le contrazioni espanse, se specificato.
        """
        if expand_contractions:
            original_text = text
            expanded_text = contractions.fix(text)
            debug_print("[INFO]", f"Testo dopo espansione delle contrazioni: '{expanded_text}'")
            expanded_text = re.sub(r'\s{2,}', ' ', expanded_text).strip()
            debug_print("[INFO]", f"Testo finale dopo pulizia degli spazi: '{expanded_text}'")
            return expanded_text
        return text

    ### Specific Software Cleaning Functions ###

    def remove_version_info_func(self, text, remove_versions=True):
        """
        Removes all version and patch number information from the text.
        
        Args:
            text (str): The text containing version information.
            remove_versions (bool): If True, removes version information from the text.
        
        Returns:
            str: The text without version information.
        """
        if remove_versions:
            version_phrases = [
                r'\b\d+(\.\d+)*\.x before \d+(\.\d+)*', 
                r'\b\d+:\d+\.\d+(\.\d+)?(\.x)?\b', 
                r'\bbefore \d+:\d+\.\d+(\.\d+)?(\.x)?\b',  
                r'\bversions?\b\s*\d+(\.\d+)*\b',  
                r'\bversions?\b.*?\b\d+(\.\d+)*\.x',  
                r'\bv\.?\s*\d+(\.\d+)*',
                r'\b(?:rc\d+)\b',
                r'\b\d+(?:\.\d+){0,2}[-.]?rc\d+\b',
                r'\b\d+(\.\d+)* and earlier',  
                r'\b\d+(\.\d+)* and later',  
                r'\b\d+(\.\d+)* and below',  
                r'\bservice pack \d+(\.\d+)?\b',
                r'\bsp\d+(\.\d+)?\b',
                r'\branging from \b\d+(\.\d+)*.*? to \d+(\.\d+)*',  
                r'\bfrom version \d+(\.\d+)* to version \d+(\.\d+)*',  
                r'\bup to and including version \d+(\.\d+)*',  
                r'\bbefore \d+(\.\d+)*',  
                r'\bversions? \d+(\.\d+){1,2} through \d+(\.\d+){1,2}\b',
                r'\bincluding \d+(\.\d+){1,3}',
                r'\bincluding versions?\b.*?\b\d+(\.\d+)*',
                r'\bexcluding \d+(\.\d+){1,3}',
                r'\bthrough \d+(\.\d+)*',
                r'\bpatch \d+(\.\d+)*',
                r'\brelease \d+(\.\d+)*',
                r'\bbefore build \d+(\.\d+)*',
                r'\bbuild \d+(\.\d+)*',
                r'\bupdate \d+(\.\d+)*',
                r'\b(\d+(\.\d+){1,3})(, \d+(\.\d+){1,3})*( and \d+(\.\d+){1,3})?\b',
                r'\b\d+\.\d+\.\d+',
                r'\b\d+\.\d+',
                r'\b\d+\.x\b',
                r'\b\d+\.\d+\.x\b',
                r'(?<=, )\.x\b',
                r'\b\.x\b',
                r'\bCVE-\d{4}-\d{4,7}(, CVE-\d{4}-\d{4,7})*( and CVE-\d{4}-\d{4,7})?\b', 
            ]

            combined_pattern = r'(' + '|'.join(version_phrases) + r')'
            text = re.sub(combined_pattern, '', text, flags=re.IGNORECASE)
            #text = re.sub(r'\b(and|or|,|are|is)\b', '', text, flags=re.IGNORECASE)
            text = re.sub(r'\s*,\s*', ', ', text)
            text = re.sub(r'\s{2,}', ' ', text).strip()
            text = re.sub(r'\s*,\s*$', '', text)
            debug_print("[INFO]", f"Text after removing version information: '{text}'")

        return text

    def remove_entities_references_func(self, text, remove_entities=True):
        """
        Removes references to CVE, CWE, and CAPEC identifiers from the text if the remove_cve option is set to True.

        Args:
            text (str): The text to be processed.
            remove_cve (bool): If True, removes CVE, CWE, and CAPEC references from the text.

        Returns:
            str: The text with CVE, CWE, and CAPEC references removed, if specified.
        """
        if remove_entities:
            original_text = text  # Preserve the original text for debugging

            # Remove CVE references (e.g., CVE-2021-34527)
            cve_pattern = r'(?i)CVE-\d{4}-\d{4,7}'
            text = re.sub(cve_pattern, '', text)
            debug_print("[INFO]", f"Text after removing CVE references: '{text}'")

            # Remove CWE references (e.g., CWE-79)
            cwe_pattern = r'(?i)CWE-\d{1,5}'
            text = re.sub(cwe_pattern, '', text)
            debug_print("[INFO]", f"Text after removing CWE references: '{text}'")

            # Remove CAPEC references (e.g., CAPEC-1234)
            capec_pattern = r'(?i)CAPEC-\d{1,5}'
            text = re.sub(capec_pattern, '', text)
            debug_print("[INFO]", f"Text after removing CAPEC references: '{text}'")

            # Remove any extra spaces introduced by removals
            text = re.sub(r'\s+', ' ', text).strip()
            debug_print("[INFO]", f"Final text after removing CVE, CWE, and CAPEC references: '{text}'")

        return text

    ### File Related Cleaning
    
    def remove_file_paths_func(self, text, remove_paths=True):
        """
        Removes file and directory paths from the text if the remove_paths option is set to True.
        
        Args:
            text (str): The text to be processed.
            remove_paths (bool): If True, removes file and directory paths from the text.
        
        Returns:
            str: The text with file paths removed, if specified.
        """
        if remove_paths:
            text = re.sub(r'(?:(?:[A-Za-z]:)?[\/][\w.-]+(?:[\/][\w.-]+)*)|(?:[\/][\w.-]+(?:[\/][\w.-]+)*)+', '', text)
            text = re.sub(r'\s+', ' ', text).strip()  # Remove extra spaces
            debug_print("[INFO]", f"Text after removing file paths: '{text}'")
        return text
    
    def remove_file_names_func(self, text, remove_file_names=True):
        """
        Removes file names with specific extensions from the text if the remove_file_names option is set to True.

        Args:
            text (str): The text to be processed.
            remove_file_names (bool): If True, removes file names from the text.

        Returns:
            str: The text with file names removed, if specified.
        """
        if remove_file_names:
            original_text = text  # Preserve the original text for debugging

            # Define the regex pattern to match file names with specified extensions
            file_extensions = (
                "exe|execute|dll|pdf|docx|txt|jpg|jpeg|png|gif|bmp|tiff|"
                "mp3|wav|mp4|avi|mkv|zip|rar|tar|gz|csv|xlsx|pptx|html|xml|json|log"
            )
            file_name_pattern = rf'\b\w+\.({file_extensions})\b'

            # Remove file names matching the pattern
            text = re.sub(file_name_pattern, '', text)
            debug_print("[INFO]", f"Text after removing file names: '{text}'")

            # Remove any extra spaces introduced by removals
            text = re.sub(r'\s+', ' ', text).strip()
            debug_print("[INFO]", f"Final text after cleaning spaces post file name removal: '{text}'")

        return text
    
    def replace_file_paths_func(self, text, replace_file_paths=True):
        """
        Replaces file paths in the text with 'path' for directory paths or 'file ext' for file paths based on their extensions.
        
        Args:
            text (str): The text to be processed.
            replace_file_paths (bool): If True, replaces file paths in the text.
        
        Returns:
            str: The text with file paths replaced, if specified.
        """
        if replace_file_paths:
            # Replace directory paths with 'path' and file paths with 'file ext'
            text = re.sub(
                r'(?:(?:[A-Za-z]:)?[\\/][\w.-]+(?:[\\/][\w.-]+)*)|(?:[\\/][\w.-]+(?:[\\/][\w.-]+)*)+',
                lambda m: 'path' if m.group(0).endswith('/') or m.group(0).endswith('\\') 
                        else f"{m.group(0).split('.')[-1]} file" if '.' in m.group(0) 
                        else 'file', 
                text
            )
            # Remove extra spaces
            text = re.sub(r'\s+', ' ', text).strip()
            debug_print("[INFO]", f"Text after removing file paths: '{text}'")
        return text

    ### General Language Cleaning Functions ###

    def remove_stop_words_func(self, text, remove_stop_words=True):
        """
        Removes stop words from the text if the remove_stop_words option is set to True.

        Args:
            text (str): The text to be processed.
            remove_stop_words (bool): If True, removes stop words from the text.

        Returns:
            str: The text with stop words removed, if specified.
        """
        if remove_stop_words:
            # Remove stop words using list comprehension
            text = ' '.join([word for word in text.split() if word.lower() not in self.stopwords])
            debug_print("[INFO]", f"Text after removing stop words: '{text}'")
            
            # Remove extra spaces
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[INFO]", f"Final text after cleaning spaces post stop words removal: '{text}'")
        
        return text
    
    def lemmatize_func(self, text, lemmatize=True):
        """
        Esegue la lemmatizzazione del testo utilizzando spaCy se l'opzione lemmatize è impostata a True.

        Args:
            text (str): Il testo da lemmatizzare.
            lemmatize (bool): Se True, esegue la lemmatizzazione sul testo.

        Returns:
            str: Il testo lemmatizzato, se specificato.
        """
        if lemmatize:
            original_text = text  # Conserva il testo originale per il debug

            # Processa il testo con spaCy
            doc = self.nlp(text)

            # Estrae i lemmi di ciascun token
            lemmatized_tokens = [token.lemma_ for token in doc]

            # Ricostruisce il testo lemmatizzato
            lemmatized_text = ' '.join(lemmatized_tokens)
            debug_print("[INFO]", f"Testo dopo la lemmatizzazione: '{lemmatized_text}'")

            # Rimuove eventuali spazi multipli introdotti dalla lemmatizzazione
            lemmatized_text = re.sub(r'\s{2,}', ' ', lemmatized_text).strip()
            debug_print("[INFO]", f"Testo finale dopo la pulizia degli spazi post lemmatizzazione: '{lemmatized_text}'")

            return lemmatized_text

        return text
    
    def simple_tokenization_func(self, text, sentence_tokenization=True):
        """
        Tokenizza il testo suddividendolo in frasi se l'opzione sentence_tokenization è impostata a True.
    
        Args:
            text (str): Il testo da elaborare.
            sentence_tokenization (bool): Se True, suddivide il testo in frasi.
    
        Returns:
            str: Il testo tokenizzato in frasi, se specificato.
        """
        if sentence_tokenization:
            original_text = text  # Conserva il testo originale per il debug
            
            # Utilizza NLTK per la tokenizzazione delle frasi
            sentences = sent_tokenize(text)
            tokenized_text = ' '.join(sentences)  # Puoi mantenere le frasi separate, ad esempio con '\n'.join(sentences)
            debug_print("[INFO]", f"Testo dopo tokenizzazione in frasi: '{tokenized_text}'")
            
            # Rimuove eventuali spazi multipli introdotti dalla tokenizzazione
            tokenized_text = re.sub(r'\s{2,}', ' ', tokenized_text).strip()
            debug_print("[INFO]", f"Testo finale dopo pulizia degli spazi post tokenizzazione in frasi: '{tokenized_text}'")
            
            return tokenized_text
        
        return text

    def advanced_tokenization_func(self, text, advanced_tokenization=True):
        """
        Esegue una tokenizzazione avanzata rimuovendo la punteggiatura se l'opzione advanced_tokenization è impostata a True.
    
        Args:
            text (str): Il testo da elaborare.
            advanced_tokenization (bool): Se True, esegue una tokenizzazione avanzata rimuovendo la punteggiatura.
    
        Returns:
            str: Il testo tokenizzato e pulito dalla punteggiatura, se specificato.
        """
        if advanced_tokenization:
            original_text = text  # Conserva il testo originale per il debug
            
            # Processa il testo con spaCy
            doc = self.nlp(text)
            
            # Estrae i token rimuovendo la punteggiatura
            tokens = [token.text for token in doc if not token.is_punct]
            tokenized_text = ' '.join(tokens)
            debug_print("[INFO]", f"Testo dopo tokenizzazione avanzata: '{tokenized_text}'")
            
            # Rimuove eventuali spazi multipli introdotti dalla tokenizzazione
            tokenized_text = re.sub(r'\s{2,}', ' ', tokenized_text).strip()
            debug_print("[INFO]", f"Testo finale dopo pulizia degli spazi post tokenizzazione avanzata: '{tokenized_text}'")
            
            return tokenized_text
        
        return text

    def convert_genitive_to_of_func(self, text, genitive=True):
        """
        Converte le costruzioni possessive in inglese (genitivo sassone) nel formato "of".
        Ad esempio, "A holiday's day" diventa "A day of holiday".
        
        Args:
            text (str): Il testo da elaborare.
        
        Returns:
            str: Il testo elaborato con le costruzioni possessive convertite.
        """
        if genitive:
            debug_print("[INFO]", "Inizio conversione del genitivo sassone.")
            
            # Pattern per il possessivo singolare (X's Y)
            pattern_singular = r"\b(\w+)'s\s+(\w+)\b"
            # Pattern per il possessivo plurale (Xs' Y)
            pattern_plural = r"\b(\w+)'\s+(\w+)\b"
            
            # Funzione di sostituzione per il possessivo singolare
            def replace_singular(match):
                possessor = match.group(1)
                possessed = match.group(2)
                replacement = f"{possessed} of {possessor}"
                debug_print("[DEBUG]", f"Sostituzione singolare: '{match.group(0)}' -> '{replacement}'")
                return replacement
            
            # Funzione di sostituzione per il possessivo plurale
            def replace_plural(match):
                possessor = match.group(1)
                possessed = match.group(2)
                replacement = f"{possessed} of {possessor}"
                debug_print("[DEBUG]", f"Sostituzione plurale: '{match.group(0)}' -> '{replacement}'")
                return replacement
            
            # Prima sostituzione per il possessivo singolare
            text = re.sub(pattern_singular, replace_singular, text)
            # Seconda sostituzione per il possessivo plurale
            text = re.sub(pattern_plural, replace_plural, text)
            
            # Rimuovere eventuali spazi multipli creati dalle sostituzioni
            text = re.sub(r'\s{2,}', ' ', text).strip()
            debug_print("[DEBUG]", f"Testo dopo la conversione del genitivo sassone: '{text}'")
            
            debug_print("[INFO]", "Conversione del genitivo sassone completata.")
        return text
    
    def clean_text(self, text, cpe_uris=None):
        """
        Ripulisce una stringa di testo secondo le opzioni definite.
        :param text: Stringa di testo da ripulire.
        :param cpe_uris: Lista di CPE URIs da preprocessare.
        :return: Testo ripulito.
        """
        # Rimuove la punteggiatura
        text = self.remove_puncts_func(text, self.remove_puncts)

        # Converti in minuscolo
        text = self.convert_to_lowercase_func(text, self.lowercase)
        
        # Rimuovi spazi extra
        text = self.remove_space_newline_func(text, self.remove_space_newline)

        # Genitivo sassone
        text = self.convert_genitive_to_of_func(text, self.genitive)

        # Se l'opzione per la rimozione delle informazioni sulle versioni è abilitata
        text = self.remove_version_info_func(text, self.remove_versions)

        # Rimozioni dei nomi dei prodotti e software all'interno della CVE
        text = process_cpe_uris_in_text(text, cpe_uris, self.remove_products)

        # Rimuovi riferimenti a CVE
        text = self.remove_entities_references_func(text, self.remove_entities)

        # Rimuovi date
        text = self.remove_dates_and_months_func(text, self.remove_dates)

        # Rimuovi i link
        text = self.remove_links_func(text, self.remove_links)

        # Espandi le contrazioni tipo I don't in I do not
        text = self.expand_contractions_func(text, self.expand_contractions)

        # Tokenizza il testo in frasi
        text = self.simple_tokenization_func(text, self.sentence_tokenization)

        # Esegui lemmatizzazione se abilitata
        text = self.lemmatize_func(text, self.lemmatize)

        # Rimuovi i percorsi dei file e delle directory
        text = self.remove_file_paths_func(text, self.remove_file_paths)
        
        # Rimuovi i caratteri speciali
        text = self.remove_special_characters_func(text, self.remove_special_characters)
  
        # Sostituisci i percorsi dei file con "file ext"
        text = self.replace_file_paths_func(text, self.replace_file_paths)

        # Tokenizzazione avanzata
        text = self.advanced_tokenization_func(text, self.advanced_tokenization)

        # Rimuove stop words
        text = self.remove_stop_words_func(text, self.remove_stop_words)
        
        # Rimuovi nomi di file
        text = self.remove_file_names_func(text, self.remove_file_names)

        # Rimuovi numeri
        text = self.remove_digits_func(text, self.remove_digits)

        # Rimuovi il contenuto tra parentesi
        text = self.remove_parentheses_content_func(text, self.remove_parentheses_content)

        # Rimuovi la punteggiatura
        text = self.remove_punctuation_func(text, self.remove_punctuation, self.preserve_file_extensions)

        # Rimuove ripetizioni di parole consecutive
        text = self.remove_consecutive_repeats_func(text, self.remove_consecutive_repeat)

        # Rimuovi spazi extra
        text = self.remove_space_newline_func(text, self.remove_space_newline)

        text = self.remove_puncts_func(text, self.remove_puncts)

        debug_print("[RESULT]", f"Final text cleaned: '{text}'")
        
        return text

# Esempio di utilizzo

if __name__ == "__main__":
    cleaner = TextCleaner()
    text = """The MD5 Message-Digest Algorithm is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of MD5 in the signature algorithm of an X.509 certificate."""
    
    cpe_uris = [
        "cpe:2.3:a:ietf:md5:-:*:*:*:*:*:*:*",  
        "cpe:2.3:a:apple:webkit:*:*:*:*:*:*:*:*",  # Esempio di CPE URI
    ]
    
    # Ripulisci il testo
    cleaned_text = cleaner.clean_text(text)
    
    # Stampa il testo ripulito
    print(f"Testo ripulito: '{cleaned_text}'")

    print(cleaner.find_software_names(text))
