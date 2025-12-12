
import re
from fuzzywuzzy import fuzz
from debug.debug_utils import debug_print


class CPE:
    def __init__(self, cpe_type, vendor, product):
        self.cpe_type = cpe_type
        self.vendor = vendor
        self.product = product
        self.versions = []
        self.updates = []
        self.editions = []
        self.languages = []
        self.sw_editions = []
        self.target_sws = []
        self.target_hws = []

    def add_details(self, version, update, edition, language, sw_edition, target_sw, target_hw):
        if version not in self.versions and version not in ['*', '-']:
            self.versions.append(version)
        if update not in self.updates and update not in ['*', '-']:
            self.updates.append(update)
        if edition not in self.editions and edition not in ['*', '-']:
            self.editions.append(edition)
        if language not in self.languages and language not in ['*', '-']:
            self.languages.append(language)
        if sw_edition not in self.sw_editions and sw_edition not in ['*', '-']:
            self.sw_editions.append(sw_edition)
        if target_sw not in self.target_sws and target_sw not in ['*', '-']:
            self.target_sws.append(target_sw)
        if target_hw not in self.target_hws and target_hw not in ['*', '-']:
            self.target_hws.append(target_hw)

    def get_type(self):
        return self.cpe_type

    def get_vendor(self):
        return self.vendor

    def get_product(self):
        return self.product

    def get_versions(self):
        return self.versions

    def get_updates(self):
        return self.updates

    def get_editions(self):
        return self.editions

    def get_languages(self):
        return self.languages

    def get_sw_editions(self):
        return self.sw_editions

    def get_target_sws(self):
        return self.target_sws

    def get_target_hws(self):
        return self.target_hws


def aggregate_cpe_uris(cpe_uri_list):
    print("Inizio aggregazione CPE URIs")
    aggregated_data = {}

    for cpe_uri in cpe_uri_list:
        # Verifica se il CPE inizia con "cpe:2.3:"
        if not cpe_uri.startswith("cpe:2.3:"):
            print(f"Skipped invalid CPE: {cpe_uri} (does not start with 'cpe:2.3:')")
            continue

        parts = cpe_uri.split(':')

        # Verifica la lunghezza delle parti
        if len(parts) < 10:  # Deve avere almeno 10 parti
            print(f"Skipped malformed CPE: {cpe_uri} (not enough parts)")
            continue
        
        # Aggiungi ":*" se l'ultimo campo manca
        if len(parts) == 10:
            parts.append('*')  # Aggiungiamo un valore di default per l'ultimo campo
        
        # Estrai i campi necessari, ignorando "cpe:2.3"
        cpe_type, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw = parts[2:12]

        # Creiamo una chiave unica per type, vendor e product
        key = (cpe_type, vendor, product)

        if key not in aggregated_data:
            aggregated_data[key] = CPE(cpe_type, vendor, product)

        # Aggiungi i dettagli all'oggetto CPE
        aggregated_data[key].add_details(version, update, edition, language, sw_edition, target_sw, target_hw)

    # Creiamo la lista finale
    result = list(aggregated_data.values())

    print("Aggregazione completata")
    return result

def normalize_cpe_uri(cpe_uri):
    """Normalizza i nomi di vendor e prodotto rimuovendo underscore e abbassando il case."""
    return cpe_uri.replace('_', ' ').strip().lower()

def preprocess_cpe_uris(cpe_uris):
    """Processa una lista di CPE URIs ed estrae i campi rilevanti in base al formato standard CPE."""
    processed_uris = []

    for cpe_uri in cpe_uris:
        # Dividi il CPE URI nei suoi componenti
        parts = cpe_uri.split(':')

        # Controlla se il CPE URI ha abbastanza parti
        if len(parts) < 11:
            continue  # Non ci sono abbastanza parti per processare

        # Estrai i campi rilevanti in base al formato CPE
        part = parts[2]  # Tipo (application, OS, hardware)
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        update = parts[6]
        edition = parts[7]
        language = parts[8]
        sw_edition = parts[9]
        sw_target = parts[10]  # Assicurati di controllare che questo sia l'indice corretto

        # Costruisci un elenco di campi
        fields = [
            part,
            vendor,
            product,
            version,
            update,
            edition,
            sw_edition,
            language,
            sw_target
        ]

        # Stampa dei valori dei campi con i relativi indici
        for index, value in enumerate(fields):
            debug_print("[DEBUG]", f"Index: {index}, Campo: '{value}'")

        # Solo aggiungi alla lista processata se abbiamo campi
        if fields:
            processed_uris.append(fields)

    return processed_uris

def cpe_type_to_string(part):
    """Converti il tipo CPE in una stringa più leggibile."""
    if part == 'a':
        return 'application'
    elif part == 'h':
        return 'hardware'
    elif part == 'o':
        return 'operating system'
    return part

def find_exact_matches(term, text):
    """Trova tutte le corrispondenze esatte di una stringa in un testo, ignorando maiuscole e minuscole."""
    # Normalizza il termine e il testo in minuscolo
    term_lower = term.lower()
    text_lower = text.lower()

    # Trova le corrispondenze utilizzando espressioni regolari
    matches = re.findall(r'\b' + re.escape(term_lower) + r'\b', text_lower)
    
    # Trova le posizioni delle corrispondenze
    positions = []
    start = 0
    
    for match in matches:
        start = text_lower.find(term_lower, start)
        if start != -1:
            positions.append(start)
            start += len(term_lower)  # Sposta l'indice per cercare la prossima occorrenza

    return matches, positions

def find_partial_matches(vendor, product, text):
    """Trova le corrispondenze parziali di vendor e product nel testo e restituisce le posizioni e la lunghezza delle corrispondenze."""
    # Normalizza il vendor e il product in minuscolo
    vendor_normalized = vendor.lower() if vendor else ""
    product_normalized = product.lower()
    
    matches = []

    # Se il vendor è vuoto, gestiamo le parole del product
    if not vendor_normalized and len(product_normalized.split()) > 1:
        product_words = product_normalized.split()
        n = len(product_words)

        # Crea tutte le combinazioni ordinate di n-1 parole
        for i in range(n):
            pattern = re.compile(r'\b(?:' + r'\s+'.join(re.escape(product_words[j]) for j in range(n) if j != i) + r')\b', re.IGNORECASE)
            for match in pattern.finditer(text):
                matched_string = match.group()
                position = match.start()
                length = len(matched_string)
                matches.append((matched_string, position, length))

    # Caso 1: Vendor incompleto seguito da product
    if vendor_normalized:
        incomplete_pattern = re.compile(rf'\b{re.escape(vendor_normalized.split()[0])}\b\s+{re.escape(product_normalized)}', re.IGNORECASE)
        for match in incomplete_pattern.finditer(text):
            matched_string = match.group()
            position = match.start()
            length = len(matched_string)
            matches.append((matched_string, position, length))

    # Caso 2: Vendor completo seguito da una o più parole (o numeri) e poi product
    if vendor_normalized:
        complete_pattern = re.compile(rf'\b{re.escape(vendor_normalized)}\b\s+(\w+\s+){0,2}{re.escape(product_normalized)}', re.IGNORECASE)
        for match in complete_pattern.finditer(text):
            matched_string = match.group()
            position = match.start()
            length = len(matched_string)
            matches.append((matched_string, position, length))

    return matches

def find_all_fuzzy_correspondaces(term, text, threshold=70):
    """Trova tutte le corrispondenze fuzzy per un termine nel testo e restituisce le posizioni e la lunghezza delle corrispondenze."""
    # Normalizza il termine da cercare
    term_lower = term.lower()
    debug_print("[INFO]", f"Termine cercato (normalizzato): '{term_lower}'")

    # Divide il testo in parole
    words = re.findall(r'\b\w+\b|\W', text)
    debug_print("[INFO]", f"Testo diviso in parole: {words}")

    matches = []

    # Combina le parole per controllare le corrispondenze fuzzy
    for i in range(len(words)):
        for j in range(i + 1, len(words) + 1):
            # Combina le parole da i a j
            combined_string = ''.join(words[i:j]).strip().lower()  # Normalizza la stringa combinata
            score = fuzz.partial_ratio(combined_string, term_lower)

            debug_print("[INFO]", f"Controllando combinazione: '{combined_string}', punteggio: {score}")

            # Controlla se il punteggio supera la soglia
            if score > threshold:
                position = sum(len(w) for w in words[:i]) + sum(1 for w in words[:i] if w.strip())  # Calcola la posizione
                length = len(combined_string)
                matches.append((combined_string, position, length))
                debug_print("[INFO]", f"Match trovato: '{combined_string}', Posizione: {position}, Lunghezza: {length}")

    if not matches:
        debug_print("[WARNING]", f"Nessun match trovato per '{term}' sopra la soglia di {threshold}")

    return matches

def find_all_fuzzy_matches(term, text, threshold=70):
    """Trova tutte le corrispondenze fuzzy per un termine nel testo e restituisce le posizioni e la lunghezza delle corrispondenze."""
    term_lower = term.lower()
    debug_print("[INFO]", f"Termine cercato (normalizzato): '{term_lower}'")

    matches = []

    # Usa re.finditer per ottenere le posizioni di tutte le parole
    for match in re.finditer(r'\b\w+\b', text):
        word = match.group()
        clean_word = word.lower()

        # Calcola il punteggio di similarità fuzzy
        score = fuzz.ratio(clean_word, term_lower)
        debug_print("[INFO]", f"Controllando parola: '{clean_word}', punteggio: {score}")

        # Controlla se il punteggio supera la soglia
        if score > threshold:
            position = match.start()  # Posizione iniziale della corrispondenza
            length = len(word)
            matches.append((word, position, length))
            debug_print("[INFO]", f"Match trovato: '{word}', Posizione: {position}, Lunghezza: {length}")
            debug_print("[INFO]", f"Testo attuale con match: '{text}'")

    if not matches:
        debug_print("[WARNING]", f"Nessun match trovato per '{term}' sopra la soglia di {threshold}")

    debug_print("[INFO]", f"Matches finali: {matches}")
    return matches  # Assicurati di restituire i matches trovati

def replace_word_in_text(text, word_to_find, replacement):
    if not isinstance(text, str):
        raise ValueError("Il parametro 'text' deve essere una stringa.")
    
    if ' ' in word_to_find:  # Controllo se ci sono spazi
        return text
    
    parts = []
    word_length = len(word_to_find)

    for i in range(1, word_length):
        part1 = word_to_find[:i]
        part2 = word_to_find[i:]
        parts.append((part1, part2))

        for j in range(i + 1, word_length):
            part1 = word_to_find[:i]
            part2 = word_to_find[i:j]
            part3 = word_to_find[j:]
            if part2:  # Se part2 non è vuoto
                parts.append((part1, part2, part3))


    for combination in parts:
        combined_pattern = r'\b' + r'\s+'.join(re.escape(part) for part in combination) + r'\b'
        pattern = re.compile(combined_pattern, re.IGNORECASE)
        if pattern.search(text):
            text = pattern.sub(replacement, text)
            replacements_made = True
            debug_print("[INFO]", f"Sostituzione: '{combination}' con '{replacement}' nel testo.")

    return text

def process_cpe_uris_in_text(text, cpe_uris, remove_products):
    """Processa il testo con una lista di CPE URIs e aggiorna il testo in base ai CPE."""

    if remove_products and cpe_uris:
        # Normalizza il testo
        text = text.lower().strip()
        debug_print("[INFO]", f"Testo normalizzato: '{text}'")

        # Crea una struttura fattada CPE Uris
        cpe_list = aggregate_cpe_uris(cpe_uris)

        for cpe_uri in cpe_list:
            part = cpe_type_to_string(cpe_uri.get_type())  # Tipo (application, OS, hardware)
            vendor = cpe_uri.get_vendor()
            product = cpe_uri.get_product()
            
            # Normalizza vendor e product
            vendor_normalized = normalize_cpe_uri(vendor)
            product_normalized = normalize_cpe_uri(product)
            
            # Crea la stringa combinata
            combined_string = f"{vendor_normalized} {product_normalized}"
            
            # 1) Ricerca esatta e sostituzione
            exact_matches, positions = find_exact_matches(combined_string, text)
            for match, position in zip(exact_matches, positions):
                text = text[:position] + part + text[position + len(match):]
                debug_print("[INFO]", f"Sostituzione esatta: '{match}' con '{part}' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione esatta: '{text}'")

            # 2) Ricerca parziale e sostituzione
            partial_matches = find_partial_matches(vendor_normalized, product_normalized, text)
            for matched_string, position, length in partial_matches:
                text = text[:position] + part + text[position + length:]
                debug_print("[INFO]", f"Sostituzione parziale: '{matched_string}' con '{part}' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione parziale: '{text}'")


            fuzzy_matches = find_all_fuzzy_matches(combined_string, text)
            # Ordinare i match dalla fine all'inizio per evitare problemi di posizionamento
            fuzzy_matches_sorted = sorted(fuzzy_matches, key=lambda x: x[1], reverse=True)

            for matched_string, position, matched_length in fuzzy_matches_sorted:
                debug_print("[INFO]", f"Sostituzione fuzzy: '{matched_string}' con '{part}' a posizione {position}")
                text = text[:position] + part + text[position + matched_length:]
                debug_print("[INFO]", f"Testo dopo sostituzione fuzzy: '{text}'")

        # 4) Solo il product con ricerca esatta
            exact_product_matches, product_positions = find_exact_matches(product_normalized, text)
            for match, position in zip(exact_product_matches, product_positions):
                # Crea un pattern che gestisce gli spazi
                pattern = r'\b' + re.escape(product_normalized) + r'\b'
                text = re.sub(pattern, part, text)  # Sostituisci con 'part'
                debug_print("[INFO]", f"Sostituzione esatta del prodotto: '{match}' con '{part}' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione esatta del prodotto: '{text}'")

            # 5) Fuzzy matching con il product
            fuzzy_product_matches = find_all_fuzzy_matches(product_normalized, text)
            for matched_string, position, length in fuzzy_product_matches:
                text = text[:position] + part + text[position + length:]
                debug_print("[INFO]", f"Sostituzione fuzzy del prodotto: '{matched_string}' con '{part}' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione fuzzy del prodotto: '{text}'")
            
            # 5a) Ricerca parziale e sostituzione
            partial_matches = find_partial_matches("", product_normalized, text)
            # Sostituzione nel testo delle corrispondenze trovate
            for matched_string, position, length in partial_matches:
                text = text[:position] + part + text[position + length:]  # Rimpiazza il match con 'part'
                debug_print("[INFO]", f"Sostituzione parziale: '{matched_string}' con '{part}' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione parziale: '{text}'")
            
            # 6) Replacement del vendor e product con combinazione fino a 3 parole
            if vendor_normalized is not None:
                debug_print("[INFO]", "Text prima di entrare in")
                text = replace_word_in_text(text, vendor_normalized, "")
            
            if product_normalized is not None:
                text = replace_word_in_text(text, product_normalized, part)
            
            # 7) Sostituzione del target_sw se presente
                if cpe_uri.get_target_sws():  # Controlla se la lista non è vuota
                    for target_sw in cpe_uri.get_target_sws():  # Itera su ogni elemento della lista
                        text = text.replace(target_sw.lower(), 'software')
                        debug_print("[INFO]", f"Sostituzione del target_sw: '{target_sw}' con 'software'.")
                        debug_print("[INFO]", f"Testo dopo sostituzione del target_sw: '{text}'")

            # 6) Rimozione di altre parti della CPE se presenti
            attributes_to_exclude = ['cpe_type', 'vendor', 'product', 'target_sws']
            for attr, values in vars(cpe_uri).items():
                if attr not in attributes_to_exclude:
                    debug_print("[INFO]", f"Attributo iterato attualmente da rimuovere {attr}: {values}")
                    for value in values:
                        if value not in (vendor_normalized, product_normalized):
                            text = text.replace(value.lower(), '')
                            debug_print("[INFO]", f"Rimozione di '{value}' dal testo.")
                            debug_print("[INFO]", f"Testo dopo rimozione di '{value}': '{text}'")
            
            # 7) Rimozione del vendor se presente
            exact_matches, positions = find_exact_matches(vendor_normalized, text)
            for match, position in zip(exact_matches, positions):
                # Crea un pattern che gestisce gli spazi
                pattern = r'\b' + re.escape(vendor_normalized) + r'\b'
                text = re.sub(pattern, '', text)  # Rimuovi la parola
                # Rimuovi eventuali spazi extra dopo la rimozione
                text = re.sub(r'\s+', ' ', text).strip()  # Normalizza gli spazi
                debug_print("[INFO]", f"Sostituzione esatta: '{match}' con '' a posizione {position}")
                debug_print("[INFO]", f"Testo dopo sostituzione esatta: '{text}'")

        # 8) Rimuovi tabulazioni e spazi extra
        text = re.sub(r'\s+', ' ', text).strip()

        # Controlla e rimuove le ripetizioni consecutive della parola 'part'
        if part:
            debug_print("[INFO]", f"Rimuovo le ripetizioni della parola {part}")
            pattern = r'(?i)(\b' + re.escape(part) + r'\b)[\s,.;:]*\1+'  

            # Continua a sostituire finché ci sono ripetizioni
            previous_text = None
            while previous_text != text:
                previous_text = text  # Salva il testo attuale
                text = re.sub(pattern, r'\1', text)  # Sostituisci con una sola occorrenza
            
            debug_print("[INFO]", f"Testo finale dopo rimozione delle ripetizioni: '{text}'")

        # 8) Rimuovi tabulazioni e spazi extra
        text = re.sub(r'\s+', ' ', text).strip()

        debug_print("[INFO]", f"Final text after removing vendor and products of cpe uris: '{text}'")

    return text

if __name__ == "__main__":
    # Esempio di utilizzo della funzione
    text = "mod_usertrack in Apache 1.3.11 through 1.3.20 generates session ID's using predictable information including host IP address, system time and server process ID, which allows local users to obtain session ID's and bypass authentication when these session ID's are used for authentication."
    cpe_uris = [
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",  # Esempio di CPE URI
    ]

    updated_text = process_cpe_uris_in_text(text, cpe_uris)
    print(f"Testo aggiornato: '{updated_text}'")

    