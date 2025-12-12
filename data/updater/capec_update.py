import os
import xml.etree.ElementTree as ET
import re
from django.db import IntegrityError

from data.models import CAPEC, CAPECRelatedAttackPattern, ExecutionFlow, AttackStep
from data.models import PreprocessedCAPEC, PreprocessedAttackStep, PreprocessedExecutionFlow
from data.updater.update_utils import download_file, get_entity_download_dir, update_progress_file
from debug.debug_utils import debug_print

import spacy
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.stem import PorterStemmer

entity = "capec"

global nlp 

# Carica il modello predefinito di spaCy per l'inglese
def load_spacy_model():
    try:
        # Verifica se il modello è già stato scaricato
        spacy.load("en_core_web_sm")
        print("spaCy model already downloaded.")
    except OSError:
        # Se non è stato scaricato, lo scarica
        print("Downloading spaCy model...")
        os.system("python -m spacy download en_core_web_sm")
    return spacy.load("en_core_web_sm")

# Funzione per scaricare le risorse di NLTK se non sono già presenti
def download_nltk_resources():
    nltk_data_dir = "./.venv/nltk_data"
    nltk.data.path.clear()  # Cancella i percorsi precedenti per evitare conflitti
    nltk.data.path.append(nltk_data_dir)  # Aggiungi il percorso nltk_data in .venv
    
    # Controlla e scarica le stopwords
    try:
        nltk.data.find('corpora/stopwords')
        print("NLTK stopwords already downloaded.")
    except LookupError:
        print("Downloading NLTK stopwords...")
        nltk.download('stopwords', download_dir=nltk_data_dir, force=True)
        
    # Controlla e scarica punkt
    try:
        nltk.data.find('tokenizers/punkt')
        print("NLTK punkt already downloaded.")
    except LookupError:
        print("Downloading NLTK punkt...")
        nltk.download('punkt', download_dir=nltk_data_dir, force=True)
    
    # Controlla e scarica punk_tab
    try:
        nltk.data.find('tokenizers/punkt_tab')
        print("NLTK punkt_tab already downloaded.")
    except LookupError:
        print("Downloading NLTK punkt_tab...")
        nltk.download('punkt_tab', download_dir=nltk_data_dir, force=True)
    
    # Controlla e scarica wordnet
    try:
        nltk.data.find('corpora/wordnet')
        print("NLTK wordnet already downloaded.")
    except LookupError:
        print("Downloading NLTK wordnet...")
        nltk.download('wordnet', download_dir=nltk_data_dir, force=True)

def remove_namespace(tree):
    for elem in tree.iter():
        if '}' in elem.tag:
            elem.tag = elem.tag.split('}', 1)[1]
    return tree

def clean_text(text):
    return ' '.join(text.split()).strip() if text else None

def extract_cleaned_text(element):
    if element is None:
        return None
    text_content = ''.join(element.itertext())
    return clean_text(text_content)

### Funzione di Download e Import di CAPEC

def download_capec_data():
    """
    Scarica e prepara i dati di CAPEC.
    
    Returns:
        str: Percorso del file scaricato se il download ha successo.
    """
    try:
        # Scarica il file per CWE e restituisci il percorso
        file_path = download_file(entity)
        update_progress_file("download", "CAPEC", 100)
        return file_path
    except Exception as e:
        # Solleva l'errore per gestirlo nella view
        raise Exception(f"Errore durante il download dei dati CAPEC: {e}")

def import_capec_data():
    download_dir = get_entity_download_dir("capec")
    xml_files = [f for f in os.listdir(download_dir) if f.endswith(".xml")]
    
    if not xml_files:
        raise FileNotFoundError("Nessun file XML trovato nella directory CAPEC.")
    
    file_path = os.path.join(download_dir, xml_files[0])
    debug_print("INFO", f"File XML trovato per CAPEC: {file_path}")

    try:
        tree = ET.parse(file_path)
        tree = remove_namespace(tree)
        root = tree.getroot()
        debug_print("INFO", "File XML caricato e namespace rimosso con successo")
    except Exception as e:
        debug_print("ERROR", f"Errore durante il caricamento del file XML: {e}")
        return

    # Controllo e memorizzazione dei dettagli del catalogo
    catalog_name = root.attrib.get("Name")
    version = root.attrib.get("Version")
    date = root.attrib.get("Date")

    if catalog_name != "CAPEC":
        raise ValueError("Il file XML non è un catalogo CAPEC valido.")
    
    debug_print("INFO", f"Inizio importazione CAPEC - Versione: {version}, Data: {date}")

    # Creazione dei pattern CAPEC
    capec_instances = {}
    for pattern in root.findall('.//Attack_Pattern'):
        capec_id = f"CAPEC-{pattern.get('ID')}"
        name = pattern.get('Name')
        abstraction = pattern.get('Abstraction')
        status = pattern.get('Status')

        description = extract_cleaned_text(pattern.find('Description'))
        extended_description = extract_cleaned_text(pattern.find('Extended_Description'))
        likelihood_of_attack = clean_text(pattern.findtext('Likelihood_Of_Attack'))
        typical_severity = clean_text(pattern.findtext('Typical_Severity'))

        prerequisites = [extract_cleaned_text(prereq) for prereq in pattern.findall('Prerequisites/Prerequisite')]

        skills_required = [{
            "Level": skill.get("Level"),
            "Description": extract_cleaned_text(skill)
        } for skill in pattern.findall('Skills_Required/Skill')]

        resources_required = [extract_cleaned_text(resource) for resource in pattern.findall('Resources_Required/Resource')]

        indicators = [extract_cleaned_text(indicator) for indicator in pattern.findall('Indicators/Indicator')]
        
        # Modifica la ricerca dei termini alternati per verificare la struttura corretta
        alternate_terms = [extract_cleaned_text(term) for term in pattern.findall('.//Alternate_Terms/Alternate_Term/Term')]  # XPath relativo
              
        consequences = [{
            "Scope": [clean_text(scope.text) for scope in consequence.findall('Scope')],
            "Impact": [clean_text(impact.text) for impact in consequence.findall('Impact')],
            "Note": extract_cleaned_text(consequence.find('Note'))
        } for consequence in pattern.findall('Consequences/Consequence')]

        mitigations = [extract_cleaned_text(mitigation) for mitigation in pattern.findall('Mitigations/Mitigation')]

        example_instances = [extract_cleaned_text(example) for example in pattern.findall('Example_Instances/Example')]
        
        capec_data = {
            "name": name,
            "abstraction": abstraction,
            "status": status,
            "description": description,
            "extended_description": extended_description,
            "likelihood_of_attack": likelihood_of_attack,
            "typical_severity": typical_severity,
            "prerequisites": prerequisites,
            "indicators": indicators,
            "skills_required": skills_required,
            "resources_required": resources_required,
            "consequences": consequences,
            "mitigations": mitigations,
            "example_instances": example_instances,
            "alternate_terms": alternate_terms,
        }
        
        capec_instance, created = CAPEC.objects.update_or_create(id=capec_id, defaults=capec_data)
        capec_instances[capec_id] = capec_instance

        # Estrazione del flusso di esecuzione
        execution_flow_element = pattern.find('Execution_Flow')
        if execution_flow_element is not None:
            debug_print("INFO", f"Creazione di ExecutionFlow per {capec_id}")
            execution_flow_instance, _ = ExecutionFlow.objects.update_or_create(
                capec=capec_instance
            )
            # Aggiorna il campo execution_flow_instance di CAPEC
            capec_instance.execution_flow_instance = execution_flow_instance
            capec_instance.save()  # Salva le modifiche per associare l'ExecutionFlow al CAPEC

            # Dizionario per tenere traccia del conteggio dei duplicati per ciascun step_number
            step_counts = {}

            for attack_step in execution_flow_element.findall('Attack_Step'):
                # Pulizia e estrazione dei dettagli dello step
                step_number = clean_text(attack_step.find('Step').text)
                phase = clean_text(attack_step.find('Phase').text)
                description = extract_cleaned_text(attack_step.find('Description'))
                techniques = [extract_cleaned_text(tech) for tech in attack_step.findall('Technique')]

                # Incrementa il conteggio per lo step_number corrente
                if step_number in step_counts:
                    step_counts[step_number] += 1
                    # Aggiungi il suffisso alfabetico solo per i duplicati (a, b, c, ...)
                    suffixed_step_number = f"{step_number}{chr(96 + step_counts[step_number])}"  # 96 + 1 = 'a'
                else:
                    step_counts[step_number] = 1
                    # Usa solo il numero se è unico
                    suffixed_step_number = step_number

                # Aggiornamento o creazione dell'AttackStep con il numero modificato
                AttackStep.objects.update_or_create(
                    execution_flow=execution_flow_instance,
                    step=suffixed_step_number,
                    defaults={
                        "phase": phase,
                        "description": description,
                        "techniques": techniques,
                    }
                )

    debug_print("INFO", "Tutti i pattern CAPEC e ExecutionFlow sono stati creati o aggiornati.")

    # Gestione delle relazioni tra i pattern CAPEC
    for pattern in root.findall('.//Attack_Pattern'):
        capec_id = f"CAPEC-{pattern.get('ID')}"
        capec_instance = capec_instances.get(capec_id)
        
        for related_pattern in pattern.findall('Related_Attack_Patterns/Related_Attack_Pattern'):
            related_capec_id = f"CAPEC-{related_pattern.get('CAPEC_ID')}"
            nature = related_pattern.get("Nature")
            related_instance = capec_instances.get(related_capec_id)
            
            if capec_instance and related_instance:
                CAPECRelatedAttackPattern.objects.update_or_create(
                    source_capec=capec_instance,
                    target_capec=related_instance,
                    defaults={"nature": nature}
                )

    update_progress_file("import", "CAPEC", 100)
    debug_print("INFO", "Creazione delle relazioni tra pattern CAPEC completata.")
    return version, date

### Create Preprocessed CAPECs

def clean_text_for_aggregation(text):
    """
    Pulisce il testo da spazi extra, tabulazioni, a capo, rimuove gli slashes /
    e applica altre operazioni di pulizia come minuscolo e rimozione della punteggiatura.
    :param text: Testo da pulire.
    :return: Testo pulito.
    """
    if not text:
        return ""  # Ritorna una stringa vuota se il testo è vuoto o None

    # Converti il testo in minuscolo
    text = text.lower()

    # Rimuove gli slash tra le parole e sostituisce con uno spazio
    text = re.sub(r'/', ' ', text)

    # Rimuove gli i trattini tra le parole e sostituisce con uno spazio
    text = re.sub(r'-', ' ', text)

    # Rimuove la punteggiatura (eccetto le lettere e i numeri)
    text = re.sub(r'[^\w\s]', '', text)

    # Rimuove i caratteri di nuova linea e tabulazioni, e sostituisce con uno spazio singolo
    text = re.sub(r'\s+', ' ', text)

    # Rimuove eventuali spazi in eccesso all'inizio e alla fine
    text = text.strip()

    # Rimuove gli spazi extra fra le parole aggregate
    text = re.sub(r'\s{2,}', ' ', text)

    return text

def remove_stopwords_spacy(text):
    """
    Rimuove le stopwords da un testo usando spaCy.
    :param text: Testo da elaborare.
    :return: Testo senza stopwords.
    """
    # Elabora il testo con spaCy
    
    doc = nlp(text)

    # Filtra le parole rimuovendo le stopwords
    filtered_text = [token.text for token in doc if not token.is_stop]

    return ' '.join(filtered_text)

def lemmatize_text(text):
    """
    Lemmatizza il testo.
    :param text: Testo da lemmatizzare.
    :return: Testo lemmatizzato.
    """
    print(f"Sono in lemma: {text}")
    lemmatizer = WordNetLemmatizer()
    print("Sono in lemma 2")
    try:
        words = word_tokenize(text)  # Prova a tokenizzare il testo
        print("Sono in lemma 3")
    except Exception as e:
        print(f"Errore durante il tokenizing: {e}")
        return None  # Termina la funzione se c'è un errore
    print("Sono in lemma 3")
    lemmatized_text = [lemmatizer.lemmatize(word) for word in words]
    print(f"Testo lemmatizzato: {lemmatized_text}")
    print(''.join(lemmatized_text))
    return ' '.join(lemmatized_text)

def stem_text(text):
    """
    Applica lo stemming al testo usando PorterStemmer.
    :param text: Testo da stemmare.
    :return: Testo stemmato.
    """
    
    # Inizializza il PorterStemmer
    stemmer = PorterStemmer()

    # Tokenizza il testo
    words = word_tokenize(text)

    # Applica lo stemming a ogni parola nel testo
    stemmed_words = [stemmer.stem(word) for word in words]

    # Unisce le parole stemmate in un unico testo
    return ' '.join(stemmed_words)

def aggregate_and_clean_fields(capec, version="Basic"):
    """
    Aggrega e pulisce tutti i campi di un CAPEC, rimuovendo spazi extra e trattando correttamente
    i campi di tipo lista, mantenendoli come liste per i campi non aggregati.
    Le versioni di preprocessing sono applicate cumulativamente.
    """

    # Funzione per gestire le liste o dizionari come "consequences" e "skills_required"
    def clean_dict_field(field):
        if isinstance(field, list):
            # Gestisci le liste di stringhe e pulisci ogni stringa
            return [clean_text_for_aggregation(str(item)) for item in field if item]
        elif isinstance(field, dict):
            # Aggrega le chiavi e i valori se è un dizionario
            return [f"{key}: {', '.join(value) if isinstance(value, list) else value}" for key, value in field.items()]
        return [clean_text_for_aggregation(str(field))] if field else []

    # Funzione specifica per estrarre il campo "Description" da una lista di dizionari
    def clean_skills_required(field):
        if isinstance(field, list):
            # Estrae la descrizione da ciascun dizionario nella lista, escludendo quelli che sono None o stringhe vuote
            descriptions = [clean_text_for_aggregation(item.get('Description', '').strip()) for item in field if isinstance(item, dict) and item.get('Description')]
            # Unisce le descrizioni non vuote
            return descriptions
        return []

    # Funzione per aggregare una lista in una stringa e pulirla
    def aggregate_and_clean_list_field(field):
        if isinstance(field, list):
            # Unisce la lista in una singola stringa e pulisce ogni stringa
            return [clean_text_for_aggregation(str(item)) for item in field if item]
        return []

    print("Sono prima di cleaned fields")
    # Pulizia e aggregazione dei campi
    cleaned_fields = {
        'name': clean_text_for_aggregation(capec.name),
        'description': clean_text_for_aggregation(capec.description),
        'extended_description': clean_text_for_aggregation(capec.extended_description),
        'indicators': aggregate_and_clean_list_field(capec.indicators),
        'prerequisites': aggregate_and_clean_list_field(capec.prerequisites),
        'resources_required': aggregate_and_clean_list_field(capec.resources_required),
        'mitigations': aggregate_and_clean_list_field(capec.mitigations),
        'example_instances': aggregate_and_clean_list_field(capec.example_instances),
        'consequences': clean_dict_field(capec.consequences),
        'skills_required': clean_skills_required(capec.skills_required),
        'alternate_terms': aggregate_and_clean_list_field(capec.alternate_terms),
    }

    print("Sono dopo cleaned fields")
    # Versioning delle trasformazioni:
    if version == "Stopwords" or version == "Lemmatization" or version == "Stemming":
        # Per le liste, rimuovi le stopwords da ciascun elemento della lista
        print("Sono dentro 1 if")
        cleaned_fields = {key: [remove_stopwords_spacy(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else remove_stopwords_spacy(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    if version == "Lemmatization" or version == "Stemming":
        # Per le liste, lemmatizza ogni elemento della lista
        print("Sono dentro 2 if")
        cleaned_fields = {key: [lemmatize_text(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else lemmatize_text(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    if version == "Stemming":
        print("Sono dentro 3 if")
        # Per le liste, applica lo stemming a ciascun elemento della lista
        cleaned_fields = {key: [stem_text(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else stem_text(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    return cleaned_fields

def aggregate_and_clean_executionflow(attackstep, version="Basic"):
    """
    Aggrega e pulisce tutti i campi di un CAPEC, rimuovendo spazi extra e trattando correttamente
    i campi di tipo lista, mantenendoli come liste per i campi non aggregati.
    Le versioni di preprocessing sono applicate cumulativamente.
    """

    # Funzione per aggregare una lista in una stringa e pulirla
    def aggregate_and_clean_lists_field(field):
        if isinstance(field, list):
            # Unisce la lista in una singola stringa e pulisce ogni stringa
            return [clean_text_for_aggregation(str(item)) for item in field if item]
        return []

    # Pulizia e aggregazione dei campi
    cleaned_fields = {
        'attackstep_description': clean_text_for_aggregation(attackstep.description),
        'attackstep_techniques': aggregate_and_clean_lists_field(attackstep.techniques),

    }

    # Versioning delle trasformazioni:
    if version == "Stopwords" or version == "Lemmatization" or version == "Stemming":
        # Per le liste, rimuovi le stopwords da ciascun elemento della lista
        cleaned_fields = {key: [remove_stopwords_spacy(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else remove_stopwords_spacy(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    if version == "Lemmatization" or version == "Stemming":
        # Per le liste, lemmatizza ogni elemento della lista
        cleaned_fields = {key: [lemmatize_text(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else lemmatize_text(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    if version == "Stemming":
        # Per le liste, applica lo stemming a ciascun elemento della lista
        cleaned_fields = {key: [stem_text(item) if isinstance(item, str) else item for item in value]
                          if isinstance(value, list) else stem_text(value) if isinstance(value, str) else value
                          for key, value in cleaned_fields.items()}

    return cleaned_fields


### Create the Preprocessed CAPECS

def create_preprocessed_capecs():
    global nlp 
    nlp = load_spacy_model()
    download_nltk_resources()
    print("Inizio della creazione dei PreprocessedCAPEC...\n")
    capecs = CAPEC.objects.all()

    for capec in capecs:
        for version in ["Basic", "Stopwords", "Lemmatization", "Stemming"]:
            # Crea un PreprocessedCAPEC per ciascun CAPEC
            preprocessed_capec, created = PreprocessedCAPEC.objects.get_or_create(
                original_capec=capec,
                preprocessed_version=version
            )

            if created:
                print(f"Creating Preprocessed CAPEC {capec.id} with version {version}.\n")
            else:
                print(f"Preprocessed CAPEC {capec.id} with version {version} already exists.\n")
                print(f"Preprocessed CAPEC {capec.id} with version {version} already exists in the database.")
            
            # Aggrega e pulisci i campi di CAPEC
            cleaned_fields = aggregate_and_clean_fields(capec, version)

            # Aggiorna i campi di PreprocessedCAPEC
            preprocessed_capec.name = cleaned_fields['name']
            preprocessed_capec.description = cleaned_fields['description']
            preprocessed_capec.extended_description = cleaned_fields['extended_description']
            preprocessed_capec.indicators = cleaned_fields['indicators']
            preprocessed_capec.prerequisites = cleaned_fields['prerequisites']
            preprocessed_capec.resources_required = cleaned_fields['resources_required']
            preprocessed_capec.mitigations = cleaned_fields['mitigations']
            preprocessed_capec.example_instances = cleaned_fields['example_instances']
            preprocessed_capec.consequences = cleaned_fields['consequences']
            preprocessed_capec.skills_required = cleaned_fields['skills_required']
            preprocessed_capec.alternate_terms = cleaned_fields['alternate_terms']

            # Salva il record di PreprocessedCAPEC
            try:
                preprocessed_capec.save()
                print(f"Successfully saved Preprocessed CAPEC {capec.id} with version {version}.\n")
            except IntegrityError as e:
                print(f"Skipping Preprocessed CAPEC {capec.id} with version {version} due to integrity error.\n")

            # Crea il PreprocessedExecutionFlow se il CAPEC ha un ExecutionFlow associato
            execution_flow = ExecutionFlow.objects.filter(capec=capec).first()
            if execution_flow:
                # Crea PreprocessedExecutionFlow e associa al PreprocessedCAPEC
                preprocessed_execution_flow, created = PreprocessedExecutionFlow.objects.get_or_create(
                    preprocessed_capec=preprocessed_capec
                )

                if created:
                    print(f"Creating Preprocessed ExecutionFlow for CAPEC {capec.id} with version {version}.\n")
                else:
                    print(f"Preprocessed ExecutionFlow for CAPEC {capec.id} with version {version} already exists.\n")

                # Salva il PreprocessedExecutionFlow
                try:
                    preprocessed_execution_flow.save()
                    # Collega PreprocessedExecutionFlow a PreprocessedCAPEC dopo averlo salvato
                    preprocessed_capec.preprocessed_execution_flow = preprocessed_execution_flow
                    preprocessed_capec.save()
                except IntegrityError as e:
                    print(f"Skipping Preprocessed ExecutionFlow for CAPEC {capec.id} with version {version} due to integrity error.\n")

                # Crea e salva i PreprocessedAttackStep
                for attack_step in execution_flow.attack_steps.all():
                    preprocessed_attack_step, created = PreprocessedAttackStep.objects.get_or_create(
                        preprocessed_execution_flow=preprocessed_execution_flow,
                        step=attack_step.step,
                        phase=attack_step.phase,
                        description=attack_step.description,
                        techniques=attack_step.techniques
                    )

                    if created:
                        print(f"Creating Preprocessed AttackStep {attack_step.step} for CAPEC {capec.id} with version {version}.\n")
                    else:
                        print(f"Preprocessed AttackStep {attack_step.step} for CAPEC {capec.id} with version {version} already exists.\n")

                    # Aggrega e pulisci i campi di AttackStep
                    cleaned_attack_step_fields = aggregate_and_clean_executionflow(attack_step, version)

                    # Aggiorna i campi di PreprocessedAttackStep
                    preprocessed_attack_step.description = cleaned_attack_step_fields['attackstep_description']
                    preprocessed_attack_step.techniques = cleaned_attack_step_fields['attackstep_techniques']

                    # Salva il record di PreprocessedAttackStep
                    try:
                        preprocessed_attack_step.save()
                        print(f"Successfully saved Preprocessed AttackStep {attack_step.step} for CAPEC {capec.id} with version {version}.\n")
                    except IntegrityError as e:
                        print(f"Skipping Preprocessed AttackStep {attack_step.step} for CAPEC {capec.id} with version {version} due to integrity error.\n")

    print("Operazione completata.\n")
