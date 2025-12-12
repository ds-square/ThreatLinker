# data/updater/cwe_update.py
import os
import xml.etree.ElementTree as ET

from data.models import CWE, CWERelatedWeakness, CAPEC
from data.updater.update_utils import download_file, extract_zip_file, get_entity_download_dir, update_progress_file
from debug.debug_utils import debug_print

entity = "cwe"

### Funzioni Ausiliarie

def remove_namespace(tree):
    """
    Rimuove i namespace dagli elementi XML per semplificare il parsing.
    """
    for elem in tree.iter():
        if '}' in elem.tag:
            elem.tag = elem.tag.split('}', 1)[1]  # Rimuove il namespace
    return tree

def clean_text(text):
    return ' '.join(text.split()).strip() if text else None

def extract_cleaned_text(element):
    if element is None:
        return None
    text_content = ''.join(element.itertext())
    return clean_text(text_content)

### Funzioni di Import e Download

def download_cwe_data():
    """
    Scarica e prepara i dati di CWE.
    
    Returns:
        str: Percorso del file scaricato se il download ha successo.
    """
    try:
        # Scarica il file per CWE e restituisci il percorso
        file_path = download_file(entity)
        extract_zip_file(file_path, entity)
        update_progress_file("download", "CWE", 100)
        return file_path
    except Exception as e:
        # Solleva l'errore per gestirlo nella view
        raise Exception(f"Errore durante l'aggiornamento dei dati CWE: {e}")

def import_cwe_data():
    download_dir = get_entity_download_dir("cwe")
    xml_files = [f for f in os.listdir(download_dir) if f.endswith(".xml")]
    
    if not xml_files:
        raise FileNotFoundError("Nessun file XML trovato nella directory CWE.")
    
    file_path = os.path.join(download_dir, xml_files[0])
    debug_print("INFO", f"File XML trovato per CWE: {file_path}")

    try:
        tree = ET.parse(file_path)
        tree = remove_namespace(tree)  # Rimuove i namespaces
        root = tree.getroot()
        debug_print("INFO", "File XML caricato e namespace rimosso con successo")
    except Exception as e:
        debug_print("ERROR", f"Errore durante il caricamento del file XML: {e}")
        return

    catalog_name = root.attrib.get("Name")
    version = root.attrib.get("Version")
    date = root.attrib.get("Date")

    if catalog_name != "CWE":
        raise ValueError("Il file XML non è un catalogo CWE valido.")
    
    debug_print("INFO", f"Inizio importazione CWE - Versione: {version}, Data: {date}")

    for weakness in root.findall('.//Weakness'):
        cwe_id = "CWE-" + weakness.get('ID')
        name = weakness.get('Name')
        abstraction = weakness.get('Abstraction')
        structure = weakness.get('Structure')
        status = weakness.get('Status')

        description = extract_cleaned_text(weakness.find('Description'))
        extended_description = extract_cleaned_text(weakness.find('Extended_Description'))
        likelihood_of_exploit = clean_text(weakness.findtext('Likelihood_Of_Exploit'))

        background_details = []
        for background_detail in weakness.findall('Background_Details/Background_Detail'):
            background_detail = extract_cleaned_text(background_detail)
            background_details.append(background_detail)

        functional_areas = []
        for functional_area in weakness.findall('Functional_Areas/Functional_Area'):
            functional_area = extract_cleaned_text(functional_area)
            functional_areas.append(functional_area)

        common_consequences = []
        for consequence in weakness.findall('Common_Consequences/Consequence'):
            scopes = [clean_text(scope.text) for scope in consequence.findall('Scope') if scope.text]
            impacts = [clean_text(impact.text) for impact in consequence.findall('Impact') if impact.text]
            note = extract_cleaned_text(consequence.find('Note'))
            common_consequences.append({'Scope': scopes, 'Impact': impacts, 'Note': note})

        # Estrai i dati da <Applicable_Platforms>
        applicable_platforms = []
        for platform in weakness.findall('Applicable_Platforms/*'):
            platform_type = platform.tag  # Tipo di piattaforma (Language, Technology, etc.)
            platform_class = platform.get("Class")
            platform_name = platform.get("Name")
            platform_prevalence = platform.get("Prevalence")
            
            # Aggiungi i dati della piattaforma alla lista
            applicable_platforms.append({
                "Type": platform_type,
                "Class": platform_class,
                "Name": platform_name,
                "Prevalence": platform_prevalence
            })

        potential_mitigations = []
        for mitigation in weakness.findall('Potential_Mitigations/Mitigation'):
            phases = [clean_text(phase.text) for phase in mitigation.findall('Phase') if phase.text]
            strategies = [clean_text(strategy.text) for strategy in mitigation.findall('Strategy') if strategy.text]
            mitigation_description = extract_cleaned_text(mitigation.find('Description'))
            effectiveness = clean_text(mitigation.findtext('Effectiveness'))
            potential_mitigations.append({
                'Phase': phases,
                'Strategy': strategies,
                'Description': mitigation_description,
                'Effectiveness': effectiveness
            })

        detection_methods = []
        for method in weakness.findall('Detection_Methods/Detection_Method'):
            detection_method_id = method.get("Detection_Method_ID")
            detection_description = extract_cleaned_text(method.find('Description'))
            method_name = clean_text(method.findtext('Method'))
            effectiveness = clean_text(method.findtext('Effectiveness'))
            detection_methods.append({
                "detection_method_id": detection_method_id,
                "description": detection_description,
                "method": method_name,
                "effectiveness": effectiveness,
            })

        observed_examples = []
        for example in weakness.findall('Observed_Examples/Observed_Example'):
            example_desc = extract_cleaned_text(example.find('Description'))
            cve_id = clean_text(example.findtext('Reference'))
            observed_examples.append({"description": example_desc, "cve_id": cve_id})

        # Funzione per estrarre il contenuto di Demonstrative Examples
        demonstrative_examples = []
        for example in weakness.findall('Demonstrative_Examples/Demonstrative_Example'):
            intro_text = extract_cleaned_text(example.find('Intro_Text'))
            
            # Estrai Body_Text come lista per gestire più sezioni di testo
            body_texts = [extract_cleaned_text(body_text) for body_text in example.findall('Body_Text')]
            
            # Estrai le sezioni di Example_Code
            example_codes = []
            for code in example.findall('Example_Code'):
                code_nature = code.get("Nature")
                code_language = code.get("Language")
                code_content = extract_cleaned_text(code)
                example_codes.append({
                    "Nature": code_nature,
                    "Language": code_language,
                    "Content": code_content
                })
            
            # Aggiungi l'esempio alla lista
            demonstrative_examples.append({
                "Intro_Text": intro_text,
                "Body_Texts": body_texts,
                "Example_Codes": example_codes
            })

        alternate_terms = []
        for term in weakness.findall('Alternate_Terms/Alternate_Term'):
            term_text = clean_text(term.findtext('Term'))
            term_description = extract_cleaned_text(term.find('Description'))
            alternate_terms.append({'Term': term_text, 'Description': term_description})

        modes_of_introduction = []
        for mode in weakness.findall('Modes_Of_Introduction/Introduction'):
            phases = [clean_text(phase.text) for phase in mode.findall('Phase') if phase.text]
            note = clean_text(mode.findtext('Note'))
            modes_of_introduction.append({
                'Phase': phases,
                'Note': note
            })

        cwe_data = {
            "name": name,
            "description": description,
            "extended_description": extended_description,
            "abstraction": abstraction,
            "structure": structure,
            "status": status,
            "functional_areas": functional_areas,
            "demonstrative_examples": demonstrative_examples,
            "likelihood_of_exploit": likelihood_of_exploit,
            "modes_of_introduction": modes_of_introduction,
            "background_details": background_details,
            "common_consequences": common_consequences,
            "applicable_platforms": applicable_platforms,
            "potential_mitigations": potential_mitigations,
            "detection_methods": detection_methods,
            "observed_examples": observed_examples,
            "alternate_terms": alternate_terms,
        }

        debug_print("INFO", f"Dati CWE estratti: {cwe_data}")

        CWE.objects.update_or_create(id=cwe_id, defaults=cwe_data)

    debug_print("INFO", "Importazione CWE completata.")

     # Creazione delle relazioni tra CWE
    for weakness in root.findall('.//Weakness'):
        cwe_id = "CWE-" + weakness.get('ID')
        cwe_instance = CWE.objects.get(id=cwe_id)
        
        for related_weakness in weakness.findall('Related_Weaknesses/Related_Weakness'):
            related_cwe_id = f"CWE-{related_weakness.get('CWE_ID')}"
            relation_type = related_weakness.get("Nature")
            view_id = related_weakness.get("View_ID")

            if view_id == "1000":
                related_cwe_instance, _ = CWE.objects.get_or_create(id=related_cwe_id)
                CWERelatedWeakness.objects.update_or_create(
                    cwe=cwe_instance,
                    related_cwe=related_cwe_instance,
                    defaults={"relation_type": relation_type}
                )

    update_progress_file("import", "CWE", 100)
    debug_print("INFO", "Creazione delle relazioni CWE completata.")
    return version, date

def create_cwe_relationships():
    download_dir = get_entity_download_dir("cwe")
    xml_files = [f for f in os.listdir(download_dir) if f.endswith(".xml")]

    if not xml_files:
        raise FileNotFoundError("Nessun file XML trovato nella directory CWE.")

    file_path = os.path.join(download_dir, xml_files[0])
    debug_print("INFO", f"File XML trovato per CWE: {file_path}")

    try:
        tree = ET.parse(file_path)
        tree = remove_namespace(tree)  # Rimuove i namespaces
        root = tree.getroot()
        debug_print("INFO", "File XML caricato e namespace rimosso con successo")
    except Exception as e:
        debug_print("ERROR", f"Errore durante il caricamento del file XML: {e}")
        return

    # Cicla attraverso ciascun CWE e crea collegamenti ai CAPEC associati
    for weakness in root.findall('.//Weakness'):
        cwe_id = "CWE-" + weakness.get('ID')
        
        try:
            cwe_instance = CWE.objects.get(id=cwe_id)
        except CWE.DoesNotExist:
            debug_print("WARNING", f"{cwe_id} non trovato nel database; saltato.")
            continue

        # Trova i CAPEC associati nel nodo <Related_Attack_Patterns>
        for related_attack_pattern in weakness.findall('Related_Attack_Patterns/Related_Attack_Pattern'):
            capec_id = "CAPEC-" + related_attack_pattern.get('CAPEC_ID')

            try:
                capec_instance = CAPEC.objects.get(id=capec_id)
                # Aggiungi il collegamento tra il CWE e il CAPEC
                cwe_instance.related_attack_patterns.add(capec_instance)
                debug_print("INFO", f"Relazione creata: {cwe_id} -> {capec_id}")
            except CAPEC.DoesNotExist:
                debug_print("WARNING", f"{capec_id} non trovato nel database; relazione non creata.")
    
    update_progress_file("relation", "CWE", 100)
    debug_print("INFO", "Creazione delle relazioni CWE-CAPEC completata.")