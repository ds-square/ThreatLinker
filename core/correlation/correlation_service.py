from data.models import CVE  # Supponiamo che il modello CVE esista nel tuo database
import re
import csv
import xml.etree.ElementTree as ET
import pandas as pd
from io import TextIOWrapper

# Regular expression pattern per verificare un ID CVE valido
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,7}$')

def is_valid_cve_id(cve_id):
    """Verifica se una stringa è un ID CVE valido."""
    return bool(CVE_PATTERN.match(cve_id))

def extract_cves_from_list(cve_list):
    """Estrae ID CVE validi da una lista di stringhe."""
    cves = set()
    for line in cve_list:
        cve = line.strip()
        if is_valid_cve_id(cve):
            cves.add(cve)
    return cves

def extract_cves_from_csv(file):
    """Estrae ID CVE validi da un file CSV."""
    cves = set()
    reader = csv.reader(TextIOWrapper(file, encoding='utf-8'))
    for row in reader:
        for cell in row:
            if is_valid_cve_id(cell):
                cves.add(cell)
    return cves

def extract_cves_from_excel(file):
    """Estrae ID CVE validi da un file Excel. Se il file contiene più fogli, suddivide le CVE per host (nome del foglio)."""
    cves = set()
    hosts = {}
    excel_data = pd.ExcelFile(file)

    if len(excel_data.sheet_names) == 1:
        # Singolo foglio: elaborazione normale
        df = pd.read_excel(file)
        for cell in df.values.flatten():
            if isinstance(cell, str) and is_valid_cve_id(cell):
                cves.add(cell)
    else:
        # Multi-foglio: trattare ogni foglio come un host
        for sheet_name in excel_data.sheet_names:
            df = pd.read_excel(file, sheet_name=sheet_name)
            host_cves = set()
            for cell in df.values.flatten():
                if isinstance(cell, str) and is_valid_cve_id(cell):
                    host_cves.add(cell)
            # Aggiungi le CVE dell'host al set generale e al dizionario per host
            cves.update(host_cves)
            hosts[sheet_name] = host_cves

    return cves, hosts if hosts else None

def get_existing_cves(cves):
    """Restituisce solo le CVE che esistono nel database."""
    existing_cves = CVE.objects.filter(id__in=cves)  # Assume che il campo id nel modello CVE sia l'ID della CVE
    return set(existing_cves.values_list('id', flat=True))  # Restituisce solo gli ID delle CVE esistenti

def extract_valid_cves(input_data):
    """
    Funzione principale per estrarre e validare ID CVE da una lista o un file.
    :param input_data: Lista di stringhe o un file (CSV, XML, Excel).
    :return: Dizionario contenente:
             - "total_count": numero totale di CVE uniche
             - "cves": un set di CVE totali validi presenti nel database
             - "hosts": un dizionario con CVE per host (solo per Excel con più fogli)
    """
    if isinstance(input_data, list):
        cves = extract_cves_from_list(input_data)
        existing_cves = get_existing_cves(cves)  # Filtra solo le CVE che esistono nel database
        # Se non ci sono host (nessuna suddivisione), aggiungi un host generico
        return {"total_count": len(existing_cves), "cves": existing_cves, "hosts": {"Generic": existing_cves}}

    elif hasattr(input_data, 'name'):
        if input_data.name.endswith('.csv'):
            cves = extract_cves_from_csv(input_data)
            existing_cves = get_existing_cves(cves)  # Filtra solo le CVE che esistono nel database
            # Se non ci sono host (nessuna suddivisione), aggiungi un host generico
            return {"total_count": len(existing_cves), "cves": existing_cves, "hosts": {"Generic": existing_cves}}
        
        elif input_data.name.endswith(('.xls', '.xlsx')):
            cves, hosts = extract_cves_from_excel(input_data)
            existing_cves = get_existing_cves(cves)  # Filtra solo le CVE che esistono nel database
            # Calcola il totale delle CVE esistenti inclusi quelle di ogni host
            total_count = sum(len(host_cves) for host_cves in hosts.values()) if hosts else len(existing_cves)
            return {"total_count": total_count, "cves": existing_cves, "hosts": hosts}
    
    return {"total_count": 0, "cves": set(), "hosts": None}

