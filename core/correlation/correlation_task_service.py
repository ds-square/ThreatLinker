from core.models import Task, GroundTruth
from core.tasks import manage_task_status
from debug.debug_utils import debug_print

def create_correlation_task_structure(task_name, task_notes, hosts, similarity_methods, preprocessing_options, capec_version):
    """
    Funzione per creare la struttura delle Task, CorrelationTask e SingleCorrelation con stato 'Pending' e
    per tenere traccia delle CVE e degli host associati.
    """
    # Creazione della Task principale con stato 'pending'
    task = Task.objects.create(
        name=task_name,
        notes=task_notes,
        ai_models = similarity_methods,
        type='correlation',
        status='pending',  # Stato iniziale
        cve_hosts={}  # Inizializza il campo cve_hosts come dizionario vuoto
    )

    # Costruzione del dizionario cve_hosts
    cve_hosts_dict = {}

    for host, cves in hosts.items():
        # Aggiungi gli host per ogni CVE
        for cve in cves:
            if cve not in cve_hosts_dict:
                cve_hosts_dict[cve] = []  # Inizializza la lista per l'host
            cve_hosts_dict[cve].append(host)

    # Una volta che tutte le CorrelationTask sono create, aggiorna il campo cve_hosts della Task
    task.cve_hosts = cve_hosts_dict
    task.save()  # Salva il dizionario cve_hosts nella Task

    # Debug: Mostra i campi della Task appena creata
    debug_print("INFO", f"Task created with ID {task.id} - name: {task.name}, status: {task.status}, cve_hosts: {task.cve_hosts}")

    # Avvia la gestione della Task e delle CorrelationTask in parallelo
    manage_task_status.delay(task.id, similarity_methods, preprocessing_options, capec_version)  # Passiamo la task intera a Celery per l'elaborazione

def create_groundtruth_task_structure(task_name, task_notes, groundtruth_id, similarity_methods, preprocessing_options, capec_version):
    """
    Funzione per creare la struttura delle Task, CorrelationTask e SingleCorrelation con stato 'Pending' e
    per tenere traccia delle CVE e degli host associati.
    """
    # Recupera il GroundTruth specifico
    try:
        groundtruth = GroundTruth.objects.get(id=groundtruth_id)
    except GroundTruth.DoesNotExist:
        raise ValueError(f"GroundTruth with ID {groundtruth_id} does not exist.")
    
    # Estrai tutte le CVE univoche dal campo mapping del GroundTruth
    cve_list = list(set(groundtruth.mapping.keys()))  # Usa un set per eliminare duplicati e poi convertilo in lista

    # Costruzione del dizionario cve_hosts_dict con "Generic host"
    cve_hosts_dict = {cve: ['Generic'] for cve in cve_list}

    # Creazione della Task principale con stato 'pending'
    task = Task.objects.create(
        name=task_name,
        notes=task_notes,
        ai_models = similarity_methods,
        type='groundtruth',
        status='pending',  # Stato iniziale
        cve_hosts=cve_hosts_dict  # Associazioni CVE -> "Generic host"
    )

    task.save()  # Salva il dizionario cve_hosts nella Task

    # Debug: Mostra i campi della Task appena creata
    debug_print("INFO", f"Task created with ID {task.id} - name: {task.name}, status: {task.status}, cve_hosts: {task.cve_hosts}")

    # Avvia la gestione della Task e delle CorrelationTask in parallelo
    manage_task_status.delay(task.id, similarity_methods, preprocessing_options, capec_version)  # Passiamo la task intera a Celery per l'elaborazione
