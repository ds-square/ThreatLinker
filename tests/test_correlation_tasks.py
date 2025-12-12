import os
import django
import multiprocessing

# Imposta l'ambiente Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatlinker.settings')
django.setup()

from core.models import Task
from core.tasks import manage_task_status
from debug.debug_utils import debug_print


def create_correlation_task_structure(task_name, task_notes, hosts, similarity_methods, preprocessing_options, capec_version):
    """
    Funzione per creare una struttura di Task di correlazione direttamente sul database configurato.
    """
    # Creazione della Task principale
    task = Task.objects.create(
        name=task_name,
        notes=task_notes,
        ai_models=similarity_methods,
        type='correlation',
        status='pending',  # Stato iniziale
        cve_hosts={}  # Inizializza il campo cve_hosts come dizionario vuoto
    )

    # Costruzione del dizionario cve_hosts
    cve_hosts_dict = {}

    for host, cves in hosts.items():
        for cve in cves:
            if cve not in cve_hosts_dict:
                cve_hosts_dict[cve] = []  # Inizializza la lista per l'host
            cve_hosts_dict[cve].append(host)

    # Una volta costruito, aggiorna il campo cve_hosts della Task
    task.cve_hosts = cve_hosts_dict
    task.save()

    # Debug: Mostra i dettagli della Task
    debug_print("INFO", f"Task created with ID {task.id}: {task.name}, status: {task.status}")

    # Avvia la gestione della Task
    manage_task_status.delay(task.id, similarity_methods, preprocessing_options, capec_version)


if __name__ == "__main__":
    task_name = "Test Task Production"
    task_notes = "This is a test task on the production database."
    hosts = {
        "host1.example.com": ["CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708"],
        "host2.example.com": ["CVE-2018-11776", "CVE-2017-0144", "CVE-2022-0847", "CVE-2019-11510"],
        "host3.example.com": ["CVE-2021-26855", "CVE-2022-22965", "CVE-2020-0601", "CVE-2021-44228"],
        #"host4.example.com": ["CVE-2017-5715", "CVE-2020-0796", "CVE-2021-34473", "CVE-2019-10149", "CVE-2015-7297"],
        #"host5.example.com": ["CVE-2019-12384", "CVE-2018-7600", "CVE-2019-5736", "CVE-2020-1350", "CVE-2021-31589"],
        #"host6.example.com": ["CVE-2019-0199", "CVE-2017-5638", "CVE-2019-0709", "CVE-2018-4939", "CVE-2021-41878"]
    }
    similarity_methods = ["SBERT", "ATTACKBERT"]
    preprocessing_options = {"lowercase": True}
    capec_version = "Basic"

    # Creazione e gestione della Task
    create_correlation_task_structure(
        task_name=task_name,
        task_notes=task_notes,
        hosts=hosts,
        similarity_methods=similarity_methods,
        preprocessing_options=preprocessing_options,
        capec_version=capec_version,
    )
