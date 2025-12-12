from django.shortcuts import render, get_object_or_404
from core.models import Task  # Sostituisci con il tuo modello corretto se necessario
from django.urls import reverse
from data.models import CVE, CAPEC

def graph_task_data(request, task_id):
    # Ottieni la task specifica dal database
    task = get_object_or_404(Task, id=task_id)

    # Dati specifici per il grafico (esempio, da personalizzare in base alle tue esigenze)
    graph_data = {
        "task_name": task.name,
        "task_status": task.status,
    }

    context = {
        "task": task,
        "graph_data": graph_data,
    }
    return render(request, "graph/graph_task_view.html", context)


def elaborate_graph_task(request, task_id):
    # Ottieni la task specifica dal database
    task = get_object_or_404(Task, id=task_id)

    # Recupera i modelli di AI disponibili per la similarità
    similarity_methods = task.ai_models  # Supponendo sia una lista di metodi

    # Limiti disponibili per le CVE
    cve_limits = [10, 20, 30, 50, 100, 'No Limit']

    context = {
        "task": task,
        "similarity_methods": similarity_methods,
        "cve_limits": cve_limits,
    }

    return render(request, "graph/elaborate_graph_task.html", context)

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse

def graph_task_view(request, task_id):

    # Ottieni la task specifica
    task = get_object_or_404(Task, id=task_id)

    # Recupera i dati dal form
    if request.method == "POST":
        similarity_method = request.POST.get("similarity_method")
        cve_limit = request.POST.get("cve_limit")
        rank_limit = int(request.POST.get("rank_limit", 5))  # Default rank limit a 5
        cve_limit = None if cve_limit == "No Limit" else int(cve_limit)

        # Preleva tutti gli host unici
        cve_hosts = task.cve_hosts or {}
        host_names = set(host for hosts in cve_hosts.values() for host in hosts)

        # Crea un sottoinsieme di CVE per ogni host
        selected_cve = set()  # Per evitare duplicati
        host_cve_map = {}

        for host in host_names:
            host_cves = [cve for cve, hosts in cve_hosts.items() if host in hosts]
            host_selected_cves = []
            for cve in host_cves:
                if cve_limit is None or len(host_selected_cves) < cve_limit:
                    if cve not in selected_cve:
                        host_selected_cves.append(cve)
                        selected_cve.add(cve)
            host_cve_map[host] = host_selected_cves

        # Filtra i SingleCorrelation basandosi sulle CVE selezionate
        correlations = task.single_correlations.filter(cve_id__in=selected_cve)

        # Mappa per salvare i risultati finali
        result_data = {}
        cve_data = {}  # Per salvare id e descrizione delle CVE
        capec_data = {}  # Per salvare informazioni sulle CAPEC

        # Recupera tutte le informazioni sulle CVE dal database
        cve_objects = CVE.objects.filter(id__in=selected_cve)
        cve_lookup = {cve.id: {"id": cve.id, "description": cve.description} for cve in cve_objects}

        # Processa ogni correlazione
        for correlation in correlations:
            # Aggiungi informazioni sulla CVE
            cve_data[correlation.cve_id] = cve_lookup.get(
                correlation.cve_id,
                {"id": correlation.cve_id, "description": "No description available."}
            )

            # Recupera CAPEC correlate
            if similarity_method in correlation.similarity_scores:
                capec_scores = correlation.similarity_scores[similarity_method]
                filtered_capec = [
                    {
                        "capec_id": capec[0],
                        "rank": capec[1]["rank"],
                        "final_score": capec[1]["final_score"],
                    }
                    for capec in capec_scores if capec[1]["rank"] <= rank_limit
                ]
                result_data[correlation.cve_id] = filtered_capec

                # Recupera informazioni per le CAPEC dal database
                capec_ids = [capec["capec_id"] for capec in filtered_capec]
                capec_objects = CAPEC.objects.filter(id__in=capec_ids)
                for capec in capec_objects:
                    capec_data[capec.id] = {
                        "id": capec.id,
                        "name": capec.name,
                        "description": capec.description
                    }

        print(f"CVE Data: {cve_data}")
        print(f"CAPEC Data: {capec_data}")
        print(f"Result Data: {result_data}")

        # Salva i dati nel contesto
        context = {
            "task": task,
            "similarity_method": similarity_method,
            "cve_limit": cve_limit,
            "rank_limit": rank_limit,
            "host_cve_map": host_cve_map,
            "result_data": result_data,
            "cve_data": cve_data,  # Dati dettagliati per le CVE
            "capec_data": capec_data  # Dati dettagliati per le CAPEC
        }

        

        return render(request, "graph/graph_task_data.html", context)

    # Ritorna errore se non POST
    return JsonResponse({"error": "Invalid request method."}, status=400)

