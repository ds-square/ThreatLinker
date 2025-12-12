# data/views.py

from django.shortcuts import render, redirect
from django.db import connection
from django.conf import settings
from django.db.utils import OperationalError
from django.http import JsonResponse
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.contrib import messages

from data.models import DataUpdate
from data.tasks import start_update_process, reinitialize_entry_task 
from data.updater.update_utils import get_progress_status, get_progress_status_dict
from data.stats.cve_stats import get_cve_statistics
from data.stats.cwe_stats import get_cwe_statistics
from data.stats.capec_stats import get_capec_statistics

## Database STATUS

def database_status_view(request):
    # Verifica connessione al database
    db_connected = True
    db_version = "Unknown"
    max_connections = "Unknown"
    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            # Ottieni versione del database
            cursor.execute("SELECT version();")
            db_version = cursor.fetchone()[0]
            
            # Ottieni il numero massimo di connessioni
            cursor.execute("SHOW max_connections;")
            max_connections = cursor.fetchone()[0]
    except OperationalError:
        db_connected = False

    # Recupera informazioni sul database
    db_status = {
        "database_name": settings.DATABASES['default']['NAME'],
        "database_user": settings.DATABASES['default']['USER'],
        "is_connected": db_connected,
        "database_version": db_version,
        "max_connections": max_connections,
    }

    # Conta il numero di tabelle nel database
    if db_connected:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
            db_status["table_count"] = cursor.fetchone()[0]
    else:
        db_status["table_count"] = "N/A"

    return render(request, 'database/info/status.html', {"db_status": db_status})

### Database Stats

def database_stats_view(request):
    cve_stats = get_cve_statistics()
    cwe_stats = get_cwe_statistics()
    capec_stats = get_capec_statistics()
    return render(request, 'database/info/stats.html', {'cve_stats': cve_stats, 'cwe_stats': cwe_stats, 'capec_stats': capec_stats})

### Database Update Views

def database_update_view(request):
    updates = DataUpdate.objects.all()  # Recupera tutti i record di DataUpdate

    # Verifica se tutte le entità richiedono un aggiornamento
    all_require_update = all(not update.has_been_updated for update in updates)

    # Verifica se tutti gli aggiornamenti sono in stato "In Progress"
    all_in_progress = all(update.status == 'In Progress' for update in updates)

    return render(request, 'database/update/update.html', {
        'updates': updates,
        'all_require_update': all_require_update,
        'all_in_progress': all_in_progress
    })

@require_POST
def database_update_start(request):
    """
    View che avvia l'aggiornamento dei dati di tutte le entità e redireziona alla pagina di stato.
    """
    try:
        # Avvia la task in background con Celery
        start_update_process.delay()

        # Usa HttpResponseRedirect per redirezionare alla pagina di stato
        return HttpResponseRedirect(reverse('data:database_update_progress'))
    except Exception as e:
        # Gestione errori generici
        return JsonResponse({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}"
        })

def database_update_progress_view(request):
    """
    View che visualizza la pagina di stato dell'aggiornamento del database.
    """
    try:
        # Ottieni il dizionario di stato del progresso
        progress = get_progress_status_dict()

        # Controlla se l'aggiornamento è in corso
        if not progress.get("is_updating", False):
            return redirect('data:database_update')
        
        return render(request, 'database/update/update_progress.html')
      
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def progress_status_view(request):
    """
    View per restituire lo stato di avanzamento dell'aggiornamento.
    """
    try:
        return get_progress_status(request)  # Assicurati che `get_progress_status` restituisca `JsonResponse`
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


### Reinitialize (Update)

def reinitialize_entity(request, entity):
    """
    View che avvia la task di reinizializzazione per una specifica entità (CAPEC, CWE, CVE)
    e redireziona alla pagina di stato dell'aggiornamento.
    """
    try:
        # Avvia la task in background con Celery, passando l'entità specificata
        reinitialize_entry_task.delay(entity)

        # Aggiungi un messaggio di successo per l'utente
        messages.success(request, f"The entity {entity} reinitialization process has started.")

        # Redirige alla pagina di stato dell'aggiornamento
        return HttpResponseRedirect(reverse('data:database_update'))
    
    except Exception as e:
        # Gestione errori generici
        return JsonResponse({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}"
        })