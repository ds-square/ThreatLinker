from django.shortcuts import render
from django.shortcuts import render, get_object_or_404

from data.models import CVE, CWE, CAPEC
import random

# Create your views here.

### HOMEPAGE

def homepage(request):
    return render(request, 'homepage.html')

### Search

def search_view(request):
    # Genera la lista degli anni da 1999 a 2024
    years = list(range(1999, 2025))

    entities = [
        {'value': 'CVE', 'name': 'CVE'},
        {'value': 'CWE', 'name': 'CWE'},
        {'value': 'CAPEC', 'name': 'CAPEC'},
        {'value': 'ALL', 'name': 'ALL'},
    ]

    context = {
        'entities': entities,
        'years': years,
    }

    return render(request, 'search/search.html', context)

def search_results_view(request):
    results = []  # Inizializza i risultati a None

    if request.method == 'POST':
        entity = request.POST.get('entity')
        cve_id = request.POST.get('cve-id')
        cwe_id = request.POST.get('cwe-id')
        capec_id = request.POST.get('capec-id')

        if entity == 'CVE':
            if cve_id:
                cve = CVE.objects.filter(id=cve_id).first()
                if cve:
                    results.append(cve)  # Aggiungi l'oggetto CVE alla lista
                if not cve:
                    results = CVE.objects.filter(id__startswith=cve_id)
            else:
                random_count = request.POST.get('random_count', '1')
                random_count = int(random_count) if random_count.isdigit() else 1

                start_year = request.POST.get('start_year')
                end_year = request.POST.get('end_year')

                if start_year.isdigit() and end_year.isdigit():
                    start_year = int(start_year)
                    end_year = int(end_year)

                    random_cves = []
                    for year in range(start_year, end_year + 1):
                        cves_for_year = CVE.objects.filter(published_date__year=year)
                        if cves_for_year.exists():
                            random_cves += random.sample(list(cves_for_year), min(random_count, cves_for_year.count()))

                    results = random_cves

        elif entity == 'CWE':
            if cwe_id:
                results = CWE.objects.filter(id=cwe_id).first()
            else:
                random_count_cwe = request.POST.get('cwe-random-count', '1')
                random_count_cwe = int(random_count_cwe) if random_count_cwe.isdigit() else 1
                results = random.sample(list(CWE.objects.all()), min(random_count_cwe, CWE.objects.count()))

        elif entity == 'CAPEC':
            if capec_id:
                results = CAPEC.objects.filter(id=capec_id).first()
            else:
                random_count_capec = request.POST.get('capec-random-count', '1')
                random_count_capec = int(random_count_capec) if random_count_capec.isdigit() else 1
                results = random.sample(list(CAPEC.objects.all()), min(random_count_capec, CAPEC.objects.count()))

    context = {
        'results': results if results else [],  # Risultato come lista
        'entity': entity,  # Passa l'entità per il template
    }
    return render(request, 'search/search_results.html', context)


### Views for CVE, CWE and CAPEC

def view_cve(request, cve_id):
    try:
        cve = CVE.objects.get(id=cve_id)
    except CVE.DoesNotExist:
        # Chiamata alla view_error_page con il messaggio personalizzato
        return view_error_page(request, f'{cve_id} not found.')
 
    # Prepare the context to pass the CVE data to the template
    context = {
        'cve': cve
    }

    # Render the 'cve.html' template and pass the CVE context
    return render(request, 'view/cve/view_cve.html', context)

def view_cwe(request, cwe_id):
    # Fetch the CVE from the database based on the ID
    try:
        cwe = CVE.objects.get(id=cwe_id)
    except CVE.DoesNotExist:
        # Chiamata alla view_error_page con il messaggio personalizzato
        return view_error_page(request, f'{cwe_id} not found.')
 

    # Prepare the context to pass the CVE data to the template
    context = {
        'cwe': cwe
    }

    # Render the 'cve.html' template and pass the CVE context
    return render(request, 'view/cwe/view_cwe.html', context)

def view_capec(request, capec_id):
    # Fetch the CVE from the database based on the ID
    try:
        capec = CAPEC.objects.get(id=capec_id)
    except CAPEC.DoesNotExist:
        # Chiamata alla view_error_page con il messaggio personalizzato
        return view_error_page(request, f'{capec_id} not found.')
 
    # Prepara il contesto da passare al template
    context = {
        'capec': capec
    }

    # Renderizza il template 'view/capec.html' e passa il contesto del CAPEC
    return render(request, 'view/capec/view_capec.html', context)

# Funzione per visualizzare la pagina di errore
def view_error_page(request, message=None):
    """
    Rende la pagina di errore con un messaggio personalizzato (se fornito).
    Se non viene fornito nessun messaggio, viene utilizzato un messaggio di default.
    :param request: La richiesta HTTP
    :param message: Il messaggio di errore da visualizzare (opzionale)
    :return: La risposta HTTP con il template renderizzato
    """
    if not message:
        message = "Sorry, an error occurred. Please try again later."
    
    return render(request, 'errors/error_page.html', {'message': message})