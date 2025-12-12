import json
import os
from django.utils import timezone
from django.db.models import Count
from data.models import CVE, CWE, DataUpdate  # Assicurati di usare il percorso corretto ai modelli
from datetime import datetime
from collections import Counter

# Path al file JSON per salvare le statistiche
STATS_FILE_PATH = os.path.join(os.path.dirname(__file__), "generated_cve_stats.json")

def analyze_top_vendors_and_products():
    vendor_counter = Counter()
    product_counter = Counter()

    for cve in CVE.objects.exclude(vulnerable_cpe_uris__isnull=True):
        for cpe_uri in cve.vulnerable_cpe_uris:
            try:
                # Esempio CPE: "cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*"
                parts = cpe_uri.split(':')
                vendor = parts[3]  # vendor
                product = parts[4]  # product

                vendor_counter[vendor] += 1
                product_counter[product] += 1
            except IndexError:
                # In caso di un URI CPE malformato, ignoralo
                continue

    # Ottieni i top 20 vendor e prodotti
    top_20_vendors = vendor_counter.most_common(20)
    top_20_products = product_counter.most_common(20)

    return {
        'top_20_vendors': top_20_vendors,
        'top_20_products': top_20_products
    }

def get_cve_statistics():
    # Se il file esiste, carica i dati e controlla il timestamp
    if os.path.exists(STATS_FILE_PATH):
        with open(STATS_FILE_PATH, 'r') as f:
            stats = json.load(f)

        # Controlla la data di aggiornamento del file di statistiche
        stats_timestamp = datetime.fromisoformat(stats.get("timestamp"))
        stats_timestamp = timezone.make_aware(stats_timestamp, timezone.get_current_timezone())

        # Ottieni l'ultimo aggiornamento delle CVE
        last_cve_update = DataUpdate.objects.filter(name='CVE').first()

        # Se il file è aggiornato rispetto all'ultimo aggiornamento del database, restituisci i dati esistenti
        if last_cve_update and last_cve_update.last_update <= stats_timestamp:
            return stats

    # Calcola le statistiche poiché il file è assente o non aggiornato
    total_cve_count = CVE.objects.count()
    valid_cves = CVE.objects.exclude(description__startswith="Rejected reason")
    valid_cve_count = valid_cves.count()

    # 1. Distribuzione per rating
    rating_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    rated_cves = valid_cves.exclude(impact_v2__isnull=True, impact_v3__isnull=True)
    for cve in rated_cves:
        rating = cve.get_overall_rating()
        if rating:
            rating_counts[rating] += 1

    total_rated_cves = sum(rating_counts.values())
    rating_percentages = {
        rating: (count / total_rated_cves) * 100 if total_rated_cves > 0 else 0
        for rating, count in rating_counts.items()
    }

    # 2. Numero di CVE per anno e percentuali
    current_year = datetime.now().year
    cve_per_year_counts = {}
    for cve in valid_cves:
        year = int(cve.id.split('-')[1])
        if year <= current_year:
            cve_per_year_counts[year] = cve_per_year_counts.get(year, 0) + 1

    total_valid_cves = sum(cve_per_year_counts.values())
    cve_per_year_percentages = {
        year: (count / total_valid_cves) * 100 if total_valid_cves > 0 else 0
        for year, count in cve_per_year_counts.items()
    }

    # 3. Numero di CVE con almeno una CWE associata e percentuale
    cves_with_cwe_count = valid_cves.filter(related_cwes__isnull=False).distinct().count()
    cves_with_cwe_percentage = (cves_with_cwe_count / valid_cve_count) * 100 if valid_cve_count > 0 else 0

    # 4. Numero di CVE con CWE per anno e percentuale
    cves_with_cwe_per_year = {}
    for year, count in cve_per_year_counts.items():
        cves_with_cwe_year_count = valid_cves.filter(
            related_cwes__isnull=False, id__contains=f"CVE-{year}-"
        ).distinct().count()
        cves_with_cwe_per_year[year] = {
            'count': cves_with_cwe_year_count,
            'percentage': (cves_with_cwe_year_count / count) * 100 if count > 0 else 0
        }

    # 5. Le 10 CWE più presenti per anno
    top_10_cwes_per_year = {}
    for year in cve_per_year_counts.keys():
        top_cwes = (
            CWE.objects.filter(cve_related_weaknesses__id__contains=f"CVE-{year}-")
            .annotate(cve_count=Count('cve_related_weaknesses'))
            .order_by('-cve_count')[:10]
        )
        top_10_cwes_per_year[year] = [(cwe.id, cwe.cve_count) for cwe in top_cwes]

    # 6. Le 20 CWE più presenti di sempre
    top_20_cwes_all_time = (
        CWE.objects.annotate(cve_count=Count('cve_related_weaknesses'))
        .order_by('-cve_count')[:20]
    )
    top_20_cwes_all_time_list = [(cwe.id, cwe.cve_count) for cwe in top_20_cwes_all_time]

    # 7. Top 20 vendor e prodotti dai CPE
    top_vendors_and_products = analyze_top_vendors_and_products()

    # Aggiunta del timestamp e preparazione dei dati
    timestamp = datetime.now().isoformat()
    stats = {
        'timestamp': timestamp,
        'total_cve_count': total_cve_count,
        'valid_cve_count': valid_cve_count,
        'cve_rating_percentages': rating_percentages,
        'cve_per_year_counts': cve_per_year_counts,
        'cve_per_year_percentages': cve_per_year_percentages,
        'cves_with_cwe_count': cves_with_cwe_count,
        'cves_with_cwe_percentage': cves_with_cwe_percentage,
        'cves_with_cwe_per_year': cves_with_cwe_per_year,
        'top_10_cwes_per_year': top_10_cwes_per_year,
        'top_20_cwes_all_time': top_20_cwes_all_time_list,
        'top_20_vendors': top_vendors_and_products['top_20_vendors'],
        'top_20_products': top_vendors_and_products['top_20_products'],
    }
    
    # Salvataggio delle statistiche in formato JSON
    with open(STATS_FILE_PATH, 'w') as f:
        json.dump(stats, f, indent=4)
    print(f"Statistiche salvate in {STATS_FILE_PATH}")

    return stats
