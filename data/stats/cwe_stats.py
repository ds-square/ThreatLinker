import json
import os
from django.utils import timezone
from django.db.models import Count, Avg
from data.models import CWE, CAPEC, DataUpdate
from datetime import datetime
from collections import Counter

# Path al file JSON per salvare le statistiche
STATS_FILE_PATH = os.path.join(os.path.dirname(__file__), "generated_cwe_stats.json")

def analyze_cwe_capec_links():
    # Top 20 CAPEC maggiormente collegate alle CWE
    top_20_capec_links = (
        CAPEC.objects
        .annotate(cwe_count=Count('cwe_related_attack_patterns'))
        .order_by('-cwe_count')[:20]
    )
    top_20_capec_list = [(capec.id, capec.cwe_count) for capec in top_20_capec_links]

    # Numero medio di CAPEC collegate per CWE
    avg_capec_per_cwe = (
        CWE.objects
        .annotate(capec_count=Count('related_attack_patterns'))
        .aggregate(Avg('capec_count'))['capec_count__avg'] or 0
    )

    # Distribuzione delle CWE in base al numero di CAPEC collegate
    capec_link_distribution = Counter()

    # Itera su ogni CWE e conta il numero di CAPEC collegate
    for cwe in CWE.objects.all():
        capec_count = cwe.related_attack_patterns.count()  # Numero di CAPEC collegate a questa CWE
        capec_link_distribution[capec_count] += 1  # Aggiorna il conteggio per il numero di CAPEC collegate

    # Converti il Counter in un dizionario
    capec_link_distribution_dict = dict(capec_link_distribution)

    return {
        'top_20_capec_links': top_20_capec_list,
        'avg_capec_per_cwe': avg_capec_per_cwe,
        'capec_link_distribution': capec_link_distribution_dict
    }

def get_cwe_statistics():
    # Carica i dati dal file se esistente e aggiornato
    if os.path.exists(STATS_FILE_PATH):
        with open(STATS_FILE_PATH, 'r') as f:
            stats = json.load(f)

        # Verifica se il file è aggiornato
        stats_timestamp = datetime.fromisoformat(stats.get("timestamp"))
        stats_timestamp = timezone.make_aware(stats_timestamp, timezone.get_current_timezone())
        last_cwe_update = DataUpdate.objects.filter(name='CWE').first()

        if last_cwe_update and last_cwe_update.last_update <= stats_timestamp:
            return stats

    # Statistiche sulle CWE e CAPEC correlate
    cwe_capec_stats = analyze_cwe_capec_links()

    # Timestamp per aggiornare il file
    timestamp = datetime.now().isoformat()
    stats = {
        'timestamp': timestamp,
        'top_20_capec_links': cwe_capec_stats['top_20_capec_links'],
        'avg_capec_per_cwe': cwe_capec_stats['avg_capec_per_cwe'],
        'capec_link_distribution': cwe_capec_stats['capec_link_distribution'],
    }

    # Salva le statistiche in formato JSON
    with open(STATS_FILE_PATH, 'w') as f:
        json.dump(stats, f, indent=4)
    print(f"Statistiche salvate in {STATS_FILE_PATH}")

    return stats
