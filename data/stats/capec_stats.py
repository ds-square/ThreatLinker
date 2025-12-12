# data/stats/capec_stats.py

import json
import os
from django.utils import timezone
from django.db.models import Count, Avg
from data.models import CAPEC, AttackStep, DataUpdate, ExecutionFlow
from datetime import datetime

# Path al file JSON per salvare le statistiche
STATS_FILE_PATH = os.path.join(os.path.dirname(__file__), "generated_capec_stats.json")

def get_capec_statistics():
    # Se il file esiste, carica i dati e controlla il timestamp
    if os.path.exists(STATS_FILE_PATH):
        with open(STATS_FILE_PATH, 'r') as f:
            stats = json.load(f)

        # Controlla la data di aggiornamento del file di statistiche
        stats_timestamp = datetime.fromisoformat(stats.get("timestamp"))
        stats_timestamp = timezone.make_aware(stats_timestamp, timezone.get_current_timezone())

        # Ottieni l'ultimo aggiornamento delle CAPEC
        last_capec_update = DataUpdate.objects.filter(name='CAPEC').first()

        # Se il file è aggiornato rispetto all'ultimo aggiornamento del database, restituisci i dati esistenti
        if last_capec_update and last_capec_update.last_update <= stats_timestamp:
            return stats

    # Calcola le statistiche poiché il file è assente o non aggiornato
    total_capec_count = CAPEC.objects.count()
    deprecated_capec_count = CAPEC.objects.filter(status='Deprecated').count()
    valid_capec_count = total_capec_count - deprecated_capec_count

    # Numero di CAPEC con Execution Flow
    capecs_with_execution_flow_count = CAPEC.objects.filter(execution_flow_instance__isnull=False).count()
    capecs_without_execution_flow_count = valid_capec_count - capecs_with_execution_flow_count

    # Numero di Attack Steps totali
    total_attack_steps_count = AttackStep.objects.count()

    # Distribuzione del numero di Attack Steps per Execution Flow per ogni CAPEC
    attack_step_distribution = {}
    capecs_with_execution_flow = CAPEC.objects.filter(execution_flow_instance__isnull=False)
    
    for capec in capecs_with_execution_flow:
        # Conta gli Attack Steps per l'Execution Flow di questo CAPEC
        num_steps = capec.execution_flow_instance.attack_steps.count()
        
        # Aggiorna il dizionario di distribuzione
        if num_steps not in attack_step_distribution:
            attack_step_distribution[num_steps] = {'count': 0, 'percentage': 0.0}
        attack_step_distribution[num_steps]['count'] += 1

    # Calcola la percentuale per ogni numero di Attack Steps
    for num_steps, data in attack_step_distribution.items():
        data['percentage'] = (data['count'] / capecs_with_execution_flow_count) * 100

    # Calcolo della media del numero di Attack Steps per CAPEC con Execution Flow
    avg_attack_steps_per_capec = (
        ExecutionFlow.objects
        .annotate(num_steps=Count('attack_steps'))
        .aggregate(Avg('num_steps'))['num_steps__avg']
    ) or 0

    # Distribuzione delle varie "phase" degli Attack Steps
    phase_distribution = (
        AttackStep.objects
        .values('phase')
        .annotate(count=Count('id'))
    )

    phase_distribution_dict = {
        entry['phase']: {
            'count': entry['count'],
            'percentage': (entry['count'] / total_attack_steps_count) * 100
        }
        for entry in phase_distribution
    }

    # Aggiunta del timestamp e preparazione dei dati
    timestamp = datetime.now().isoformat()
    stats = {
        'timestamp': timestamp,
        'total_capec_count': total_capec_count,
        'deprecated_capec_count': deprecated_capec_count,
        'valid_capec_count': valid_capec_count,
        'capecs_with_execution_flow_count': capecs_with_execution_flow_count,
        'capecs_without_execution_flow_count': capecs_without_execution_flow_count,
        'total_attack_steps_count': total_attack_steps_count,
        'attack_step_distribution': attack_step_distribution,
        'avg_attack_steps_per_capec': avg_attack_steps_per_capec,
        'phase_distribution': phase_distribution_dict,
    }

    # Salvataggio delle statistiche in formato JSON
    with open(STATS_FILE_PATH, 'w') as f:
        json.dump(stats, f, indent=4)
    print(f"Statistiche CAPEC salvate in {STATS_FILE_PATH}")

    return stats
