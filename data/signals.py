# data/signals.py
from celery.signals import after_task_publish, task_failure, task_revoked
from data.models import DataUpdate

@after_task_publish.connect
def set_in_progress(sender=None, **kwargs):
    """
    Imposta i DataUpdate su 'In Progress' quando la task di aggiornamento viene pubblicata.
    """
    if sender == 'data.tasks.start_update_process':  # Verifica che sia la task di aggiornamento
        print("Signal after_task_publish triggered: impostazione 'In Progress'")
        DataUpdate.objects.filter(status="Pending").update(status="In Progress")


@task_failure.connect
def reset_updates_on_failure(sender=None, **kwargs):
    """
    Reimposta i DataUpdate su 'Pending' in caso di fallimento della task di aggiornamento.
    """
    if sender.name == 'data.tasks.start_update_process':  # Solo per la task di aggiornamento
        print("Signal task_failure triggered: reimpostazione 'Pending'")
        DataUpdate.objects.filter(status="In Progress").update(status="Pending")


@task_revoked.connect
def reset_updates_on_revoked(sender=None, **kwargs):
    """
    Reimposta i DataUpdate su 'Pending' quando la task di aggiornamento viene interrotta manualmente.
    """
    if sender.name == 'data.tasks.start_update_process':  # Solo per la task di aggiornamento
        print("Signal task_revoked triggered: reimpostazione 'Pending'")
        DataUpdate.objects.filter(status="In Progress").update(status="Pending")
