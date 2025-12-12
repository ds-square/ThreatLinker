# threatlinker/celery.py
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings
import logging

# Configura il logger di Celery
logging.basicConfig(level=logging.WARNING)  # Imposta il livello a WARNING per tutto
logger = logging.getLogger("celery")
logger.setLevel(logging.WARNING)

# Imposta il modulo di impostazioni di Django per Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatlinker.settings')

# Crea l'applicazione Celery
app = Celery('threatlinker')

# Carica le impostazioni di Celery dal file settings.py
app.config_from_object('django.conf:settings', namespace='CELERY')

# Cerca task definiti nelle app registrate in Django
app.autodiscover_tasks()
