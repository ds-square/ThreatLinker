# data/apps.py
from django.apps import AppConfig

class DataConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'data'

    def ready(self):
        # Importa i segnali per collegare i listener al caricamento dell’app
        import data.signals