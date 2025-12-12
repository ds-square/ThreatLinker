# threatlinker/__init__.py
from __future__ import absolute_import, unicode_literals

# Assicura che l'app venga caricato quando Django avvia
from .celery import app as celery_app

__all__ = ('celery_app',)
