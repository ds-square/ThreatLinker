# data/middleware.py

from django.shortcuts import redirect
from .models import DataUpdate

class CheckUpdateMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Escludi il middleware per le pagine di amministrazione
        if request.path.startswith('/admin/'):
            return self.get_response(request)

        # Escludi tutte le URL che iniziano con '/database'
        if request.path.startswith('/database'):
            return self.get_response(request)
        
        # Reindirizza alla pagina di aggiornamento se non ci sono record o se sono necessari aggiornamenti
        if not DataUpdate.objects.exists() or not self.check_all_updates():
            return redirect('data:database_update')

        response = self.get_response(request)
        return response

    def check_all_updates(self):
        # Controlla se esiste almeno un record con `has_been_updated=False`
        updates_needed = DataUpdate.objects.filter(has_been_updated=False).exists()
        return not updates_needed


