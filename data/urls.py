# data/urls.py

from django.urls import path
from . import views

app_name = 'data'  # Definisci app_name

urlpatterns = [
    path('status/', views.database_status_view, name='database_status'), # Database Status URL
    path('stats/', views.database_stats_view, name="database_stats"),
    path('update/', views.database_update_view, name='database_update'),  # URL per la pagina di aggiornamento
    path('update/start/', views.database_update_start, name='database_update_start'),  # Nuovo URL per iniziare l'aggiornamento
    path('update/progress/', views.database_update_progress_view, name='database_update_progress'),  # Nuovo URL per iniziare l'aggiornamento
    path('update/progress/get/', views.progress_status_view, name='progress_status'),
    path('reinitialize/<str:entity>/', views.reinitialize_entity, name='reinitialize_entity'),
]