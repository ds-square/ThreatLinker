# graph/urls.py
from django.urls import path
from . import views

app_name = 'graph'  # Definisci app_name

urlpatterns = [
    path('view/task/<int:task_id>/', views.graph_task_view, name='graph_task_view'),
    path('elaborate/task/<int:task_id>/', views.elaborate_graph_task, name='elaborate_graph_task'),
]