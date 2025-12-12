# core/urls.py
from django.urls import path
from . import views

app_name = 'core'  # Definisci app_name

urlpatterns = [
    # Text Similarity and Preprocessing Examples
    path('text-similarity/', views.text_similarity, name='text_similarity'),
    path('text-similarity/results/', views.text_similarity_result, name='text_similarity_result'),
    path('text-preprocessing/', views.text_preprocessing, name='text_preprocessing'),
    path('text-preprocessing/results/', views.text_preprocessing_results, name='text_preprocessing_results'),
    
    # Tasks
    path('tasks/', views.tasks_list, name='tasks_list'),
    path('tasks/<int:task_id>/', views.task_detail, name='task_detail'),
    path('tasks/<int:task_id>/cve/<str:cve_id>/', views.single_correlation_detail, name='single_correlation_detail'),
    path('tasks/<int:task_id>/delete/', views.delete_task, name='delete_task'),  # URL per eliminare una task
    path('tasks/<int:task_id>/export-top-capecs/', views.export_top_capecs, name='export_top_capecs'),
    path("tasks/<int:task_id>/export-groundtruth-results/", views.export_groundtruth_results, name="export_groundtruth_results"),
    path('tasks/correlation/request/', views.correlation_make_request, name='correlation_make_request'),
    path('tasks/correlation/request/start/', views.start_correlation_task, name='start_correlation_task'),

    # GroundTruths
    path('groundtruths/', views.groundtruth_list, name='groundtruth_list'),
    path('groundtruths/create/', views.create_groundtruth, name='create_groundtruth'),
    path('groundtruths/<int:groundtruth_id>/', views.groundtruth_detail, name='groundtruth_detail'),
    path('groundtruths/<int:task_id>/graphs/', views.groundtruth_graphs, name='groundtruth_graphs'),
    path('groundtruths/<int:groundtruth_id>/delete/', views.delete_groundtruth, name='delete_groundtruth'),
    path('groundtruths/<int:groundtruth_id>/correlate/', views.correlate_groundtruth, name='correlate_groundtruth'),
    path('groundtruths/<int:groundtruth_id>/correlate/start/', views.start_groundtruth_correlation_task, name='start_groundtruth_correlation_task'),
    path('ajax/get_cve_suggestions/', views.get_cve_suggestions, name='get_cve_suggestions'),
    path('ajax/get_capec_suggestions/', views.get_capec_suggestions, name='get_capec_suggestions'),
]