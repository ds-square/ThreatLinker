from django.urls import path
from . import views

app_name = 'view' 

urlpatterns = [
    path('', views.homepage, name='homepage'),
    path('view/cve/<str:cve_id>/', views.view_cve, name='view_cve'),
    path('view/cwe/<str:cwe_id>/', views.view_cwe, name='view_cwe'),
    path('view/capec/<str:capec_id>/', views.view_capec, name='view_capec'),
    path('view/error/', views.view_error_page, name='view_error'),

    path('search/', views.search_view, name='search'),
    path('search/results/', views.search_results_view, name='search_results'),

    
]