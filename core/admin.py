# core/admin.py
from django.contrib import admin
from .models import Task, SingleCorrelation

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'type', 'status', 'created_at', 'updated_at')
    list_filter = ('type', 'status')  # Aggiungi filtri per tipo e stato
    search_fields = ('name', 'notes')  # Rende ricercabile il nome e le note della Task
    ordering = ('-created_at',)  # Ordina per data di creazione discendente

@admin.register(SingleCorrelation)
class SingleCorrelationAdmin(admin.ModelAdmin):
    list_display = ('id', 'cve_id', 'created_at', 'updated_at', 'similarity_scores_display')
    list_filter = ('created_at',)
    search_fields = ('cve_id',)
    ordering = ('-created_at',)

    def similarity_scores_display(self, obj):
        # Estrai i punteggi da similarity_scores
        similarity_scores = obj.similarity_scores
        if similarity_scores:
            return ", ".join([f"{key}: {value}" for key, value in similarity_scores.items()])
        return "No scores available"
    similarity_scores_display.short_description = 'Similarity Scores'



