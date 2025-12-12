# Register your models here.

from django.contrib import admin

from data.models import CVE, CVEReference
from data.models import CWE, CWERelatedWeakness
from data.models import CAPEC, CAPECRelatedAttackPattern, AttackStep, ExecutionFlow
from data.models import PreprocessedCAPEC, PreprocessedExecutionFlow, PreprocessedAttackStep
from data.models import DataUpdate

### CVE Admin View

@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ('id', 'assigner', 'description_short', 'published_date', 'last_modified_date')
    search_fields = ('id', 'description')
    list_filter = ('published_date', 'last_modified_date')
    ordering = ('-published_date',)
    filter_horizontal = ('related_cwes',)  # Aggiunge un'interfaccia per selezionare le CWE

    def description_short(self, obj):
        # Visualizza una versione breve della descrizione per una migliore leggibilità
        return obj.description[:50] + '...' if len(obj.description) > 50 else obj.description
    description_short.short_description = 'Description'

@admin.register(CVEReference)
class CVEReferenceAdmin(admin.ModelAdmin):
    list_display = ('cve', 'url', 'name', 'refsource', 'tags_display')
    search_fields = ('cve__id', 'url', 'name')
    list_filter = ('refsource',)
    
    def tags_display(self, obj):
        # Visualizza i tag come stringa unita da virgole
        return ', '.join(obj.tags or [])
    tags_display.short_description = 'Tags'

### CWE Admin View

class CWERelatedWeaknessInline(admin.TabularInline):
    model = CWERelatedWeakness
    fk_name = 'cwe'  # Campo di foreign key per CWE
    extra = 1
    fields = ('related_cwe', 'relation_type')  # Campi da visualizzare nell'inline

@admin.register(CWE)
class CWEAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'abstraction', 'status', 'structure')  # Campi da mostrare nella lista
    search_fields = ('id', 'name')  # Campi per il filtro di ricerca
    list_filter = ('abstraction', 'status', 'structure')  # Campi per il filtro di visualizzazione
    filter_horizontal = ('related_attack_patterns',)  # Interfaccia orizzontale per selezionare related_attack_patterns
    inlines = [CWERelatedWeaknessInline]  # Inline per le relazioni

    # Configura le opzioni avanzate
    fieldsets = (
        (None, {
            'fields': ('id', 'name', 'description', 'extended_description')
        }),
        ('Details', {
            'fields': ('abstraction', 'structure', 'status', 'likelihood_of_exploit')
        }),
        ('Complex Data', {
            'fields': (
                'affected_resources', 'alternate_terms', 'applicable_platforms', 'background_details',
                'common_consequences', 'demonstrative_examples', 'detection_methods', 
                'functional_areas', 'modes_of_introduction', 'potential_mitigations', 
                'observed_examples'
            )
        }),
        ('Related Attack Patterns', {  # Sezione per related_attack_patterns
            'fields': ('related_attack_patterns',),
        }),
    )

@admin.register(CWERelatedWeakness)
class CWERelatedWeaknessAdmin(admin.ModelAdmin):
    list_display = ('cwe', 'related_cwe', 'relation_type')
    search_fields = ('cwe__id', 'related_cwe__id')


### CAPEC Admin View

class AttackStepInline(admin.TabularInline):
    model = AttackStep
    extra = 1  # Numero di moduli extra da mostrare

class ExecutionFlowAdmin(admin.ModelAdmin):
    inlines = [AttackStepInline]  # Aggiungi gli step come inline

class CAPECAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'execution_flow_instance')  # Visualizza anche l'Execution Flow
    search_fields = ('id', 'name')
    filter_horizontal = ('related_cwe_weaknesses',)  # Aggiunge un'interfaccia per selezionare le CWE
    # Mostra solo le CWEs collegate
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.prefetch_related('related_cwe_weaknesses')

admin.site.register(CAPEC, CAPECAdmin)
admin.site.register(ExecutionFlow, ExecutionFlowAdmin)
admin.site.register(CAPECRelatedAttackPattern)

### Preprocessed CAPECs

@admin.register(PreprocessedCAPEC)
class PreprocessedCAPECAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'name',
        'preprocessed_version',
        'description_aggregated',
        'extended_description_aggregated',
        'indicators_aggregated',
        'prerequisites_aggregated',
        'resources_required_aggregated',
        'mitigations_aggregated',
        'example_instances_aggregated',
        'consequences_aggregated',
        'skills_required_aggregated',
        'alternate_terms_aggregated',
        'overall_aggregated_text',  # Aggiungi anche il campo aggregato complessivo
    )
    search_fields = ('id', 'name', 'preprocessed_version')  # Permette la ricerca per ID e nome

    def get_queryset(self, request):
        # Ottimizza le query per evitare N+1
        return super().get_queryset(request).select_related('original_capec')
    
### Preprocessed ExecutionFlow


class PreprocessedAttackStepInline(admin.TabularInline):
    model = PreprocessedAttackStep
    fields = ('step', 'phase', 'description', 'techniques', 'description_aggregated', 'techniques_aggregated')
    extra = 0  # Non mostrare righe vuote per nuovi AttackStep
    readonly_fields = ('step', 'phase', 'description', 'techniques', 'description_aggregated', 'techniques_aggregated')

class PreprocessedExecutionFlowAdmin(admin.ModelAdmin):
    # Visualizza solo il campo preprocessed_capec, che è il collegamento con PreprocessedCAPEC
    list_display = ('preprocessed_capec',)
    
    # Mostra i PreprocessedAttackStep associati
    inlines = [PreprocessedAttackStepInline]

    # Aggiungi la ricerca per il preprocessed_capec
    search_fields = ('preprocessed_capec__name',)

# Registra i modelli con l'admin
admin.site.register(PreprocessedExecutionFlow, PreprocessedExecutionFlowAdmin)

### DataUpdate


@admin.register(DataUpdate)
class DataUpdateAdmin(admin.ModelAdmin):
    list_display = ['name', 'last_update', 'next_scheduled_update', 'has_been_updated', 'update_frequency', 'version', 'status']
    search_fields = ['name', 'version']
    list_filter = ['status', 'has_been_updated']
    ordering = ['-last_update']
    readonly_fields = ['next_scheduled_update']  # Imposta solo lettura per i campi calcolati

    fieldsets = [
        (None, {'fields': ['name', 'last_update', 'next_scheduled_update', 'has_been_updated', 'update_frequency', 'version', 'status']}),
    ]