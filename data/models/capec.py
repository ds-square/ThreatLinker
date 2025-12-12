from django.db import models
import re 

class CAPEC(models.Model):

    # Definizione delle scelte predefinite
    CAPEC_ABSTRACTION_CHOICES = [
        ('Meta', 'Meta'),
        ('Standard', 'Standard'),
        ('Detailed', 'Detailed'),
    ]

    CAPEC_STATUS_CHOICES = [
        ('Stable', 'Stable'),
        ('Deprecated', 'Deprecated'),
        ('Draft', 'Draft'),
        ('Incomplete', 'Incomplete'),
        ('Obsolete', 'Obsolete'),
        ('Usable', 'Usable'),
    ]

    CAPEC_NATURE_CHOICES = [
        ('ChildOf', 'ChildOf'),
        ('ParentOf', 'ParentOf'),
        ('PeerOf', 'PeerOf'),
        ('CanAlsoBe', 'CanAlsoBe'),
        ('CanFollow', 'CanFollow'),
        ('CanPrecede', 'CanPrecede'),
    ]

    CAPEC_LIKELIHOOD_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Unknown', 'Unknown'),
    ]

    CAPEC_SEVERITY_CHOICES = [
        ('Very High', 'Very High'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Very Low', 'Very Low'),
    ]

    id = models.CharField(max_length=10, unique=True, primary_key=True)  # Es. CAPEC-108
    name = models.CharField(max_length=255, default="Generic Name")  # Nome del pattern di attacco
    abstraction = models.CharField(max_length=50, choices=CAPEC_ABSTRACTION_CHOICES, default="Standard")  # Livello di astrazione
    status = models.CharField(max_length=50, choices=CAPEC_STATUS_CHOICES, default="Draft")  # Stato
    likelihood_of_attack = models.CharField(max_length=50, choices=CAPEC_LIKELIHOOD_CHOICES, blank=True, null=True)  # Probabilità di attacco
    typical_severity = models.CharField(max_length=50, choices=CAPEC_SEVERITY_CHOICES, blank=True, null=True)  # Gravità tipica
    description = models.TextField(blank=True, null=True)  # Descrizione del pattern di attacco
    description_aggregated = models.TextField(blank=True, null=True)
    extended_description = models.TextField(blank=True, null=True)  # Descrizione estesa del pattern di attacco
    extended_description_aggregated = models.TextField(blank=True, null=True)
    indicators = models.JSONField(blank=True, null=True)  # Indicatori di attacco
    indicators_aggregated = models.TextField(blank=True, null=True)
    prerequisites = models.JSONField(blank=True, null=True)  # Requisiti necessari
    prerequisites_aggregated = models.TextField(blank=True, null=True)
    resources_required = models.JSONField(blank=True, null=True)  # Risorse necessarie
    resources_required_aggregated = models.TextField(blank=True, null=True)
    mitigations = models.JSONField(blank=True, null=True)  # Strategie di mitigazione
    mitigations_aggregated = models.TextField(blank=True, null=True)
    example_instances = models.JSONField(blank=True, null=True)  # Esempi di istanze
    example_instances_aggregated = models.TextField(blank=True, null=True)
    consequences = models.JSONField(blank=True, null=True)  # Conseguenze
    consequences_aggregated = models.TextField(blank=True, null=True)
    skills_required = models.JSONField(blank=True, null=True)  # Competenze richieste
    skills_required_aggregated = models.TextField(blank=True, null=True)
    alternate_terms = models.JSONField(blank=True, null=True)  # Termini alternativi
    alternate_terms_aggregated = models.TextField(blank=True, null=True)

    # Campo aggregato complessivo basato sui campi aggregati
    overall_aggregated_text = models.TextField(blank=True, null=True)

    related_cwe_weaknesses = models.ManyToManyField('CWE', blank=True, related_name='related_to_capecs')  # Relazione con CWE
    related_patterns = models.ManyToManyField('self', through='CAPECRelatedAttackPattern', symmetrical=False, blank=True)
    
    execution_flow_instance = models.OneToOneField(
        'ExecutionFlow', on_delete=models.SET_NULL, blank=True, null=True, related_name='associated_capec'
    )  # Relazione con ExecutionFlow

    def save(self, *args, **kwargs):
        """
        Override del metodo save per generare automaticamente i campi aggregati e
        il campo complessivo 'overall_aggregated_text' basato sui campi aggregati.
        """
        # Genera i campi aggregati concatenando i valori delle liste JSON in stringhe
        self.description_aggregated = self.description or ""
        self.extended_description_aggregated = self.extended_description or ""
        self.indicators_aggregated = " ".join(self.indicators or [])
        self.prerequisites_aggregated = " ".join(self.prerequisites or [])
        self.resources_required_aggregated = " ".join(self.resources_required or [])
        self.mitigations_aggregated = " ".join(self.mitigations or [])
        self.example_instances_aggregated = " ".join(self.example_instances or [])
        
        # Campo aggregato complessivo: concatenazione di tutti i campi aggregati
        aggregated_fields = [
            self.description_aggregated,
            self.extended_description_aggregated,
            self.indicators_aggregated,
            self.prerequisites_aggregated,
            self.resources_required_aggregated,
            self.mitigations_aggregated,
            self.example_instances_aggregated,
        ]
        self.overall_aggregated_text = " ".join(aggregated_fields)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} - {self.name}"

    def get_numeric_id(self):
        """
        Estrae il numero dall'ID CAPEC nel formato 'CAPEC-XXX'.
        Se l'ID non è nel formato previsto, restituisce None.
        """
        match = re.match(r"CAPEC-(\d+)", self.id)
        if match:
            return int(match.group(1))  # Restituisce il numero come intero
        return None  # Se non trova una corrispondenza, restituisce None
    
class ExecutionFlow(models.Model):
    capec = models.OneToOneField(CAPEC, related_name='execution_flow', on_delete=models.CASCADE)

    def __str__(self):
        return f"Execution Flow for {self.capec}"

class AttackStep(models.Model):
    execution_flow = models.ForeignKey(ExecutionFlow, related_name='attack_steps', on_delete=models.CASCADE)
    step = models.CharField(max_length=10)  # Permette suffissi
    phase = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    description_aggregated = models.TextField(blank=True, null=True)  # Descrizione preprocessata e aggregata
    techniques = models.JSONField(blank=True, null=True)
    techniques_aggregated = models.TextField(blank=True, null=True)  # Tecniche preprocessate e aggregate

    def save(self, *args, **kwargs):
        """
        Override del metodo save per generare automaticamente i campi aggregati.
        """
        self.description_aggregated = self.description or ""
        self.techniques_aggregated = " ".join(self.techniques or [])
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f"{self.execution_flow} - Step {self.step} - {self.phase}"

class CAPECRelatedAttackPattern(models.Model):
    source_capec = models.ForeignKey(CAPEC, related_name='source_related_patterns', on_delete=models.CASCADE)
    target_capec = models.ForeignKey(CAPEC, related_name='target_related_patterns', on_delete=models.CASCADE)
    nature = models.CharField(max_length=20, choices=CAPEC.CAPEC_NATURE_CHOICES)

    class Meta:
        unique_together = ('source_capec', 'target_capec', 'nature')

    def __str__(self):
        return f"{self.source_capec} {self.nature} {self.target_capec}"
