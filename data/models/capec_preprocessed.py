from django.db import models

class PreprocessedCAPEC(models.Model):
    # Collegamento alla CAPEC originale (campo chiave esterna)
    original_capec = models.ForeignKey('CAPEC', on_delete=models.CASCADE, related_name='preprocessed_versions')

    
    # Campi principali
    # Rimuoviamo il vincolo di unicità sull'ID e usiamo unique_together per la combinazione unica
    id = models.AutoField(primary_key=True)  # Usando AutoField per l'ID generato automaticamente
    name = models.CharField(max_length=255, default="Generic Name")
    preprocessed_version = models.CharField(max_length=20, default="v.1.0")
    
    # Campi di testo originali e aggregati
    description = models.TextField(blank=True, null=True)
    description_aggregated = models.TextField(blank=True, null=True)
    extended_description = models.TextField(blank=True, null=True)
    extended_description_aggregated = models.TextField(blank=True, null=True)
    indicators = models.JSONField(blank=True, null=True)
    indicators_aggregated = models.TextField(blank=True, null=True)
    prerequisites = models.JSONField(blank=True, null=True)
    prerequisites_aggregated = models.TextField(blank=True, null=True)
    resources_required = models.JSONField(blank=True, null=True)
    resources_required_aggregated = models.TextField(blank=True, null=True)
    mitigations = models.JSONField(blank=True, null=True)
    mitigations_aggregated = models.TextField(blank=True, null=True)
    example_instances = models.JSONField(blank=True, null=True)
    example_instances_aggregated = models.TextField(blank=True, null=True)
    consequences = models.JSONField(blank=True, null=True)
    consequences_aggregated = models.TextField(blank=True, null=True)
    skills_required = models.JSONField(blank=True, null=True)
    skills_required_aggregated = models.TextField(blank=True, null=True)
    alternate_terms = models.JSONField(blank=True, null=True)
    alternate_terms_aggregated = models.TextField(blank=True, null=True)

    # Campo aggregato complessivo basato sui campi aggregati
    overall_aggregated_text = models.TextField(blank=True, null=True)

    # Relazione con il flusso di esecuzione preprocessato
    preprocessed_execution_flow = models.OneToOneField(
        'PreprocessedExecutionFlow', on_delete=models.SET_NULL, blank=True, null=True, related_name='associated_capec'
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['original_capec', 'preprocessed_version'], name='unique_capec_version')
        ]

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
        self.consequences_aggregated = " ".join(self.consequences or [])
        self.skills_required_aggregated = " ".join(self.skills_required or [])
        self.alternate_terms_aggregated = " ".join(self.alternate_terms or [])
        
        # Campo aggregato complessivo: concatenazione di tutti i campi aggregati
        aggregated_fields = [
            self.description_aggregated,
            self.extended_description_aggregated,
            self.indicators_aggregated,
            self.prerequisites_aggregated,
            self.resources_required_aggregated,
            self.mitigations_aggregated,
            self.example_instances_aggregated,
            self.consequences_aggregated,
            self.skills_required_aggregated,
            self.alternate_terms_aggregated
        ]
        self.overall_aggregated_text = " ".join(aggregated_fields)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Preprocessed CAPEC {self.original_capec.id} - {self.name}"
    
    @property
    def original_capec_id(self):
        """
        Restituisce l'ID della CAPEC originale collegata a questa versione preprocessata.
        """
        return self.original_capec.id

class PreprocessedExecutionFlow(models.Model):
    preprocessed_capec = models.OneToOneField('PreprocessedCAPEC', related_name='execution_flow', on_delete=models.CASCADE)

    def __str__(self):
        return f"Preprocessed Execution Flow for {self.preprocessed_capec.id}"

class PreprocessedAttackStep(models.Model):
    preprocessed_execution_flow = models.ForeignKey(
        PreprocessedExecutionFlow, related_name='preprocessed_attack_steps', on_delete=models.CASCADE
    )
    step = models.CharField(max_length=10)  # Permette suffissi
    phase = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)  # Descrizione originale del passo
    description_aggregated = models.TextField(blank=True, null=True)  # Descrizione preprocessata e aggregata
    techniques = models.JSONField(blank=True, null=True)  # Tecniche originali
    techniques_aggregated = models.TextField(blank=True, null=True)  # Tecniche preprocessate e aggregate

    def save(self, *args, **kwargs):
        """
        Override del metodo save per generare automaticamente i campi aggregati.
        """
        self.description_aggregated = self.description or ""
        self.techniques_aggregated = " ".join(self.techniques or [])
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.preprocessed_execution_flow} - Step {self.step} - {self.phase}"
