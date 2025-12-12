from django.db import models
from django.db.models import JSONField  # Se utilizzi PostgreSQL

class CWE(models.Model):
    CWE_ABSTRACTION_CHOICES = [
        ("Pillar", "Pillar"),
        ("Compound", "Compound"),
        ("Base", "Base"),
        ("Variant", "Variant"),
        ("Class", "Class"),
    ]

    CWE_STRUCTURE_CHOICES = [
        ("Simple", "Simple"),
        ("Chain", "Chain"),
        ("Composite", "Composite"),
    ]

    CWE_STATUS_CHOICES = [
        ("Draft", "Draft"),
        ("Incomplete", "Incomplete"),
        ("Stable", "Stable"),
        ("Deprecated", "Deprecated"),
        ("Obsolete", "Obsolete"),
        ("Usable", "Usable"),
    ]

    CWE_EXPLOIT_LIKELIHOOD_CHOICES = [
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Unknown", "Unknown"),
    ]

    id = models.CharField(max_length=20, unique=True, primary_key=True)  # Chiave primaria per CWE
    name = models.CharField(max_length=255)  # Nome della CWE, es. "Cross-site Scripting"
    abstraction = models.CharField(max_length=50, choices=CWE_ABSTRACTION_CHOICES)
    structure = models.CharField(max_length=50, choices=CWE_STRUCTURE_CHOICES)
    status = models.CharField(max_length=50, choices=CWE_STATUS_CHOICES)
    description = models.TextField()  # Descrizione breve della CWE
    extended_description = models.TextField(blank=True, null=True)  # Descrizione estesa della CWE, opzionale
    likelihood_of_exploit = models.CharField(max_length=50, choices=CWE_EXPLOIT_LIKELIHOOD_CHOICES, blank=True, null=True)

    # Campi JSON per dati complessi
    affected_resources = JSONField(blank=True, null=True)
    alternate_terms = JSONField(blank=True, null=True)
    applicable_platforms = JSONField(blank=True, null=True)  # Lista di dizionari con piattaforme e prevalenza
    background_details = JSONField(blank=True, null=True)
    common_consequences = JSONField(blank=True, null=True)  # Lista di dizionari con scope e impact
    demonstrative_examples = JSONField(blank=True, null=True)  # Lista di esempi dimostrativi
    detection_methods = JSONField(blank=True, null=True)  # Lista di dizionari con metodi di rilevamento e dettagli
    functional_areas = JSONField(blank=True, null=True) 
    modes_of_introduction = JSONField(blank=True, null=True)
    potential_mitigations = JSONField(blank=True, null=True)  # Lista di dizionari con metodi di mitigazione e dettagli  
    observed_examples = JSONField(blank=True, null=True)  # Lista di dizionari con esempio e CVE collegato

    # Relations
    related_weaknesses = models.ManyToManyField("self", through="CWERelatedWeakness", symmetrical=False, related_name="cwe_related_weaknesses")
    related_attack_patterns = models.ManyToManyField("CAPEC", blank=True, related_name="cwe_related_attack_patterns")


    def __str__(self):
        return f"{self.id} - {self.name}"

class CWERelatedWeakness(models.Model):
    RELATION_TYPE_CHOICES = [
        ("ChildOf", "ChildOf"),
        ("ParentOf", "ParentOf"),
        ("StartsWith", "StartsWith"),
        ("CanFollow", "CanFollow"),
        ("RequiredBy", "RequiredBy"),
        ("Requires", "Requires"),
        ("PeerOf", "PeerOf"),
        ("CanPrecede", "CanPrecede"),
        ("CanAlsoBe", "CanAlsoBe"),
    ]

    cwe = models.ForeignKey(CWE, related_name="related_weaknesses_from", on_delete=models.CASCADE)
    related_cwe = models.ForeignKey(CWE, related_name="related_weaknesses_to", on_delete=models.CASCADE)
    relation_type = models.CharField(max_length=50, choices=RELATION_TYPE_CHOICES)

    def __str__(self):
        return f"{self.cwe} {self.relation_type} {self.related_cwe}"