from django.db import models
from django.utils import timezone

class GroundTruth(models.Model):
    name = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    mapping = models.JSONField(help_text="Dizionario che associa CVE a una lista di CAPEC, es. {'CVE-XXX': ['CAPEC-1', 'CAPEC-2']}")

    def __str__(self):
        return self.name
