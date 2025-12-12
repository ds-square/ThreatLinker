from django.db import models
from django.db.models import JSONField

class CVE(models.Model):
    id = models.CharField(max_length=20, primary_key=True)
    assigner = models.TextField(blank=True, null=True)
    data_type = models.CharField(max_length=30, blank=True, null=True)
    data_format = models.CharField(max_length=30, blank=True, null=True)
    data_version = models.CharField(max_length=20, blank=True, null=True)

    # Descrizione e Date
    description = models.TextField()
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()

    # Impatto
    impact_v2 = JSONField(null=True, blank=True)
    impact_v3 = JSONField(null=True, blank=True)

    # Relazioni e Altri Campi
    vulnerable_cpe_uris = JSONField(null=True, blank=True)
    related_cpe_uris = JSONField(null=True, blank=True)
    related_cwes = models.ManyToManyField("CWE", blank=True, related_name="cve_related_weaknesses")

    def get_summary(self):
        return self.description[:100] + '...' if len(self.description) > 100 else self.description

    def __str__(self):
        return self.id

    def get_cvss_v2_info(self, key):
        return self.impact_v2.get('cvssV2', {}).get(key, 'N/A') if self.impact_v2 else 'N/A'

    def get_cvss_v3_info(self, key):
        return self.impact_v3.get('cvssV3', {}).get(key, 'N/A') if self.impact_v3 else 'N/A'

    def get_vulnerable_cpe_uris(self):
        return self.vulnerable_cpe_uris or []

    def get_related_cpe_uris(self):
        return self.related_cpe_uris or []

    def get_related_cwes(self):
        return self.related_cwes.all()

    def get_reference_urls(self):
        return [ref.url for ref in self.references.all()]
    
    # Funzioni per gli impatti V2

    def get_vector_string(self):
        return self.impact_v2.get('cvssV2', {}).get('vectorString', 'N/A')

    def get_attack_vector(self):
        return self.impact_v2.get('cvssV2', {}).get('accessVector', 'N/A')

    def get_access_complexity(self):
        return self.impact_v2.get('cvssV2', {}).get('accessComplexity', 'N/A')

    def get_authentication(self):
        return self.impact_v2.get('cvssV2', {}).get('authentication', 'N/A')

    def get_confidentiality_impact(self):
        return self.impact_v2.get('cvssV2', {}).get('confidentialityImpact', 'N/A')

    def get_integrity_impact(self):
        return self.impact_v2.get('cvssV2', {}).get('integrityImpact', 'N/A')

    def get_availability_impact(self):
        return self.impact_v2.get('cvssV2', {}).get('availabilityImpact', 'N/A')

    def get_base_score(self):
        return self.impact_v2.get('cvssV2', {}).get('baseScore', 'N/A')

    # Funzioni per gli impatti V3

    def get_vector_string_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('vectorString', 'No vector string available.')
        return 'Impact V3 data is not available.'

    def get_attack_vector_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('attackVector', 'No attack vector available.')
        return 'Impact V3 data is not available.'

    def get_attack_complexity_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('attackComplexity', 'No attack complexity available.')
        return 'Impact V3 data is not available.'

    def get_privileges_required_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('privilegesRequired', 'No privileges required information available.')
        return 'Impact V3 data is not available.'

    def get_user_interaction_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('userInteraction', 'No user interaction information available.')
        return 'Impact V3 data is not available.'

    def get_confidentiality_impact_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('confidentialityImpact', 'No confidentiality impact information available.')
        return 'Impact V3 data is not available.'

    def get_integrity_impact_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('integrityImpact', 'No integrity impact information available.')
        return 'Impact V3 data is not available.'

    def get_availability_impact_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('availabilityImpact', 'No availability impact information available.')
        return 'Impact V3 data is not available.'

    def get_base_score_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('baseScore', 'No base score available.')
        return 'Impact V3 data is not available.'

    def get_base_severity_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('baseSeverity', 'No base severity information available.')
        return 'Impact V3 data is not available.'

    def get_scope_v3(self):
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.impact_v3['cvssV3'].get('scope', 'No scope information available.')
        return 'Impact V3 data is not available.'
    
    # Funzioni per ottenere il rating di rischio
    
    def get_rating_v2(self):
        score = self.get_base_score()
        if score != 'N/A':
            return self.calculate_rating(score)
        return None

    def get_rating_v3(self):
        score = self.get_base_score_v3()
        if score != 'N/A':
            return self.calculate_rating(score)
        return None

    def get_overall_rating(self):
        # Ritorna il rating di v3 se disponibile, altrimenti di v2, o None se nessuno è presente
        if self.impact_v3 and 'cvssV3' in self.impact_v3:
            return self.get_rating_v3()
        elif self.impact_v2 and 'cvssV2' in self.impact_v2:
            return self.get_rating_v2()
        return None

    def calculate_rating(self, score):
        if 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        return None


class CVEReference(models.Model):
    cve = models.ForeignKey(CVE, related_name='references', on_delete=models.CASCADE)
    url = models.TextField()  # Cambiato da URLField a TextField per evitare limiti di lunghezza
    name = models.TextField(blank=True, null=True)  # Cambiato per consentire lunghezze maggiori
    refsource = models.TextField(blank=True, null=True)  # Cambiato per lunghezze variabili
    tags = JSONField(blank=True, null=True)

    def __str__(self):
        return self.url
