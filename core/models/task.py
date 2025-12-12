from django.db import models

class Task(models.Model):
    TASK_TYPE_CHOICES = [
        ('correlation', 'Correlation'),
        ('groundtruth', 'Groundtruth'),
        ('other', 'Other'),
    ]
    
    TASK_STATUS_CHOICES = [
        ('complete', 'Complete'),
        ('pending', 'Pending'),
        ('failed', 'Failed'),
        ('in_progress', 'In Progress'),
    ]
    
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=TASK_TYPE_CHOICES, default='other')
    status = models.CharField(max_length=50, choices=TASK_STATUS_CHOICES, default='pending')
    cve_hosts = models.JSONField(null=True)  # Contiene il dizionario CVE -> hosts

    ai_models = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.id} - {self.name} ({self.get_type_display()})"

    def get_full_details(self):
        return (
            f"ID: {self.id}\n"
            f"Name: {self.name}\n"
            f"Type: {self.get_type_display()}\n"
            f"Status: {self.get_status_display()}\n"
            f"Notes: {self.notes}\n"
            f"Created at: {self.created_at}\n"
            f"Updated at: {self.updated_at}\n"
        )

    def check_task_completion(self):
        """
        Controlla se tutte le SingleCorrelation sono complete per questa Task.
        La Task è completa solo se:
        - Il numero di SingleCorrelation complete è uguale al numero di CVE nel dizionario cve_hosts.
        - Ogni cve_id nelle SingleCorrelation corrisponde a una CVE nel dizionario cve_hosts.
        """
        total_cves = len(self.cve_hosts)  # Numero di CVE nel dizionario
        complete_single_correlations = self.single_correlations.filter(status='complete').count()  # Conta le SingleCorrelation complete
        
        # Verifica che ogni cve_id di SingleCorrelation corrisponda a una CVE nel dizionario cve_hosts
        all_cve_ids_valid = True
        cve_ids_in_task = set(self.cve_hosts.keys())  # Le CVE nei hosts della Task

        for single_correlation in self.single_correlations.filter(status='complete'):
            if single_correlation.cve_id not in cve_ids_in_task:
                all_cve_ids_valid = False
                break

        # Se il numero di SingleCorrelation complete è uguale al numero di CVE
        # e se tutte le SingleCorrelation hanno cve_id validi, la Task è completa
        if complete_single_correlations == total_cves and all_cve_ids_valid:
            self.status = 'complete'
            self.save()
            return True
        else:
            self.status = 'in_progress'
            self.save()
            return False

class SingleCorrelation(models.Model):
    SINGLECORRELATION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('complete', 'Complete'),
        ('failed', 'Failed'),
    ]
    status = models.CharField(max_length=50, choices=SINGLECORRELATION_STATUS_CHOICES, default='pending')
    cve_id = models.CharField(max_length=20)  # ID della CVE
    hosts = models.TextField(blank=True, null=True)
    task = models.ForeignKey(Task, related_name='single_correlations', on_delete=models.CASCADE, null=True)  # ForeignKey con Task
    similarity_scores = models.JSONField()  # Punteggi di similarità per ogni metodo (es. 'method1': score, 'method2': score)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Single Correlation: {self.cve_id}"
