from django.db import models
from datetime import timedelta

class DataUpdate(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Complete', 'Complete'),
        ('Failed', 'Failed'),
    ]

    name = models.CharField(max_length=50, unique=True)
    last_update = models.DateTimeField(null=True, blank=True)
    next_scheduled_update = models.DateTimeField(null=True, blank=True)
    has_been_updated = models.BooleanField(default=False)
    update_frequency = models.IntegerField(null=True, blank=True, help_text="Frequency of updates in days")
    version = models.CharField(max_length=20, blank=True, null=True, help_text="Current version of the data entity")  # Versione come stringa
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending', help_text="Status of the update")

    def __str__(self):
        return self.name

    def schedule_next_update(self):
        if self.update_frequency and self.last_update:
            self.next_scheduled_update = self.last_update + timedelta(days=self.update_frequency)
            self.save()

