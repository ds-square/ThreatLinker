# data/migrations/0002_add_initial_dataupdate_records.py

from django.db import migrations

def create_initial_dataupdate_records(apps, schema_editor):
    DataUpdate = apps.get_model('data', 'DataUpdate')
    initial_records = [
        {"name": "CVE", "has_been_updated": False},
        {"name": "CWE", "has_been_updated": False},
        {"name": "CAPEC", "has_been_updated": False},
    ]
    for record in initial_records:
        DataUpdate.objects.get_or_create(name=record["name"], defaults=record)

class Migration(migrations.Migration):

    dependencies = [
        ('data', '0001_initial'),  # Assicurati che corrisponda all'ultima migrazione esistente
    ]

    operations = [
        migrations.RunPython(create_initial_dataupdate_records),
    ]
