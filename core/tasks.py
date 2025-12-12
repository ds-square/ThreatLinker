import os
import importlib
from celery import shared_task

# Percorso della directory contenente i file delle tasks
TASKS_DIR = os.path.join(os.path.dirname(__file__), 'tasks')

# Carica dinamicamente tutti i file in /tasks/
for file in os.listdir(TASKS_DIR):
    if file.endswith('.py') and file != '__init__.py':
        module_name = f"core.tasks.{file[:-3]}"
        try:
            importlib.import_module(module_name)
        except Exception as e:
            print(f"Error importing {module_name}: {e}")
