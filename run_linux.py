import subprocess
import time
import os
import sys

def start_django_server():
    print("Avviando il server Django...")
    django_manage_path = os.path.join(os.getcwd(), "manage.py")
    return subprocess.Popen(
        [os.path.join(os.getcwd(), ".venv", "bin", "python"), django_manage_path, "runserver"]
    )

def start_celery_workers(worker_count=4):
    workers = []
    for i in range(worker_count):
        print(f"Avviando il worker Celery {i+1}...")

        # Comando per avviare un worker Celery con il pool solo
        celery_command = [
            os.path.join(os.getcwd(), ".venv", "bin", "celery"),
            "-A", "threatlinker", "worker", "--loglevel=info", "--pool=solo"
        ]

        worker = subprocess.Popen(celery_command, cwd=os.getcwd())
        workers.append(worker)
    
    return workers

def start_redis():
    print("Avviando Redis...")
    # Assicurati che `redis-server` sia installato e configurato correttamente su Linux
    return subprocess.Popen(["redis-server"])

def clear_redis_tasks():
    print("Pulizia delle task in sospeso in Redis...")
    # Esegui il comando Redis per cancellare le task di Celery
    command = ["redis-cli", "FLUSHALL"]  # Questo comando pulisce l'intero database di Redis
    try:
        subprocess.run(command, check=True)
        print("Task in sospeso cancellate.")
    except subprocess.CalledProcessError:
        print("Errore durante la pulizia delle task in Redis.")

if __name__ == "__main__":
    try:
        # Avvia Redis
        redis_process = start_redis()
        time.sleep(5)  # Attendi qualche secondo per assicurarti che Redis sia avviato

        # Pulisci le task memorizzate in Redis
        clear_redis_tasks()

        # Avvia Django
        django_process = start_django_server()
        time.sleep(5)  # Attendi che il server Django parta
        
        # Avvia più worker Celery con il pool solo
        celery_workers = start_celery_workers(worker_count=4)  # Avvia 4 worker

        # Mantieni i processi attivi
        django_process.wait()
        for worker in celery_workers:
            worker.wait()
        redis_process.wait()
    except KeyboardInterrupt:
        print("\nArresto dei servizi...")
        django_process.terminate()
        for worker in celery_workers:
            worker.terminate()
        redis_process.terminate()
        print("Tutti i servizi sono stati arrestati.")
