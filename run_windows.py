import subprocess
import time
import ctypes
import os
import sys

CREATE_NEW_CONSOLE = subprocess.CREATE_NEW_CONSOLE
NUM_PROCESSES = 4

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_django_server():
    print("Avviando il server Django...")
    django_manage_path = os.path.join(os.getcwd(), "manage.py")
    return subprocess.Popen(
        [os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe"), django_manage_path, "runserver"],
        creationflags=CREATE_NEW_CONSOLE
    )

def start_celery_workers(worker_count=NUM_PROCESSES):
    workers = []
    for i in range(worker_count):
        print(f"Avviando il worker Celery {i+1}...")

        # Comando per avviare un worker Celery con il pool solo
        celery_command = [
            os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe"), "-m", "celery",
            "-A", "threatlinker", "worker", "--loglevel=info", "--pool=solo"
        ]

        worker = subprocess.Popen(
            celery_command,
            creationflags=CREATE_NEW_CONSOLE,
            cwd=os.getcwd()
        )
        workers.append(worker)
    
    return workers

def start_memurai():
    print("Avviando Memurai...")
    # Percorso dell'eseguibile di Memurai, cambialo se necessario
    memurai_executable_path = "C:\\Program Files\\Memurai\\memurai.exe"
    return subprocess.Popen([memurai_executable_path], creationflags=CREATE_NEW_CONSOLE)

def clear_memurai_tasks():
    print("Pulizia delle task in sospeso in Memurai...")
    # Esegui il comando memurai-cli per cancellare le task di Celery
    command = ["memurai-cli", "FLUSHALL"]  # Questo comando pulisce l'intero database di Memurai
    try:
        subprocess.run(command, check=True)
        print("Task in sospeso cancellate.")
    except subprocess.CalledProcessError:
        print("Errore durante la pulizia delle task in Memurai.")

if __name__ == "__main__":
    if is_admin():
        try:
            # Avvia Memurai
            memurai_process = start_memurai()
            time.sleep(5)  # Attendi qualche secondo per assicurarti che Memurai sia avviato

            # Pulisci le task memorizzate in Memurai
            clear_memurai_tasks()

            # Avvia Django
            django_process = start_django_server()
            time.sleep(5)  # Attendi che il server Django parta
            
            # Avvia più worker Celery con il pool solo
            celery_workers = start_celery_workers(worker_count=NUM_PROCESSES)  

            # Mantieni i processi attivi
            django_process.wait()
            for worker in celery_workers:
                worker.wait()
            memurai_process.wait()
        except KeyboardInterrupt:
            print("\nArresto dei servizi...")
            django_process.terminate()
            for worker in celery_workers:
                worker.terminate()
            memurai_process.terminate()
            print("Tutti i servizi sono stati arrestati.")
    else:
        # Richiedi i privilegi di amministratore
        print("Richiesta di privilegi amministrativi...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
