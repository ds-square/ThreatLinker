import os
import inspect
from datetime import datetime
import multiprocessing

# Definisci le costanti
DEBUG_MODE = False
DEBUG_MODE_LOG = True
DEBUG_PARALLEL = True  # Se True, i log saranno separati per ogni processo usando il PID

# Variabile globale per controllare l'inizializzazione del log
log_initialized = False

# Colori ANSI per il terminale (solo per console)
class Colors:
    GREEN = '\033[92m'    # Verde per le cartelle
    ORANGE = '\033[93m'   # Arancione per i file
    RED = '\033[91m'      # Rosso per le funzioni
    RESET = '\033[0m'     # Reset del colore

def initialize_log():
    """Inizializza il file di log cancellando tutti i file di log presenti nella directory."""
    global log_initialized

    if not log_initialized:
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')

        # Verifica se la directory esiste, altrimenti la crea
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Elimina tutti i file .log nella cartella logs
        for filename in os.listdir(log_dir):
            file_path = os.path.join(log_dir, filename)
            if os.path.isfile(file_path) and filename.endswith('.log'):
                os.remove(file_path)  # Elimina il file log

        log_initialized = True  # Imposta l'inizializzazione come completata

def format_context(context, colored=True):
    """Applica i colori alla struttura del context. Se colored=False, rimuove i colori."""
    parts = context.split('.')
    if len(parts) < 3:
        return context  # Se la struttura non è completa, restituisce il context originale

    if colored:
        # Colora le cartelle (prima parte)
        folders = ".".join(parts[:-2])
        colored_folders = f"{Colors.GREEN}{folders}{Colors.RESET}"

        # Colora il file (penultima parte)
        file = parts[-2]
        colored_file = f"{Colors.ORANGE}{file}{Colors.RESET}"

        # Colora la funzione (ultima parte)
        function = parts[-1]
        colored_function = f"{Colors.RED}{function}{Colors.RESET}"

        # Unisce il tutto con colori
        return f"{colored_folders}.{colored_file}.{colored_function}"
    else:
        # Rimuove i colori
        return context

def get_context():
    """Genera automaticamente il context 'cartelle.file.funzione', partendo dalla directory del progetto."""
    stack = inspect.stack()

    # Ottieni informazioni sul file e la funzione chiamante
    frame = stack[2]  # Indice 2 per risalire alla funzione chiamante
    module = inspect.getmodule(frame[0])

    # Percorso del file
    file_path = module.__file__
    file_name = os.path.basename(file_path).replace('.py', '')

    # Funzione chiamante
    function_name = frame.function

    # Ottieni la directory corrente del progetto
    project_root = os.path.dirname(file_path)

    # Estrarre le cartelle relative al progetto
    folder_path = os.path.relpath(os.path.dirname(file_path), project_root).replace(os.sep, '.').strip('.')
    
    # Costruisce il context completo
    context = f"{folder_path}.{file_name}.{function_name}"
    return context

def debug_print(level, message):
    """Stampa un messaggio di debug sia a schermo che in un file di log.
    
    Il context è generato automaticamente in base alla funzione chiamante.
    """
    # Se DEBUG_MODE è False, non fa nulla
    if not DEBUG_MODE:
        return
    
    # Inizializza il log alla prima chiamata
    initialize_log()

    # Aggiungi un timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Ottieni e formatta il context
    context = get_context()
    colored_context = format_context(context, colored=True)
    log_context = format_context(context, colored=False)

    # Costruisci il messaggio di log
    log_message = f"{timestamp} [{level}] {message} - Context: {log_context}"
    colored_message = f"{timestamp} [{level}] {message} - Context: {colored_context}"

    # Stampa a schermo (con colori)
    print(colored_message)
    
    # Scrivi nel file di log (senza colori) solo se DEBUG_MODE_LOG è True
    if DEBUG_MODE_LOG:
        # Usa la stessa directory del file corrente
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Differenzia il log per il processo padre e quelli paralleli usando il nome del processo
        process_name = multiprocessing.current_process().name
        pid = multiprocessing.current_process().pid
        
        if DEBUG_PARALLEL:
            if process_name == "MainProcess":  # Identifica il processo principale
                log_file = os.path.join(log_dir, f'project_debug_main_{pid}.log')  # File specifico per il processo principale
            else:
                log_file = os.path.join(log_dir, f'project_debug_{pid}.log')  # File specifico per ogni processo figlio
        else:
            log_file = os.path.join(log_dir, 'project_debug.log')  # Un unico file per tutti

        # Scrivi nel file log
        with open(log_file, 'a', encoding='utf-8') as log:  # Usa la codifica utf-8
            log.write(log_message + '\n')


# Esempio di utilizzo
def example_function():
    debug_print('DEBUG', 'Esempio di messaggio di debug')

if __name__ == "__main__":
    example_function()
